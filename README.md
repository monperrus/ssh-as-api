# SSH as an API Interface

HTTP REST is the default choice for exposing a system's interface, but SSH is a compelling alternative: it is universally available, encrypted, authenticated, and carries a well-understood security model. This document presents the concept and its implementation in Go.

## The Idea

Instead of exposing `POST /api/deploy` over HTTP, you expose it as:

```
ssh api.example.com deploy
```

The client is the standard `ssh` binary every developer already has. No SDK, no token management, no TLS certificate setup on the client side. Authentication uses SSH public keys, which most developers already have configured.

This pattern is used in production by Heroku (`git push heroku main`), GitHub (`ssh -T git@github.com`), and Fly.io (`fly ssh console`).

## Access Modes

### Anonymous Mode

The server accepts connections without verifying identity. Anyone can call read-only commands.

```
ssh api.example.com status
ssh api.example.com version
```

Implementation: set `NoClientAuth: true` in `ssh.ServerConfig`. No key exchange for authentication is performed; the session is still encrypted.

```go
config := &ssh.ServerConfig{
    NoClientAuth: true,
}
```

### Authenticated Mode

The server requires a valid SSH public key. Commands are scoped to the authenticated user's identity and permissions.

```
ssh api.example.com whoami
ssh api.example.com list-jobs
```

Implementation: provide a `PublicKeyCallback` that validates the offered key against a known set (a database, a flat file, an LDAP directory).

```go
config := &ssh.ServerConfig{
    PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
        user := lookupUser(key)
        if user == nil {
            return nil, fmt.Errorf("unknown key")
        }
        return &ssh.Permissions{
            Extensions: map[string]string{"username": user.Name, "role": user.Role},
        }, nil
    },
}
```

The `Permissions.Extensions` map is threaded through to every channel and request handler, so `role` is available when dispatching commands.

### Admin Mode

A specific key (or key fingerprint) grants elevated privileges. The same server handles all three modes simultaneously by branching on the identity established during handshake.

```
ssh api.example.com reload-config     # requires admin
ssh api.example.com drain-queue       # requires admin
```

Implementation: check the fingerprint or role in the dispatcher.

```go
func dispatch(cmd string, perms *ssh.Permissions, ch ssh.Channel) int {
    role := ""
    if perms != nil {
        role = perms.Extensions["role"]
    }

    switch cmd {
    case "status":
        return cmdStatus(ch)           // public
    case "list-jobs":
        if role == "" {
            fmt.Fprintln(ch.Stderr(), "authentication required")
            return 1
        }
        return cmdListJobs(ch)         // authenticated users
    case "reload-config":
        if role != "admin" {
            fmt.Fprintln(ch.Stderr(), "admin required")
            return 1
        }
        return cmdReloadConfig(ch)     // admin only
    default:
        fmt.Fprintf(ch.Stderr(), "unknown command: %q\n", cmd)
        return 127
    }
}
```

## What Commands Can Do

Because each command is a Go function receiving an `io.Writer` (stdout) and `io.Writer` (stderr), they can do anything:

- Query a database and stream results line by line
- Trigger a background job and tail its log output in real time
- Accept input via stdin (the SSH channel is bidirectional)
- Return structured data (JSON, CSV) that the caller pipes into `jq` or scripts

Streaming is natural: write to `ch` (stdout) as data arrives. The SSH framing handles backpressure.

## Structured Input

Commands receive their arguments from the `exec` payload — the string after `ssh host`. Parse it with `strings.Fields` or `flag.NewFlagSet`:

```go
func cmdDeploy(args []string, ch ssh.Channel) int {
    fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
    fs.SetOutput(ch.Stderr())
    env := fs.String("env", "staging", "target environment")
    if err := fs.Parse(args); err != nil {
        return 2
    }
    // deploy to *env ...
}
```

Invoked as:

```
ssh api.example.com deploy -env production
```

## Persistent Sessions (Shell Mode)

When the client connects without a command (`ssh api.example.com` with no trailing argument), the server receives a `shell` channel request instead of `exec`. This can be used to open an interactive REPL:

```
$ ssh api.example.com
> help
  status        show system status
  list-jobs     list running jobs
  quit          close session
> status
ok, 3 jobs running
> quit
```

Implementation: handle `shell` requests with a `bufio.Scanner` read loop over `ch`.

## Host Key and Trust

The server generates or loads a persistent host key. Clients verify it on first connect (TOFU — Trust On First Use) or the fingerprint is published out-of-band (DNS SSHFP records, documentation).

For a public API, publish the fingerprint prominently:

```
Fingerprint: SHA256:abc123...
SSHFP record: example.com. IN SSHFP 3 2 <hash>
```

## Comparison with HTTP REST

| | SSH | HTTP REST |
|---|---|---|
| Transport encryption | Built-in | Requires TLS setup |
| Authentication | Public key (built-in) | Token/OAuth/mTLS (external) |
| Client | `ssh` (pre-installed everywhere) | curl, SDK, browser |
| Streaming | Native (bidirectional channel) | SSE or WebSocket workaround |
| Interactive sessions | Native (shell mode) | Not applicable |
| Firewall friendliness | Port 22 usually open | Port 80/443 usually open |
| Scripting | `ssh host cmd \| grep \| jq` | curl + jq |
| Binary payloads | Trivial (stdin/stdout) | Multipart, base64 |

## Implementation

See [main.go](main.go) in this repository for a working implementation covering all three access modes, shell mode, and argument parsing.

## When to Choose SSH over HTTP

- Your users are developers who already manage SSH keys
- You need streaming output (build logs, tail -f, progress bars)
- You want authentication without building an auth service
- You want interactive sessions alongside scripted calls
- The interface is internal tooling, not a public web API

HTTP REST remains the right choice when the client is a browser, a mobile app, or a third party who cannot be expected to have an SSH key.
