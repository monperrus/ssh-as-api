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

## Sharing Port 22 with the System sshd

Running the SSH API server on a non-standard port exposes it to Deep Packet Inspection (see below). The alternative is to share port 22 with the existing system sshd using `ForceCommand`.

Add a dedicated system user (e.g. `api`) and in `/etc/ssh/sshd_config`:

```
Match User api
    ForceCommand /usr/local/bin/api-dispatcher
    AllowTcpForwarding no
    PermitTTY no
```

The dispatcher binary reads `$SSH_ORIGINAL_COMMAND` for the requested command. Authentication (public key) is handled entirely by sshd.

### Key-based access control under ForceCommand

sshd does not pass the authenticated key to `ForceCommand` by default. Two approaches to recover per-key roles:

**Option A — `command=` per key in `authorized_keys` (no root needed)**

Embed the role directly in each key's `authorized_keys` entry:

```
command="ROLE=anon  /usr/local/bin/api-dispatcher",no-pty,no-port-forwarding ssh-rsa   AAAA... alice
command="ROLE=user  /usr/local/bin/api-dispatcher",no-pty,no-port-forwarding ssh-rsa   AAAA... bob
command="ROLE=admin /usr/local/bin/api-dispatcher",no-pty,no-port-forwarding ssh-ed25519 AAAA... martin
```

The dispatcher reads `$ROLE` and `$SSH_ORIGINAL_COMMAND`:

```go
role := os.Getenv("ROLE")
cmd  := os.Getenv("SSH_ORIGINAL_COMMAND")
os.Exit(dispatch(cmd, role, os.Stdout, os.Stderr))
```

**Option B — `ExposeAuthInfo yes` in sshd_config (OpenSSH 7.9+, requires root)**

Add to `/etc/ssh/sshd_config`:

```
ExposeAuthInfo yes
```

sshd writes the authenticated key to a temporary file and sets `$SSH_USER_AUTH` to its path. The dispatcher reads it and maps fingerprint → role internally, keeping all access-control logic in the binary.

> **Gotcha: the file contains the raw public key, not the fingerprint.**
>
> The actual file format is:
> ```
> publickey ssh-rsa AAAAB3NzaC1yc2EAAA...
> ```
> The third field is the base64-encoded public key blob, **not** a `SHA256:...` fingerprint string. You must parse the key and compute the fingerprint yourself:

```go
data, _ := os.ReadFile(os.Getenv("SSH_USER_AUTH"))
// fields: ["publickey", "<type>", "<base64-key>"]
fields := strings.Fields(string(data))
pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(fields[1] + " " + fields[2]))
fp   := ssh.FingerprintSHA256(pub)   // now a "SHA256:..." string
role := fingerprintToRole(fp)
cmd  := os.Getenv("SSH_ORIGINAL_COMMAND")
os.Exit(dispatch(cmd, role, os.Stdout, os.Stderr))
```

See [cmd/dispatcher/main.go](cmd/dispatcher/main.go) for the full working implementation.

Option A suits setups where you don't control `sshd_config`. Option B keeps the role mapping inside the binary, matching the logic of a standalone SSH server.

## Deep Packet Inspection

Some networks (corporate firewalls, certain hosting providers) run Deep Packet Inspection that detects the SSH protocol signature and blocks it on any port other than 22. Symptoms: `nc` can reach the server and read the banner (`SSH-2.0-...`), but the SSH client hangs with "Connection timed out during banner exchange" — the DPI lets the TCP handshake and the server's opening banner through, then drops the client's response when it recognises the SSH version string.

Mitigations:

- **Use port 22** — universally allowed, but requires sharing it with the system sshd (e.g. via `sslh`).
- **Wrap in TLS on port 443** — use `stunnel` on both ends, or a reverse proxy with stream support. DPI sees HTTPS.
- **SSH jump host** — if you already have SSH access on port 22, tunnel through it: `ssh -J user@host -p <api-port> user@localhost <cmd>`.

## When to Choose SSH over HTTP

- Your users are developers who already manage SSH keys
- You need streaming output (build logs, tail -f, progress bars)
- You want authentication without building an auth service
- You want interactive sessions alongside scripted calls
- The interface is internal tooling, not a public web API

HTTP REST remains the right choice when the client is a browser, a mobile app, or a third party who cannot be expected to have an SSH key.
