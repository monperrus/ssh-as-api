package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- access roles -------------------------------------------------------

const (
	roleAnon  = ""
	roleUser  = "user"
	roleAdmin = "admin"
)

// authorizedKeys maps public-key fingerprint → role.
// In production this would come from a database or file.
var authorizedKeys = map[string]string{
	// Add entries like: "SHA256:abc...": roleAdmin,
}

// adminFingerprints can also be set via -admin flag at startup.
var adminFingerprints []string

// --- commands -----------------------------------------------------------

type cmdCtx struct {
	args  []string
	stdin io.Reader
	out   io.Writer
	err   io.Writer
	role  string
	user  string
}

func cmdHello(c cmdCtx) int {
	name := "World"
	if len(c.args) > 0 {
		name = c.args[0]
	}
	fmt.Fprintf(c.out, "Hello, %s!\n", name)
	return 0
}

func cmdWhoami(c cmdCtx) int {
	if c.role == roleAnon {
		fmt.Fprintln(c.out, "anonymous")
		return 0
	}
	fmt.Fprintf(c.out, "user=%s role=%s\n", c.user, c.role)
	return 0
}

func cmdStatus(c cmdCtx) int {
	fmt.Fprintf(c.out, "server up, time=%s\n", time.Now().UTC().Format(time.RFC3339))
	return 0
}

func cmdEcho(c cmdCtx) int {
	fmt.Fprintln(c.out, strings.Join(c.args, " "))
	return 0
}

func cmdSecret(c cmdCtx) int {
	if c.role == roleAnon {
		fmt.Fprintln(c.err, "error: authentication required")
		return 1
	}
	fmt.Fprintln(c.out, "the secret is: 42")
	return 0
}

func cmdReload(c cmdCtx) int {
	if c.role != roleAdmin {
		fmt.Fprintln(c.err, "error: admin role required")
		return 1
	}
	fmt.Fprintln(c.out, "config reloaded (simulated)")
	return 0
}

func cmdHelp(c cmdCtx) int {
	fmt.Fprintf(c.out, "Available commands:\n")
	fmt.Fprintf(c.out, "  hello [name]   greet (anonymous)\n")
	fmt.Fprintf(c.out, "  status         server status (anonymous)\n")
	fmt.Fprintf(c.out, "  echo [args]    echo arguments (anonymous)\n")
	fmt.Fprintf(c.out, "  whoami         show identity (anonymous)\n")
	fmt.Fprintf(c.out, "  secret         show secret (authenticated)\n")
	fmt.Fprintf(c.out, "  reload         reload config (admin)\n")
	fmt.Fprintf(c.out, "  help           show this help\n")
	return 0
}

// --- dispatcher ---------------------------------------------------------

func dispatch(raw string, role, user string, ch ssh.Channel) int {
	parts := strings.Fields(raw)
	cmd := ""
	args := []string{}
	if len(parts) > 0 {
		cmd = parts[0]
		args = parts[1:]
	}

	c := cmdCtx{
		args:  args,
		stdin: ch,
		out:   ch,
		err:   ch.Stderr(),
		role:  role,
		user:  user,
	}

	switch cmd {
	case "hello":
		return cmdHello(c)
	case "status":
		return cmdStatus(c)
	case "echo":
		return cmdEcho(c)
	case "whoami":
		return cmdWhoami(c)
	case "secret":
		return cmdSecret(c)
	case "reload":
		return cmdReload(c)
	case "help", "":
		return cmdHelp(c)
	default:
		fmt.Fprintf(ch.Stderr(), "unknown command: %q — type 'help' for available commands\n", cmd)
		return 127
	}
}

// --- shell (interactive REPL) ------------------------------------------

func runShell(role, user string, ch ssh.Channel) int {
	fmt.Fprintf(ch, "SSH API shell (role=%s", role)
	if role == roleAnon {
		fmt.Fprintf(ch, ", type 'help' for commands")
	}
	fmt.Fprintln(ch, ")")

	scanner := bufio.NewScanner(ch)
	for {
		fmt.Fprint(ch, "> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "quit" || line == "exit" {
			fmt.Fprintln(ch, "bye")
			break
		}
		dispatch(line, role, user, ch)
	}
	return 0
}

// --- SSH plumbing -------------------------------------------------------

func handleSession(nc ssh.NewChannel, perms *ssh.Permissions) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		log.Printf("accept channel: %v", err)
		return
	}
	defer ch.Close()

	role, user := roleAnon, "anonymous"
	if perms != nil {
		if r, ok := perms.Extensions["role"]; ok {
			role = r
		}
		if u, ok := perms.Extensions["user"]; ok {
			user = u
		}
	}

	for req := range reqs {
		switch req.Type {
		case "exec":
			req.Reply(true, nil)
			cmd := parseExecPayload(req.Payload)
			code := dispatch(cmd, role, user, ch)
			sendExitStatus(ch, uint32(code))
			return
		case "shell":
			req.Reply(true, nil)
			code := runShell(role, user, ch)
			sendExitStatus(ch, uint32(code))
			return
		default:
			req.Reply(false, nil)
		}
	}
}

func serve(conn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		log.Printf("handshake: %v", err)
		return
	}
	defer sc.Close()
	log.Printf("connect: %s role=%s", sc.RemoteAddr(), roleOf(sc.Permissions))
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}
		go handleSession(nc, sc.Permissions)
	}
}

func roleOf(p *ssh.Permissions) string {
	if p == nil {
		return roleAnon
	}
	if r, ok := p.Extensions["role"]; ok {
		return r
	}
	return roleAnon
}

// --- auth ---------------------------------------------------------------

func publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp := ssh.FingerprintSHA256(key)
	log.Printf("pubkey offered: %s type=%s", fp, key.Type())

	for _, a := range adminFingerprints {
		if fp == a {
			log.Printf("pubkey accepted as admin: %s", fp)
			return &ssh.Permissions{
				Extensions: map[string]string{
					"role": roleAdmin,
					"user": conn.User(),
				},
			}, nil
		}
	}

	if role, ok := authorizedKeys[fp]; ok {
		return &ssh.Permissions{
			Extensions: map[string]string{
				"role": role,
				"user": conn.User(),
			},
		}, nil
	}

	log.Printf("pubkey rejected: %s", fp)
	return nil, fmt.Errorf("unknown key %s", fp)
}

// --- main ---------------------------------------------------------------

func main() {
	addr := flag.String("addr", ":2222", "listen address")
	adminFP := flag.String("admin", "", "comma-separated admin key fingerprints (SHA256:...)")
	flag.Parse()

	if *adminFP != "" {
		for _, fp := range strings.Split(*adminFP, ",") {
			adminFingerprints = append(adminFingerprints, strings.TrimSpace(fp))
		}
	}

	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	cfg := &ssh.ServerConfig{
		// Keyboard-interactive with no prompts is the anonymous fallback.
		// The client tries public key first (per default PreferredAuthentications
		// order); if no known key is offered it falls through to this, which
		// succeeds immediately and assigns the anon role.
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if _, err := challenge("", "", nil, nil); err != nil {
				return nil, err
			}
			return &ssh.Permissions{
				Extensions: map[string]string{"role": roleAnon, "user": "anonymous"},
			}, nil
		},
		PublicKeyCallback: publicKeyCallback,
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	log.Printf("SSH API server on %s (anonymous + key auth)", *addr)
	if len(adminFingerprints) > 0 {
		log.Printf("admin fingerprints: %v", adminFingerprints)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go serve(conn, cfg)
	}
}

// --- helpers ------------------------------------------------------------

func parseExecPayload(p []byte) string {
	if len(p) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(p[:4])
	if uint32(len(p)) < 4+n {
		return ""
	}
	return string(p[4 : 4+n])
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	ch.SendRequest("exit-status", false, payload)
}

