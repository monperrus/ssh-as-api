// ForceCommand dispatcher for sshd Option B (ExposeAuthInfo yes).
// Reads the key fingerprint from $SSH_USER_AUTH and maps it to a role
// via /etc/ssh-api/roles (format: "SHA256:xxx role" one per line).
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const rolesFile = "/etc/ssh-api/roles"

func loadRoles() map[string]string {
	m := map[string]string{}
	f, err := os.Open(rolesFile)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

func role() string {
	roles := loadRoles()
	authFile := os.Getenv("SSH_USER_AUTH")
	if authFile == "" {
		return "anon"
	}
	data, err := os.ReadFile(authFile)
	if err != nil {
		return "anon"
	}
	// file format: "publickey <type> <base64-key>"
	// parse as authorized_keys line: "<type> <base64-key>"
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return "anon"
	}
	authLine := fields[1] + " " + fields[2]
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authLine))
	if err != nil {
		return "anon"
	}
	fp := ssh.FingerprintSHA256(pub)
	if r, ok := roles[fp]; ok {
		return r
	}
	return "anon"
}

func main() {
	r := role()
	cmd := strings.TrimSpace(os.Getenv("SSH_ORIGINAL_COMMAND"))
	os.Exit(dispatch(cmd, r))
}

func dispatch(cmd, role string) int {
	parts := strings.Fields(cmd)
	name, args := "", []string{}
	if len(parts) > 0 {
		name, args = parts[0], parts[1:]
	}

	switch name {
	case "hello":
		who := "World"
		if len(args) > 0 {
			who = args[0]
		}
		fmt.Fprintf(os.Stdout, "Hello, %s!\n", who)
		return 0

	case "whoami":
		fmt.Fprintf(os.Stdout, "role=%s\n", role)
		return 0

	case "status":
		fmt.Fprintf(os.Stdout, "up, time=%s\n", time.Now().UTC().Format(time.RFC3339))
		return 0

	case "secret":
		if role == "anon" {
			fmt.Fprintln(os.Stderr, "error: authentication required")
			return 1
		}
		fmt.Fprintln(os.Stdout, "the secret is: 42")
		return 0

	case "reload":
		if role != "admin" {
			fmt.Fprintln(os.Stderr, "error: admin role required")
			return 1
		}
		fmt.Fprintln(os.Stdout, "config reloaded (simulated)")
		return 0

	case "help", "":
		fmt.Fprintln(os.Stdout, "commands: hello [name]  whoami  status  secret (auth)  reload (admin)")
		return 0

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", name)
		return 127
	}
}
