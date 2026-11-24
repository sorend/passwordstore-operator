package gitstore

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/skeema/knownhosts"
	gossh "golang.org/x/crypto/ssh"
)

// authMethod builds the go-git authentication method for the configuration. It returns nil
// for a repository without credentials.
func (m *Manager) authMethod(ctx context.Context, cfg Config, ep *transport.Endpoint) (transport.AuthMethod, error) {
	switch {
	case cfg.Auth.SSH != nil:
		return sshAuthMethod(ep, cfg.Auth.SSH)

	case cfg.Auth.Token != nil:
		username := cfg.Auth.Token.Username
		if username == "" {
			username = DefaultTokenUsername
		}
		return &githttp.BasicAuth{Username: username, Password: cfg.Auth.Token.Token}, nil

	case cfg.Auth.App != nil:
		token, err := m.apps.token(ctx, cfg.Auth.App)
		if err != nil {
			return nil, err
		}
		return &githttp.BasicAuth{Username: DefaultTokenUsername, Password: token}, nil
	}
	return nil, nil
}

func sshAuthMethod(ep *transport.Endpoint, a *SSHAuth) (transport.AuthMethod, error) {
	user := ep.User
	if user == "" {
		user = DefaultSSHUser
	}
	auth, err := gitssh.NewPublicKeys(user, a.PrivateKey, string(a.Passphrase))
	if err != nil {
		return nil, fmt.Errorf("parse ssh private key: %w", err)
	}

	// The host key callback is always set explicitly, so that go-git never falls back to the
	// known_hosts files of the user that runs the operator.
	if a.InsecureIgnoreHostKey {
		auth.HostKeyCallback = gossh.InsecureIgnoreHostKey() //nolint:gosec // opt-in through the API
		return auth, nil
	}

	db, err := newKnownHostsDB(a.KnownHosts)
	if err != nil {
		return nil, err
	}
	port := ep.Port
	if port == 0 {
		port = 22
	}
	auth.HostKeyCallback = db.HostKeyCallback()
	// Offer only the host key types that are in known_hosts. A server that has several kinds of
	// host keys otherwise picks one that is not in the file, which fails as a key mismatch.
	auth.HostKeyAlgorithms = db.HostKeyAlgorithms(net.JoinHostPort(ep.Host, strconv.Itoa(port)))
	return auth, nil
}

// newKnownHostsDB parses known_hosts content. The parser only reads files, so the content is
// written to a temporary file that is removed straight away. Host keys are public.
func newKnownHostsDB(content string) (*knownhosts.HostKeyDB, error) {
	f, err := os.CreateTemp("", "known_hosts-")
	if err != nil {
		return nil, fmt.Errorf("parse knownHosts, a writable temporary directory is needed: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()

	if _, err := f.WriteString(strings.TrimSpace(content) + "\n"); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("parse knownHosts: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("parse knownHosts: %w", err)
	}

	db, err := knownhosts.NewDB(f.Name())
	if err != nil {
		return nil, fmt.Errorf("parse knownHosts: %w", err)
	}
	return db, nil
}

// explainError adds a hint to the errors of the SSH host key check, which are otherwise
// reported as a failed handshake.
func explainError(err error) error {
	switch {
	case knownhosts.IsHostKeyChanged(err), strings.Contains(err.Error(), "knownhosts: key mismatch"):
		return fmt.Errorf("the host key of the server does not match knownHosts, "+
			"the server was replaced or the connection is intercepted: %w", err)
	case knownhosts.IsHostUnknown(err), strings.Contains(err.Error(), "knownhosts: key is unknown"):
		return fmt.Errorf("the server is not in knownHosts, add its host key (ssh-keyscan): %w", err)
	}
	return err
}
