package testutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHKey is a throwaway SSH key pair.
type SSHKey struct {
	// Private is the private key, in OpenSSH format unless WithRSAPEM was used.
	Private []byte
	Public  gossh.PublicKey
	// Passphrase protects Private. It is empty for an unprotected key.
	Passphrase string
}

// SSHKeyOption customizes NewSSHKey.
type SSHKeyOption func(*sshKeyConfig)

type sshKeyConfig struct {
	passphrase string
	rsaPEM     bool
}

// WithSSHPassphrase protects the private key with a passphrase.
func WithSSHPassphrase(passphrase string) SSHKeyOption {
	return func(c *sshKeyConfig) { c.passphrase = passphrase }
}

// WithRSAPEM makes an RSA key in the traditional PEM format instead of an ed25519 key in the
// OpenSSH format.
func WithRSAPEM() SSHKeyOption {
	return func(c *sshKeyConfig) { c.rsaPEM = true }
}

// NewSSHKey generates an SSH key pair.
func NewSSHKey(t TB, opts ...SSHKeyOption) *SSHKey {
	t.Helper()
	var cfg sshKeyConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.rsaPEM {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if cfg.passphrase != "" {
			//nolint:staticcheck // legacy PEM encryption is what old keys use, and the test needs one
			block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(cfg.passphrase), x509.PEMCipherAES256)
			if err != nil {
				t.Fatal(err)
			}
		}
		pub, err := gossh.NewPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return &SSHKey{Private: pem.EncodeToMemory(block), Public: pub, Passphrase: cfg.passphrase}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if cfg.passphrase != "" {
		block, err = gossh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(cfg.passphrase))
	} else {
		block, err = gossh.MarshalPrivateKey(priv, "test")
	}
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &SSHKey{Private: pem.EncodeToMemory(block), Public: sshPub, Passphrase: cfg.passphrase}
}

// SSHServer is an SSH server that only serves "git upload-pack" for repositories below a root
// directory, to clients that authenticate with one of the authorized keys.
type SSHServer struct {
	// Host and Port are where the server listens.
	Host string
	Port int
	// KnownHosts has the ed25519 host key of the server in known_hosts format. The server also has
	// an ECDSA host key, which is not in KnownHosts, like when "ssh-keyscan -t ed25519" is used
	// for a server that has several kinds of host keys.
	KnownHosts string
	// HostKey is the ed25519 host key.
	HostKey gossh.PublicKey

	listener net.Listener
	root     string
	config   *gossh.ServerConfig

	mu       sync.Mutex
	sessions int
}

// NewSSHServer starts the server, serving repositories below root.
func NewSSHServer(t TB, root string, authorized ...gossh.PublicKey) *SSHServer {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := gossh.NewSignerFromKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := gossh.NewSignerFromKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	config := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			for _, a := range authorized {
				if bytes.Equal(a.Marshal(), key.Marshal()) {
					return &gossh.Permissions{}, nil
				}
			}
			return nil, errors.New("key is not authorized")
		},
	}
	config.AddHostKey(edSigner)
	config.AddHostKey(ecSigner)

	s := &SSHServer{
		Host:       addr.IP.String(),
		Port:       addr.Port,
		HostKey:    edSigner.PublicKey(),
		KnownHosts: knownhosts.Line([]string{net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))}, edSigner.PublicKey()),
		listener:   listener,
		root:       root,
		config:     config,
	}
	go s.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return s
}

// URL returns the ssh:// URL of a repository below the root, for example "store".
func (s *SSHServer) URL(repo string) string {
	return fmt.Sprintf("ssh://git@%s:%d/%s", s.Host, s.Port, repo)
}

// ScpURL returns the scp-style URL of a repository. It uses the standard port, so it is only
// useful together with a server that listens on port 22.
func (s *SSHServer) ScpURL(repo string) string {
	return fmt.Sprintf("git@%s:%s", s.Host, repo)
}

// Sessions returns how many commands have been run for clients.
func (s *SSHServer) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions
}

func (s *SSHServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *SSHServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	serverConn, channels, requests, err := gossh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer func() { _ = serverConn.Close() }()
	go gossh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "only sessions are supported")
			continue
		}
		channel, reqs, err := newChannel.Accept()
		if err != nil {
			return
		}
		go s.session(channel, reqs)
	}
}

func (s *SSHServer) session(channel gossh.Channel, requests <-chan *gossh.Request) {
	defer func() { _ = channel.Close() }()
	for req := range requests {
		switch req.Type {
		case "env":
			_ = req.Reply(true, nil)
		case "exec":
			var payload struct{ Command string }
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			s.mu.Lock()
			s.sessions++
			s.mu.Unlock()
			status := s.run(channel, payload.Command)
			_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{status}))
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// run executes a "git-upload-pack '<path>'" command and returns its exit status.
func (s *SSHServer) run(channel gossh.Channel, command string) uint32 {
	fail := func(msg string) uint32 {
		_, _ = io.WriteString(channel.Stderr(), msg+"\n")
		return 128
	}

	name, quoted, ok := strings.Cut(command, " ")
	if !ok || (name != "git-upload-pack" && name != "git upload-pack") {
		return fail("only git-upload-pack is allowed")
	}
	repo := strings.Trim(quoted, "'\"")
	dir := filepath.Join(s.root, filepath.Clean("/"+repo))
	if !strings.HasPrefix(dir, filepath.Clean(s.root)+string(filepath.Separator)) {
		return fail("path is outside of the root")
	}

	cmd := exec.Command("git", "upload-pack", dir)
	cmd.Stdin = channel
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	if err := cmd.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return uint32(exitErr.ExitCode())
		}
		return fail(err.Error())
	}
	return 0
}
