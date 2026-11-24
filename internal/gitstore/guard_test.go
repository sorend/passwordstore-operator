package gitstore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

// These tests are about servers that misbehave. The Git server of a store is chosen by whoever
// creates the store, so it can be anything: one that never stops talking, one that never talks, one
// that is somewhere that the operator should not go.

// floodSize is how much a flooding server is willing to send. It is far more than any limit.
const floodSize = 200 << 20

// flood is a server that answers every request with a body that does not end, as fast as it is read.
// It counts how much it wrote. A client that stops reading is not written to for much longer: what
// is written without being read stays in the buffers of the sockets, which are a few megabytes.
type flood struct {
	URL     string
	written atomic.Int64
}

func newFlood(t *testing.T, status int, contentType string, body func(w io.Writer, written *atomic.Int64)) *flood {
	t.Helper()
	f := &flood{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		body(w, &f.written)
	}))
	t.Cleanup(server.Close)
	f.URL = server.URL
	return f
}

// write sends p, counts it, and says whether the client is still there.
func write(w io.Writer, written *atomic.Int64, p []byte) bool {
	n, err := w.Write(p)
	written.Add(int64(n))
	return err == nil
}

// text is a body that is words that are not a protocol of any kind.
func text(w io.Writer, written *atomic.Int64) {
	chunk := bytes.Repeat([]byte("THE-ANSWER "), 3<<10)
	for written.Load() < floodSize && write(w, written, chunk) {
	}
}

// references is an advertisement of references that is correct and does not end. It is what a repository
// with a number of branches that nobody has counted looks like to a client that asks for them.
func references(w io.Writer, written *atomic.Int64) {
	const hash = "0123456789abcdef0123456789abcdef01234567"
	pkt := func(payload string) string { return fmt.Sprintf("%04x%s", len(payload)+4, payload) }

	if !write(w, written, []byte(pkt("# service=git-upload-pack\n")+"0000"+pkt(hash+" HEAD\x00side-band-64k\n"))) {
		return
	}
	var chunk strings.Builder
	for i := 0; written.Load() < floodSize; {
		chunk.Reset()
		for range 500 {
			chunk.WriteString(pkt(fmt.Sprintf("%s refs/heads/branch-with-a-long-name-%d\n", hash, i)))
			i++
		}
		if !write(w, written, []byte(chunk.String())) {
			return
		}
	}
}

// notMuch is what a flood may have written when the client stopped reading early: the limits of the
// operator are a few megabytes, and the sockets hold a few more.
const notMuch = 50 << 20

func TestErrorResponsesAreCapped(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newFlood(t, status, "text/plain", text)

			start := time.Now()
			_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", gitstore.Config{URL: f.URL + "/repo.git"}, 0)
			if err == nil {
				t.Fatal("expected an error")
			}
			if len(err.Error()) > 3000 {
				t.Errorf("the error is %d bytes long, the answer of a server must not end up in it", len(err.Error()))
			}
			if took := time.Since(start); took > 10*time.Second {
				t.Errorf("took %s", took)
			}
			if got := f.written.Load(); got > notMuch {
				t.Errorf("the client read until the server had written %d bytes, an error answer must be read for only a small part", got)
			}
		})
	}
}

func TestAnswersThatAreTooLargeAreNotRead(t *testing.T) {
	const advertisement = "application/x-git-upload-pack-advertisement"
	opts := gitstore.Options{MaxRepositoryBytes: 1 << 20} // so, a transfer of at most 2 MiB

	t.Run("the references of a repository", func(t *testing.T) {
		f := newFlood(t, http.StatusOK, advertisement, references)

		_, err := newManager(opts).Sync(context.Background(), "s", gitstore.Config{URL: f.URL + "/repo.git"}, 0)
		if !errors.Is(err, gitstore.ErrLimitExceeded) {
			t.Fatalf("err = %v, want ErrLimitExceeded", err)
		}
		if got := f.written.Load(); got > notMuch {
			t.Errorf("the client read until the server had written %d bytes", got)
		}
	})

	t.Run("the references of a repository that is already held", func(t *testing.T) {
		// The first answer is real, the later ones are the flood. The question is only which commit
		// the branch is at, so what is allowed for that is less than for a download.
		server := testutil.NewGitServer(t)
		server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("x")})

		var flooding atomic.Bool
		var written atomic.Int64
		real := reverseProxy(t, server.URL)
		front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !flooding.Load() {
				real.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", advertisement)
			w.WriteHeader(http.StatusOK)
			references(w, &written)
		}))
		t.Cleanup(front.Close)

		m := newManager(gitstore.Options{})
		cfg := gitstore.Config{URL: front.URL + "/store"}
		mustSync(t, m, "s", cfg, 0)

		flooding.Store(true)
		_, err := m.Sync(context.Background(), "s", cfg, 0)
		if !errors.Is(err, gitstore.ErrLimitExceeded) {
			t.Fatalf("err = %v, want ErrLimitExceeded", err)
		}
		if got := written.Load(); got > notMuch {
			t.Errorf("the client read until the server had written %d bytes, the list of references is limited to a few megabytes", got)
		}
	})
}

func TestAServerThatStopsTalkingIsGivenUpOn(t *testing.T) {
	// The answer starts, and then nothing comes. The limit of time is the one of the fetch, not the
	// one for the arrival of the first byte.
	release := make(chan struct{})
	stalling := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "001e# service=git-upload-pack\n0000")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); stalling.Close() })

	m := newManager(gitstore.Options{Timeout: 400 * time.Millisecond})
	start := time.Now()
	_, err := m.Sync(context.Background(), "s", gitstore.Config{URL: stalling.URL + "/repo.git"}, 0)
	if err == nil {
		t.Fatal("expected an error")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("took %s, the timeout is 400ms", took)
	}
}

// reverseProxy sends requests on to the server that serves the repository at repoURL.
func reverseProxy(t *testing.T, repoURL string) http.Handler {
	t.Helper()
	u, err := url.Parse(repoURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = ""
	return httputil.NewSingleHostReverseProxy(u)
}

// An SSH server that does not behave is the case that go-git leaves open: it has no limit of time for
// the handshake, so a server that says nothing keeps a worker for ever.
func TestSSHServersThatDoNotAnswerAreGivenUpOn(t *testing.T) {
	servers := map[string]func(conn net.Conn, done <-chan struct{}){
		"says nothing": func(_ net.Conn, done <-chan struct{}) { <-done },
		"sends its banner very slowly": func(conn net.Conn, done <-chan struct{}) {
			// A byte every 50ms, of a line that never ends: no limit per read would ever be reached.
			for {
				select {
				case <-done:
					return
				case <-time.After(50 * time.Millisecond):
					if _, err := conn.Write([]byte("S")); err != nil {
						return
					}
				}
			}
		},
		"talks a lot and says nothing": func(conn net.Conn, done <-chan struct{}) {
			chunk := bytes.Repeat([]byte("SSH-2.0-"), 1<<12)
			for {
				select {
				case <-done:
					return
				default:
					if _, err := conn.Write(chunk); err != nil {
						return
					}
				}
			}
		},
	}

	for name, behave := range servers {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					wg.Go(func() {
						defer func() { _ = conn.Close() }()
						behave(conn, done)
					})
				}
			})
			t.Cleanup(func() { close(done); _ = listener.Close(); wg.Wait() })

			key := testutil.NewSSHKey(t)
			cfg := gitstore.Config{
				URL:  fmt.Sprintf("ssh://git@%s/store", listener.Addr()),
				Auth: gitstore.Auth{SSH: &gitstore.SSHAuth{PrivateKey: key.Private, InsecureIgnoreHostKey: true}},
			}
			m := newManager(gitstore.Options{Timeout: 500 * time.Millisecond})

			start := time.Now()
			_, err = m.Sync(context.Background(), "s", cfg, 0)
			if err == nil {
				t.Fatal("expected an error")
			}
			if took := time.Since(start); took > 4*time.Second {
				t.Errorf("took %s, the timeout is 500ms", took)
			}

			// What matters most: the store is free again. Whoever asks next is not held up by the first.
			start = time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err = m.Sync(ctx, "s", cfg, 0)
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("the second caller waited for the first until its own time ran out: %v", err)
			}
			if took := time.Since(start); took > 4*time.Second {
				t.Errorf("the second caller took %s", took)
			}
		})
	}
}

func TestStoresOnServersThatDoNotAnswerDoNotHoldUpOtherStores(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { defer func() { _ = conn.Close() }(); <-done })
		}
	})
	t.Cleanup(func() { close(done); _ = listener.Close(); wg.Wait() })

	key := testutil.NewSSHKey(t)
	stuck := gitstore.Config{
		URL:  fmt.Sprintf("ssh://git@%s/store", listener.Addr()),
		Auth: gitstore.Auth{SSH: &gitstore.SSHAuth{PrivateKey: key.Private, InsecureIgnoreHostKey: true}},
	}
	good := testutil.NewGitServer(t)
	good.Commit(t, "init", map[string][]byte{"a.gpg": []byte("x")})

	m := newManager(gitstore.Options{Timeout: 2 * time.Second})

	// Six stores on a server that says nothing, more than there are workers or slots for downloads.
	var wg2 sync.WaitGroup
	for i := range 6 {
		wg2.Go(func() { _, _ = m.Sync(context.Background(), fmt.Sprintf("stuck-%d", i), stuck, 0) })
	}
	time.Sleep(200 * time.Millisecond)

	// A store that is fine is served as soon as a slot is free, which is within the timeout.
	start := time.Now()
	if _, err := m.Sync(context.Background(), "good", gitstore.Config{URL: good.URL}, 0); err != nil {
		t.Fatalf("a good store, next to stuck ones: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the good store waited %s for the stuck ones", took)
	}
	wg2.Wait()
}

func TestLoopbackIsRefusedByDefault(t *testing.T) {
	// A Manager that is made as the operator makes it, without the permission that the other tests
	// give theirs. The servers of the tests are on the loopback interface.
	m := gitstore.NewManager(gitstore.Options{})
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("x")})

	t.Run("http", func(t *testing.T) {
		_, err := m.Sync(context.Background(), "http", gitstore.Config{URL: server.URL}, 0)
		if !errors.Is(err, gitstore.ErrAddressNotAllowed) {
			t.Fatalf("err = %v, want ErrAddressNotAllowed", err)
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("the message does not say why: %v", err)
		}
	})

	t.Run("a name that resolves to the loopback interface", func(t *testing.T) {
		// Checking the name would not be enough, it is the address that it resolves to.
		url := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
		_, err := m.Sync(context.Background(), "localhost", gitstore.Config{URL: url}, 0)
		if !errors.Is(err, gitstore.ErrAddressNotAllowed) {
			t.Fatalf("err = %v, want ErrAddressNotAllowed", err)
		}
	})

	t.Run("ssh", func(t *testing.T) {
		f := newSSHFixture(t)
		_, err := m.Sync(context.Background(), "ssh", f.cfg(), 0)
		if !errors.Is(err, gitstore.ErrAddressNotAllowed) {
			t.Fatalf("err = %v, want ErrAddressNotAllowed", err)
		}
		if f.server.Sessions() != 0 {
			t.Error("a connection was made to the server")
		}
	})

	t.Run("the api of a GitHub App", func(t *testing.T) {
		pemKey, key := testutil.NewRSAKeyPEM(t)
		github := testutil.NewFakeGitHubApp(t, 1, 2, &key.PublicKey)
		cfg := gitstore.Config{URL: "https://git.example.com/org/repo.git", Auth: gitstore.Auth{App: &gitstore.AppAuth{
			AppID: 1, InstallationID: 2, PrivateKey: pemKey, BaseURL: github.URL,
		}}}
		_, err := m.Sync(context.Background(), "github", cfg, 0)
		if !errors.Is(err, gitstore.ErrAddressNotAllowed) {
			t.Fatalf("err = %v, want ErrAddressNotAllowed", err)
		}
		if github.Requests() != 0 {
			t.Error("the key of the App was used on the loopback interface")
		}
	})

	t.Run("the metadata service of a cloud", func(t *testing.T) {
		// Nothing listens there in a test, so the refusal is what the error is about.
		_, err := m.Sync(context.Background(), "metadata", gitstore.Config{URL: "http://169.254.169.254/latest/meta-data/"}, 0)
		if !errors.Is(err, gitstore.ErrAddressNotAllowed) {
			t.Fatalf("err = %v, want ErrAddressNotAllowed", err)
		}
	})

	t.Run("and a failure of that kind is not a reason to stop talking to the others", func(t *testing.T) {
		if _, err := newManager(gitstore.Options{}).Sync(context.Background(), "ok", gitstore.Config{URL: server.URL}, 0); err != nil {
			t.Fatalf("with the permission, the same server is fine: %v", err)
		}
	})
}

func TestAllowedHosts(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("x")})
	cfg := gitstore.Config{URL: server.URL} // http://127.0.0.1:<port>/store

	t.Run("a host that is in the list", func(t *testing.T) {
		m := newManager(gitstore.Options{AllowedHosts: []string{"github.com", "127.0.0.1"}})
		mustSync(t, m, "s", cfg, 0)
	})

	t.Run("a host that is not", func(t *testing.T) {
		before := len(server.Requests())
		m := newManager(gitstore.Options{AllowedHosts: []string{"github.com", "*.example.com"}})
		_, err := m.Sync(context.Background(), "s", cfg, 0)
		if !errors.Is(err, gitstore.ErrHostNotAllowed) {
			t.Fatalf("err = %v, want ErrHostNotAllowed", err)
		}
		for _, want := range []string{"127.0.0.1", "github.com", "*.example.com"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the message %q does not mention %s", err, want)
			}
		}
		if got := server.Requests(); len(got) != before {
			t.Errorf("the server was contacted: %v", got[before:])
		}
	})

	t.Run("ssh and scp-style addresses are checked by their host", func(t *testing.T) {
		m := newManager(gitstore.Options{AllowedHosts: []string{"github.com"}})
		key := testutil.NewSSHKey(t)
		auth := gitstore.Auth{SSH: &gitstore.SSHAuth{PrivateKey: key.Private, InsecureIgnoreHostKey: true}}
		for _, url := range []string{"git@gitlab.com:org/repo.git", "ssh://git@gitlab.com:2222/org/repo.git"} {
			if _, err := m.Sync(context.Background(), "s", gitstore.Config{URL: url, Auth: auth}, 0); !errors.Is(err, gitstore.ErrHostNotAllowed) {
				t.Errorf("%s: err = %v, want ErrHostNotAllowed", url, err)
			}
		}
	})

	t.Run("the api of a GitHub App is checked too", func(t *testing.T) {
		pemKey, _ := testutil.NewRSAKeyPEM(t)
		m := newManager(gitstore.Options{AllowedHosts: []string{"github.com"}})
		cfg := gitstore.Config{URL: "https://github.com/org/repo.git", Auth: gitstore.Auth{App: &gitstore.AppAuth{
			AppID: 1, InstallationID: 2, PrivateKey: pemKey, BaseURL: "https://api.evil.example.com",
		}}}
		_, err := m.Sync(context.Background(), "s", cfg, 0)
		if !errors.Is(err, gitstore.ErrHostNotAllowed) || !strings.Contains(err.Error(), "api.evil.example.com") {
			t.Fatalf("err = %v, want ErrHostNotAllowed for the host of the API", err)
		}
	})

	t.Run("an empty list is no restriction", func(t *testing.T) {
		mustSync(t, newManager(gitstore.Options{AllowedHosts: []string{}}), "s", cfg, 0)
	})
}

// A Git server is free to answer with a redirect. What the operator sends to a server in the way
// of credentials is for that server, and not for where it sends the operator next.
func TestCredentialsAreNotSentWhereARedirectGoes(t *testing.T) {
	var hits atomic.Int64
	var sawCredentials atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "" {
			sawCredentials.Store(true)
		}
		http.Error(w, "nothing here", http.StatusNotFound)
	}))
	t.Cleanup(elsewhere.Close)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path+"?"+r.URL.RawQuery, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	t.Run("a token for a repository", func(t *testing.T) {
		_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s",
			tokenCfg(redirecting.URL+"/repo.git", "x-access-token", "s3cr3t-token-value"), 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		if hits.Load() == 0 {
			t.Fatal("the redirect was not followed, so this test does not show anything")
		}
		if sawCredentials.Load() {
			t.Error("the token was sent to the server that the redirect leads to")
		}
	})

	t.Run("the key of a GitHub App", func(t *testing.T) {
		hits.Store(0)
		pemKey, _ := testutil.NewRSAKeyPEM(t)
		cfg := gitstore.Config{URL: "https://git.example.com/org/repo.git", Auth: gitstore.Auth{App: &gitstore.AppAuth{
			AppID: 1, InstallationID: 2, PrivateKey: pemKey, BaseURL: redirecting.URL,
		}}}
		_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", cfg, 0)
		if err == nil || !strings.Contains(err.Error(), "307") {
			t.Fatalf("err = %v, want the redirect to be the answer", err)
		}
		if hits.Load() != 0 || sawCredentials.Load() {
			t.Errorf("the request that holds the signed JWT was sent on (%d requests there)", hits.Load())
		}
	})
}
