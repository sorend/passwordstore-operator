package gitstore_test

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

// incompressible returns n bytes that do not shrink when they are compressed, so that what a
// repository is on the wire is what it is in memory. The same seed gives the same bytes.
func incompressible(seed uint64, n int) []byte {
	r := rand.New(rand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8)}))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func TestSyncRefusesWhatIsTooLarge(t *testing.T) {
	t.Run("an object that is a few kilobytes on the wire, and megabytes in memory", func(t *testing.T) {
		server := testutil.NewGitServer(t)
		// Zeros shrink to almost nothing: this is the pack of a repository that a client would inflate.
		server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("fine"), "bomb.gpg": make([]byte, 4<<20)})

		m := newManager(gitstore.Options{MaxRepositoryBytes: 1 << 20})
		_, err := m.Sync(context.Background(), "s", gitstore.Config{URL: server.URL}, 0)
		if !errors.Is(err, gitstore.ErrLimitExceeded) {
			t.Fatalf("err = %v, want ErrLimitExceeded", err)
		}
		if !strings.Contains(err.Error(), "object of 4194304 bytes") {
			t.Errorf("the message does not say what is too large: %v", err)
		}
	})

	t.Run("objects that are too much together", func(t *testing.T) {
		server := testutil.NewGitServer(t)
		files := map[string][]byte{}
		for i := range 8 {
			files["entry-"+string(rune('a'+i))+".gpg"] = incompressible(uint64(i), 200<<10)
		}
		server.Commit(t, "init", files) // 1.6 MiB

		m := newManager(gitstore.Options{MaxRepositoryBytes: 1 << 20})
		_, err := m.Sync(context.Background(), "s", gitstore.Config{URL: server.URL}, 0)
		if !errors.Is(err, gitstore.ErrLimitExceeded) || !strings.Contains(err.Error(), "repository is larger than 1048576 bytes") {
			t.Fatalf("err = %v, want ErrLimitExceeded about the size of the repository", err)
		}
	})

	t.Run("a repository that is just within the limit", func(t *testing.T) {
		server := testutil.NewGitServer(t)
		files := map[string][]byte{}
		for i := range 4 {
			files["entry-"+string(rune('a'+i))+".gpg"] = incompressible(uint64(i), 200<<10)
		}
		server.Commit(t, "init", files) // 800 KiB

		snap := mustSync(t, newManager(gitstore.Options{MaxRepositoryBytes: 1 << 20}), "s", gitstore.Config{URL: server.URL}, 0)
		got, err := snap.ReadFile("entry-c.gpg")
		if err != nil || !bytes.Equal(got, incompressible(2, 200<<10)) {
			t.Fatalf("ReadFile: %d bytes, %v", len(got), err)
		}
	})

	t.Run("the failure is remembered for the cooldown, and the others are not affected", func(t *testing.T) {
		bad := testutil.NewGitServer(t)
		bad.Commit(t, "init", map[string][]byte{"bomb.gpg": make([]byte, 4<<20)})
		good := testutil.NewGitServer(t)
		good.Commit(t, "init", map[string][]byte{"a.gpg": []byte("x")})

		m := newManager(gitstore.Options{MaxRepositoryBytes: 1 << 20})
		if _, err := m.Sync(context.Background(), "bad", gitstore.Config{URL: bad.URL}, time.Hour); err == nil {
			t.Fatal("expected an error")
		}
		requests := len(bad.Requests())
		if _, err := m.Sync(context.Background(), "bad", gitstore.Config{URL: bad.URL}, time.Hour); !errors.Is(err, gitstore.ErrLimitExceeded) {
			t.Fatalf("err = %v, want the same error again", err)
		}
		if got := len(bad.Requests()); got != requests {
			t.Errorf("a store that is too large was downloaded again within the cooldown (%d requests)", got-requests)
		}
		mustSync(t, m, "good", gitstore.Config{URL: good.URL}, 0)
	})
}

// repository makes a server with one file of the size, as one commit.
func repository(t *testing.T, seed uint64, size int) *testutil.GitServer {
	t.Helper()
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"entry.gpg": incompressible(seed, size)})
	return server
}

func TestCacheDropsWhatWasUsedLeast(t *testing.T) {
	// Each repository is 600 KiB, so that two fit in the cache of 1.5 MiB and three do not.
	const size = 600 << 10
	opts := func(clock *fakeClock) gitstore.Options {
		return gitstore.Options{MaxRepositoryBytes: 1 << 20, CacheBytes: 3 << 19, Now: clock.Now}
	}
	cfg := func(s *testutil.GitServer) gitstore.Config { return gitstore.Config{URL: s.URL} }

	t.Run("the one that was used longest ago goes", func(t *testing.T) {
		clock := newClock()
		m := newManager(opts(clock))
		a, b, c := repository(t, 1, size), repository(t, 2, size), repository(t, 3, size)

		mustSync(t, m, "a", cfg(a), 0)
		clock.Advance(time.Second)
		mustSync(t, m, "b", cfg(b), 0)
		clock.Advance(time.Second)
		mustSync(t, m, "a", cfg(a), 0) // a is now the one that was used last
		clock.Advance(time.Second)
		if a.Fetches() != 1 || b.Fetches() != 1 {
			t.Fatalf("both fit and are kept: downloads a=%d b=%d", a.Fetches(), b.Fetches())
		}

		mustSync(t, m, "c", cfg(c), 0) // no room: b goes
		clock.Advance(time.Second)

		mustSync(t, m, "a", cfg(a), 0)
		if a.Fetches() != 1 {
			t.Errorf("a was used last and must still be held, but it was downloaded %d times", a.Fetches())
		}
		mustSync(t, m, "c", cfg(c), 0)
		if c.Fetches() != 1 {
			t.Errorf("c is new and must be held, downloads: %d", c.Fetches())
		}
		mustSync(t, m, "b", cfg(b), 0)
		if b.Fetches() != 2 {
			t.Errorf("b was used least and must have been dropped, downloads: %d", b.Fetches())
		}
	})

	t.Run("what was dropped still reads, for whoever has it", func(t *testing.T) {
		clock := newClock()
		m := newManager(gitstore.Options{MaxRepositoryBytes: 1 << 20, CacheBytes: 1 << 20, Now: clock.Now})
		a, b := repository(t, 1, size), repository(t, 2, size)

		snapA := mustSync(t, m, "a", cfg(a), 0)
		clock.Advance(time.Second)
		mustSync(t, m, "b", cfg(b), 0) // only one fits: a is dropped from the cache

		got, err := snapA.ReadFile("entry.gpg")
		if err != nil || !bytes.Equal(got, incompressible(1, size)) {
			t.Fatalf("a snapshot that is being used must not be pulled from under its user: %d bytes, %v", len(got), err)
		}
	})

	t.Run("a store that is being refreshed is not waited for, and the new one gets in at the next try", func(t *testing.T) {
		clock := newClock()
		m := newManager(gitstore.Options{MaxRepositoryBytes: 1 << 20, CacheBytes: 1 << 20, Now: clock.Now})
		a, b := repository(t, 1, size), repository(t, 2, size)

		// The server of a can be made to keep the answer to what its branches are.
		var hold atomic.Bool
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		real := reverseProxy(t, a.URL)
		front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hold.Load() {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			real.ServeHTTP(w, r)
		}))
		t.Cleanup(front.Close)
		aCfg := gitstore.Config{URL: front.URL + "/store"}

		mustSync(t, m, "a", aCfg, 0) // a takes the room that there is
		clock.Advance(time.Second)

		hold.Store(true)
		refreshed := make(chan error, 1)
		go func() {
			_, err := m.Sync(context.Background(), "a", aCfg, 0)
			refreshed <- err
		}()
		select {
		case <-entered: // a is now being refreshed, and nobody else can use what it holds
		case <-time.After(10 * time.Second):
			t.Fatal("the refresh of a did not start")
		}

		// b needs room, and the only room is what a holds. It does not wait for a, and does not take it.
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := m.Sync(ctx, "b", cfg(b), 0)
		if !errors.Is(err, gitstore.ErrLimitExceeded) || !strings.Contains(err.Error(), "no room") {
			t.Fatalf("err = %v, want ErrLimitExceeded because there is no room", err)
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("b waited %s for a, which has a lock that is held", took)
		}

		hold.Store(false)
		close(release)
		if err := <-refreshed; err != nil {
			t.Fatalf("the refresh of a: %v", err)
		}

		// Nothing is lost by it: when a is free again, b makes room.
		clock.Advance(time.Minute)
		mustSync(t, m, "b", cfg(b), 0)
	})
}

func TestIdleStoresAreForgotten(t *testing.T) {
	clock := newClock()
	m := newManager(gitstore.Options{Now: clock.Now})
	a, b := repository(t, 1, 1<<10), repository(t, 2, 1<<10)

	mustSync(t, m, "a", gitstore.Config{URL: a.URL}, 0)
	mustSync(t, m, "a", gitstore.Config{URL: a.URL}, 0)
	if a.Fetches() != 1 {
		t.Fatalf("a is held: downloads = %d", a.Fetches())
	}

	// Nobody asks for a for a long time, as when a store was deleted while it was being fetched.
	clock.Advance(3 * time.Hour)
	mustSync(t, m, "b", gitstore.Config{URL: b.URL}, 0) // asking for any store is when the idle ones are looked for

	mustSync(t, m, "a", gitstore.Config{URL: a.URL}, 0)
	if a.Fetches() != 2 {
		t.Errorf("a had been idle for three hours and must have been dropped: downloads = %d", a.Fetches())
	}

	t.Run("one that is asked for now and then stays", func(t *testing.T) {
		clock := newClock()
		m := newManager(gitstore.Options{Now: clock.Now})
		c, d := repository(t, 3, 1<<10), repository(t, 4, 1<<10)
		for range 5 {
			mustSync(t, m, "c", gitstore.Config{URL: c.URL}, 0)
			clock.Advance(30 * time.Minute)
			mustSync(t, m, "d", gitstore.Config{URL: d.URL}, 0)
		}
		if c.Fetches() != 1 {
			t.Errorf("c is used every half hour and must be held: downloads = %d", c.Fetches())
		}
	})
}

func TestAFailureOfTheCallerIsNotAFailureOfTheStore(t *testing.T) {
	server := repository(t, 1, 1<<10)

	var block atomic.Bool
	block.Store(true)
	hits := atomic.Int64{}
	real := reverseProxy(t, server.URL)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if block.Load() {
			<-r.Context().Done()
			return
		}
		real.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)

	m := newManager(gitstore.Options{Timeout: 30 * time.Second})
	cfg := gitstore.Config{URL: front.URL + "/store"}

	// The caller gives up while the server is slow.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := m.Sync(ctx, "s", cfg, time.Hour); err == nil {
		t.Fatal("expected an error")
	}

	// The next caller, within the cooldown, is not told that the store failed. It asks again.
	block.Store(false)
	before := hits.Load()
	snap, err := m.Sync(context.Background(), "s", cfg, time.Hour)
	if err != nil {
		t.Fatalf("the cancellation of another caller was remembered as a failure of the store: %v", err)
	}
	if hits.Load() == before {
		t.Error("the server was not asked again")
	}
	if _, err := snap.ReadFile("entry.gpg"); err != nil {
		t.Error(err)
	}
}

func TestTagsAreNotDownloadedAgainAndAgain(t *testing.T) {
	for name, annotated := range map[string]bool{"lightweight tag": false, "annotated tag": true} {
		t.Run(name, func(t *testing.T) {
			server := testutil.NewGitServer(t)
			first := server.Commit(t, "release", map[string][]byte{"a.gpg": []byte("v1")})
			server.Tag(t, "v1", annotated)
			// The branch moves on, the tag stays.
			server.Commit(t, "later", map[string][]byte{"a.gpg": []byte("later")})

			m := newManager(gitstore.Options{})
			cfg := gitstore.Config{URL: server.URL, Branch: "refs/tags/v1"}

			snap := mustSync(t, m, "s", cfg, 0)
			if snap.Revision() != first {
				t.Fatalf("revision = %s, want the commit of the tag, %s", snap.Revision(), first)
			}
			if got := mustRead(t, snap, "a.gpg"); got != "v1" {
				t.Errorf("a.gpg = %q, want what the tag has", got)
			}
			for range 3 {
				mustSync(t, m, "s", cfg, 0)
			}
			if server.Fetches() != 1 {
				t.Errorf("a tag does not move, but it was downloaded %d times", server.Fetches())
			}
		})
	}
}
