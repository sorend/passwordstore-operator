package gitstore_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

func TestSnapshotSymlinks(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "files", map[string][]byte{
		"real.gpg":            []byte("real"),
		"team/db/admin.gpg":   []byte("team admin"),
		"team/db/replica.gpg": []byte("replica"),
		"secret-outside.txt":  []byte("OUTSIDE THE STORE"),
		"pass/inside.gpg":     []byte("inside the store"),
	})

	links := []struct{ name, target string }{
		{"alias.gpg", "real.gpg"},                          // same directory
		{"team/alias.gpg", "db/admin.gpg"},                 // relative, going down
		{"team/db/sibling.gpg", "replica.gpg"},             // same directory, deeper
		{"other/up.gpg", "../real.gpg"},                    // going up
		{"chain-a.gpg", "chain-b.gpg"},                     // a chain
		{"chain-b.gpg", "chain-c.gpg"},                     //
		{"chain-c.gpg", "real.gpg"},                        //
		{"shared", "team/db"},                              // a link to a directory
		{"shared-nested", "shared"},                        // a link to a link to a directory
		{"loop-a.gpg", "loop-b.gpg"},                       // a loop
		{"loop-b.gpg", "loop-a.gpg"},                       //
		{"self.gpg", "self.gpg"},                           // a link to itself
		{"dangling.gpg", "does-not-exist.gpg"},             // a link to nothing
		{"to-dir.gpg", "team"},                             // a link to a directory, used as a file
		{"escape.gpg", "../secret-outside.txt"},            // leaves the repository
		{"deep/escape.gpg", "../../secret-outside.txt"},    // leaves the repository from a subdirectory
		{"absolute.gpg", "/etc/passwd"},                    // absolute
		{"pass/up-out.gpg", "../secret-outside.txt"},       // leaves the store when the store is pass/
		{"pass/to-inside.gpg", "inside.gpg"},               // stays in the store when the store is pass/
		{"empty-target.gpg", ""},                           // nonsense
		{"dot.gpg", "."},                                   // the directory itself
		{"dotdot.gpg", ".."},                               // the parent
		{"traverse-in-the-middle.gpg", "team/../real.gpg"}, // cleaned, stays inside
	}
	for _, l := range links {
		if l.target == "" {
			continue // git cannot store an empty link target
		}
		server.CommitSymlink(t, "link "+l.name, l.name, l.target)
	}

	m := newManager(gitstore.Options{})
	root := mustSync(t, m, "root", gitstore.Config{URL: server.URL}, 0)

	tests := []struct {
		name    string
		file    string
		want    string // content, when it can be read
		wantErr string // "notexist" or a part of the message
	}{
		{name: "same directory", file: "alias.gpg", want: "real"},
		{name: "going down", file: "team/alias.gpg", want: "team admin"},
		{name: "deeper", file: "team/db/sibling.gpg", want: "replica"},
		{name: "going up", file: "other/up.gpg", want: "real"},
		{name: "chain", file: "chain-a.gpg", want: "real"},
		{name: "directory link in the middle", file: "shared/admin.gpg", want: "team admin"},
		{name: "directory link to a directory link", file: "shared-nested/replica.gpg", want: "replica"},
		{name: "cleaned target", file: "traverse-in-the-middle.gpg", want: "real"},

		{name: "loop", file: "loop-a.gpg", wantErr: "too many levels"},
		{name: "self", file: "self.gpg", wantErr: "too many levels"},
		{name: "dangling", file: "dangling.gpg", wantErr: "notexist"},
		{name: "link to a directory", file: "to-dir.gpg", wantErr: "notexist"},
		{name: "directory link itself", file: "shared", wantErr: "notexist"},
		{name: "leaves the repository", file: "escape.gpg", wantErr: "leaves the store"},
		{name: "leaves from a subdirectory", file: "deep/escape.gpg", wantErr: "leaves the store"},
		{name: "absolute", file: "absolute.gpg", wantErr: "not inside the store"},
		{name: "link to the directory itself", file: "dot.gpg", wantErr: "leaves the store"},
		{name: "link to the parent", file: "dotdot.gpg", wantErr: "leaves the store"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := root.ReadFile(tt.file)
			switch tt.wantErr {
			case "":
				if err != nil || string(data) != tt.want {
					t.Fatalf("ReadFile(%s) = %q, %v; want %q", tt.file, data, err, tt.want)
				}
			case "notexist":
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("ReadFile(%s) = %q, %v; want fs.ErrNotExist", tt.file, data, err)
				}
			default:
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadFile(%s) = %q, %v; want an error containing %q", tt.file, data, err, tt.wantErr)
				}
				if strings.Contains(string(data), "OUTSIDE") {
					t.Fatalf("ReadFile(%s) leaked content from outside the store", tt.file)
				}
			}
		})
	}

	t.Run("a link cannot leave a store in a subdirectory", func(t *testing.T) {
		store := mustSync(t, m, "sub", gitstore.Config{URL: server.URL, Path: "pass"}, 0)
		if got := mustRead(t, store, "to-inside.gpg"); got != "inside the store" {
			t.Errorf("to-inside.gpg = %q", got)
		}
		// pass/../secret-outside.txt is in the repository but not in the store.
		data, err := store.ReadFile("up-out.gpg")
		if err == nil || !strings.Contains(err.Error(), "leaves the store") {
			t.Fatalf("ReadFile(up-out.gpg) = %q, %v; want a refusal", data, err)
		}
	})

	t.Run("snapshots are used from several goroutines", func(t *testing.T) {
		done := make(chan error, 8)
		for range 8 {
			go func() {
				var err error
				for _, f := range []string{"alias.gpg", "shared/admin.gpg", "chain-a.gpg", "team/alias.gpg"} {
					if _, e := root.ReadFile(f); e != nil {
						err = e
					}
				}
				done <- err
			}()
		}
		for range 8 {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	})
}

func TestSnapshotRejectsSubmodules(t *testing.T) {
	// A gitlink entry (mode 160000) cannot be committed without the git binary, and the
	// package never initializes submodules, so only the symlink and file modes are in play.
	// This documents that a path that goes through a regular file is not an entry.
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"file.gpg": []byte("x")})
	snap := mustSync(t, newManager(gitstore.Options{}), "s", gitstore.Config{URL: server.URL}, 0)
	if _, err := snap.ReadFile("file.gpg/inside"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
	_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", gitstore.Config{URL: server.URL, Path: "file.gpg"}, 0)
	if !errors.Is(err, gitstore.ErrPathNotFound) {
		t.Fatalf("err = %v, want ErrPathNotFound", err)
	}
}
