package gitstore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

const (
	// MaxFileSize bounds the size of a file that is read from a repository. An entry that is
	// encrypted from the largest plaintext that fits in a Secret is a little over 1 MiB.
	MaxFileSize = 2 << 20

	// maxSymlinkHops bounds the number of symbolic links that are followed to find a file.
	maxSymlinkHops = 8
)

// ErrPathNotFound means the configured path of the store does not exist in the repository.
var ErrPathNotFound = errors.New("path of the password store not found in the repository")

// Snapshot is a read-only view of the password store at one commit. It is safe for concurrent
// use, and it stays valid and unchanged when newer commits are fetched.
type Snapshot struct {
	storer storer.EncodedObjectStorer
	commit plumbing.Hash
	// root is the tree of the directory that holds the store.
	root plumbing.Hash
}

// Revision returns the SHA of the commit that the snapshot was taken from.
func (s *Snapshot) Revision() string {
	return s.commit.String()
}

// ReadFile returns the content of a file of the store. name is relative to the root of the
// store and uses "/" as separator. Symbolic links inside the repository are followed, but a link
// that leads out of the store is an error. A file that does not exist is an error that matches
// fs.ErrNotExist.
func (s *Snapshot) ReadFile(name string) ([]byte, error) {
	file, err := s.find(name)
	if err != nil {
		return nil, err
	}
	if file.Size > MaxFileSize {
		return nil, fmt.Errorf("%s is %d bytes, which is more than the limit of %d bytes", name, file.Size, MaxFileSize)
	}

	r, err := file.Reader()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	defer func() { _ = r.Close() }()

	data, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

func notExist(name string) error {
	return &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
}

// find locates the file, following symbolic links.
func (s *Snapshot) find(name string) (*object.File, error) {
	segments := strings.Split(name, "/")
	for range maxSymlinkHops + 1 {
		file, redirected, err := s.walk(name, segments)
		if err != nil {
			return nil, err
		}
		if file != nil {
			return file, nil
		}
		segments = redirected
	}
	return nil, fmt.Errorf("%s: too many levels of symbolic links", name)
}

// walk follows segments from the root of the store. It returns the file when it reaches one.
// When it meets a symbolic link it returns the segments that continue the walk from the root.
//
// Trees are loaded again for every walk. A Tree caches what it decodes without locking, so
// sharing one between concurrent readers would be a data race.
func (s *Snapshot) walk(name string, segments []string) (file *object.File, redirected []string, err error) {
	tree, err := object.GetTree(s.storer, s.root)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", name, err)
	}

	var dir []string // the directory that tree is, which relative links are resolved against
	for i, segment := range segments {
		last := i == len(segments)-1

		e, err := tree.FindEntry(segment)
		if err != nil {
			if errors.Is(err, object.ErrEntryNotFound) || errors.Is(err, object.ErrDirectoryNotFound) {
				return nil, nil, notExist(name)
			}
			return nil, nil, fmt.Errorf("read %s: %w", name, err)
		}

		switch e.Mode {
		case filemode.Dir:
			if last {
				return nil, nil, notExist(name)
			}
			if tree, err = object.GetTree(s.storer, e.Hash); err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", name, err)
			}
			dir = append(dir, segment)

		case filemode.Symlink:
			target, err := s.linkTarget(e.Hash)
			if err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", name, err)
			}
			resolved, err := resolveLink(dir, target)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			return nil, append(strings.Split(resolved, "/"), segments[i+1:]...), nil

		case filemode.Regular, filemode.Executable, filemode.Deprecated:
			if !last {
				return nil, nil, notExist(name)
			}
			f, err := tree.TreeEntryFile(e)
			if err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", name, err)
			}
			return f, nil, nil

		default:
			return nil, nil, fmt.Errorf("%s: %s is a submodule or has an unsupported file mode", name, segment)
		}
	}
	return nil, nil, notExist(name)
}

// linkTarget reads the target of a symbolic link, which Git stores as the content of a blob.
func (s *Snapshot) linkTarget(hash plumbing.Hash) (string, error) {
	blob, err := object.GetBlob(s.storer, hash)
	if err != nil {
		return "", err
	}
	if blob.Size > 4096 {
		return "", errors.New("symbolic link target is too long")
	}
	r, err := blob.Reader()
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()
	target, err := io.ReadAll(r)
	return string(target), err
}

// resolveLink resolves the target of a link that is in directory dir, to a path relative to the
// root of the store. Targets that are absolute or that leave the store are refused.
func resolveLink(dir []string, target string) (string, error) {
	if target == "" || path.IsAbs(target) {
		return "", fmt.Errorf("symbolic link to %q is not inside the store", target)
	}
	resolved := path.Join(path.Join(dir...), target)
	if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") {
		return "", fmt.Errorf("symbolic link to %q leaves the store", target)
	}
	return resolved, nil
}
