package gitstore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/storage/memory"
)

// perObjectOverhead estimates the memory that an object takes besides its content.
const perObjectOverhead = 256

// maxDeltaHeader is the number of bytes at the start of a delta that hold the two sizes in it: two
// variable length integers of at most ten bytes each.
const maxDeltaHeader = 20

// limits bounds what one clone may hold.
type limits struct {
	// maxTransfer is the size of the packfile as it comes from the server.
	maxTransfer int64
	// maxObject is the size of one object after decompression, also when it is the result of a delta.
	maxObject int64
	// maxRepository is the size of all objects together after decompression.
	maxRepository int64
	// maxObjects is the number of objects.
	maxObjects int64
}

// limitedStorage is the in-memory storage of a clone. It is a packfile writer, so go-git gives it the packfile
// as it comes from the server, before anything has been decompressed. The packfile of a server can
// be a few kilobytes that decompress to gigabytes, so it is checked first: the declared size of every object
// and the size that a delta makes of its base, which is in the first bytes of the delta, are known
// without decompressing them.
type limitedStorage struct {
	*memory.Storage
	limits limits
	// stored is the memory that the objects take, known when the packfile was stored.
	stored int64
}

func newLimitedStorage(l limits) *limitedStorage {
	return &limitedStorage{Storage: memory.NewStorage(), limits: l}
}

// PackfileWriter makes go-git hand over the packfile to be checked.
func (s *limitedStorage) PackfileWriter() (io.WriteCloser, error) {
	return &packWriter{storage: s}, nil
}

type packWriter struct {
	storage *limitedStorage
	buf     bytes.Buffer
}

func (w *packWriter) Write(p []byte) (int, error) {
	if int64(w.buf.Len()+len(p)) > w.storage.limits.maxTransfer {
		return 0, fmt.Errorf("%w: the packfile is larger than %d bytes", ErrLimitExceeded, w.storage.limits.maxTransfer)
	}
	return w.buf.Write(p)
}

// Close checks the packfile and stores its objects.
func (w *packWriter) Close() error {
	data := w.buf.Bytes()
	size, err := checkPack(data, w.storage.limits)
	if err != nil {
		return err
	}
	if err := packfile.UpdateObjectStorage(w.storage.Storage, bytes.NewReader(data)); err != nil {
		return err
	}
	w.storage.stored += size
	return nil
}

// checkPack checks a packfile against the limits without keeping anything of what it holds, and
// returns the memory that its objects will take.
func checkPack(data []byte, l limits) (int64, error) {
	tooLarge := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrLimitExceeded, fmt.Sprintf(format, args...))
	}

	s := packfile.NewScanner(bytes.NewReader(data))
	_, count, err := s.Header()
	if err != nil {
		return 0, fmt.Errorf("read the packfile: %w", err)
	}
	if int64(count) > l.maxObjects {
		return 0, tooLarge("the repository has %d objects, the limit is %d", count, l.maxObjects)
	}

	var stored int64
	for range count {
		h, err := s.NextObjectHeader()
		if err != nil {
			return 0, fmt.Errorf("read the packfile: %w", err)
		}
		// Whatever it is, it is not decompressed when it is already too large.
		if h.Length > l.maxObject {
			return 0, tooLarge("the repository has an object of %d bytes, the limit is %d", h.Length, l.maxObject)
		}

		size := h.Length
		switch h.Type {
		case plumbing.OFSDeltaObject, plumbing.REFDeltaObject:
			head := &headWriter{max: maxDeltaHeader}
			if _, _, err := s.NextObject(head); err != nil {
				return 0, fmt.Errorf("read the packfile: %w", err)
			}
			if size, err = deltaTargetSize(head.data); err != nil {
				return 0, err
			}
			if size > l.maxObject {
				return 0, tooLarge("the repository has an object of %d bytes, the limit is %d", size, l.maxObject)
			}
		default:
			// The object has to be read to find the end of it. What is read is not kept.
			if _, _, err := s.NextObject(io.Discard); err != nil {
				return 0, fmt.Errorf("read the packfile: %w", err)
			}
		}

		stored += size + perObjectOverhead
		if stored > l.maxRepository {
			return 0, tooLarge("the repository is larger than %d bytes", l.maxRepository)
		}
	}
	return stored, nil
}

// headWriter keeps the first bytes that are written to it, and ignores the rest.
type headWriter struct {
	max  int
	data []byte
}

func (w *headWriter) Write(p []byte) (int, error) {
	if room := w.max - len(w.data); room > 0 {
		w.data = append(w.data, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// deltaTargetSize returns the size of the object that a delta makes, which is the second number in
// the delta, after the size of its base.
func deltaTargetSize(delta []byte) (int64, error) {
	_, n := readVarint(delta)
	if n == 0 {
		return 0, errors.New("read the packfile: a delta without sizes")
	}
	target, m := readVarint(delta[n:])
	if m == 0 || target > math.MaxInt64 {
		return 0, errors.New("read the packfile: a delta without a valid size")
	}
	return int64(target), nil
}

// readVarint reads the variable length integer that Git uses in deltas: seven bits per byte, the
// least significant first, with the high bit set while there are more. n is the number of bytes
// that it was, and 0 if there is no complete integer.
func readVarint(b []byte) (v uint64, n int) {
	var shift uint
	for i, c := range b {
		if i >= 10 {
			return 0, 0
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
	}
	return 0, 0
}
