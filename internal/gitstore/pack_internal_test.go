package gitstore

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
)

// These tests build packfiles by hand, so that they can be hostile in ways that a real Git server
// never is: objects that claim to be larger than they are, deltas that claim to make gigabytes, a
// count of objects that is not true.

const (
	typeBlob     = 3
	typeRefDelta = 7
)

func deflate(t testing.TB, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// objectHeader is the header of an entry of a packfile: the type and the size, which is spread over
// as many bytes as it takes, with the high bit set while there are more.
func objectHeader(typ byte, size uint64) []byte {
	out := []byte{typ<<4 | byte(size&0x0f)}
	for size >>= 4; size > 0; size >>= 7 {
		out[len(out)-1] |= 0x80
		out = append(out, byte(size&0x7f))
	}
	return out
}

// packEntry is an object of a packfile that says it is size bytes, and holds the data.
func packEntry(t testing.TB, typ byte, declaredSize uint64, data []byte) []byte {
	t.Helper()
	return append(objectHeader(typ, declaredSize), deflate(t, data)...)
}

func blobEntry(t testing.TB, data []byte) []byte {
	return packEntry(t, typeBlob, uint64(len(data)), data)
}

func refDeltaEntry(t testing.TB, base plumbing.Hash, delta []byte) []byte {
	t.Helper()
	out := objectHeader(typeRefDelta, uint64(len(delta)))
	out = append(out, base[:]...)
	return append(out, deflate(t, delta)...)
}

func packOf(count uint32, entries ...[]byte) []byte {
	var b bytes.Buffer
	b.WriteString("PACK")
	_ = binary.Write(&b, binary.BigEndian, uint32(2))
	_ = binary.Write(&b, binary.BigEndian, count)
	for _, e := range entries {
		b.Write(e)
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes()
}

func packOfEntries(entries ...[]byte) []byte { return packOf(uint32(len(entries)), entries...) }

// varint is how a delta spells a size: seven bits per byte, the least significant first.
func varint(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// copyDelta is a delta that makes the first n bytes of a base of baseSize bytes, and says that the
// result is claimed bytes.
func copyDelta(baseSize, claimed uint64, n byte) []byte {
	out := append(varint(baseSize), varint(claimed)...)
	// A copy of n bytes from offset 0: the command, one byte of offset and one of size.
	return append(out, 0x80|0x01|0x10, 0x00, n)
}

var testLimits = limits{maxTransfer: 1 << 20, maxObject: 64 << 10, maxRepository: 256 << 10, maxObjects: 100}

func TestCheckPackAcceptsWhatIsFine(t *testing.T) {
	base := []byte("hello world")
	baseHash := plumbing.ComputeHash(plumbing.BlobObject, base)

	pack := packOfEntries(
		blobEntry(t, base),
		blobEntry(t, []byte("another one")),
		// A delta that makes "hello" out of "hello world".
		refDeltaEntry(t, baseHash, copyDelta(uint64(len(base)), 5, 5)),
	)
	size, err := checkPack(pack, testLimits)
	if err != nil {
		t.Fatalf("checkPack: %v", err)
	}
	// Every object counts with its size, the delta with the size of what it makes, and an overhead.
	if want := int64(11+11+5) + 3*perObjectOverhead; size != want {
		t.Errorf("size = %d, want %d", size, want)
	}
}

func TestCheckPackRefuses(t *testing.T) {
	zeros := func(n int) []byte { return make([]byte, n) }
	baseHash := plumbing.ComputeHash(plumbing.BlobObject, []byte("hello world"))

	tests := map[string]struct {
		pack []byte
		want string // part of the message
		// limit is true when the error is that a limit was exceeded, and not that the pack is broken.
		limit bool
	}{
		"an object that is too large": {
			pack:  packOfEntries(blobEntry(t, zeros(int(testLimits.maxObject)+1))),
			want:  "object of 65537 bytes",
			limit: true,
		},
		"an object that is too large, and is a few bytes on the wire": {
			// 64 MiB of zeros is a few kilobytes of zlib. It is refused for what it claims, without being inflated.
			pack:  packOfEntries(blobEntry(t, zeros(64<<20))),
			want:  "object of 67108864 bytes",
			limit: true,
		},
		"objects that are too large together": {
			// Eight of 40000 bytes are 320000, with the overhead, which is over 256 KiB.
			pack:  packOfEntries(blobEntry(t, zeros(40000)), blobEntry(t, zeros(40001)), blobEntry(t, zeros(40002)), blobEntry(t, zeros(40003)), blobEntry(t, zeros(40004)), blobEntry(t, zeros(40005)), blobEntry(t, zeros(40006)), blobEntry(t, zeros(40007))),
			want:  "repository is larger than",
			limit: true,
		},
		"more objects than allowed, said in the header": {
			// There are no objects at all, the header is the lie. Nothing is read to find that out.
			pack:  packOf(1_000_000),
			want:  "1000000 objects",
			limit: true,
		},
		"a delta that claims to make a gigabyte": {
			pack: packOfEntries(
				blobEntry(t, []byte("hello world")),
				refDeltaEntry(t, baseHash, copyDelta(11, 1<<30, 11)),
			),
			want:  "object of 1073741824 bytes",
			limit: true,
		},
		"a delta that claims more than fits in an integer": {
			pack: packOfEntries(refDeltaEntry(t, baseHash, append(varint(11), varint(1<<63+5)...))),
			want: "valid size",
		},
		"a delta without sizes": {
			pack: packOfEntries(refDeltaEntry(t, baseHash, nil)),
			want: "without sizes",
		},
		"a delta with only one size": {
			pack: packOfEntries(refDeltaEntry(t, baseHash, varint(11))),
			want: "valid size",
		},
		"a delta with a size that does not end": {
			pack: packOfEntries(refDeltaEntry(t, baseHash, bytes.Repeat([]byte{0xff}, 40))),
			want: "without sizes",
		},
		"an object that is larger than it says": {
			// The header says 10 bytes, there are 1 MiB. It stops at 10 and does not inflate the rest.
			pack: packOfEntries(packEntry(t, typeBlob, 10, zeros(1<<20))),
			want: "read the packfile",
		},
		"a packfile that ends before it should": {
			pack: packOf(3, blobEntry(t, []byte("one"))),
			want: "read the packfile",
		},
		"not a packfile": {
			pack: []byte("this is not a packfile, but it is longer than a header"),
			want: "read the packfile",
		},
		"nothing": {
			pack: nil,
			want: "read the packfile",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := checkPack(tt.pack, testLimits)
			if err == nil {
				t.Fatal("checkPack accepted the packfile")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
			if got := errors.Is(err, ErrLimitExceeded); got != tt.limit {
				t.Errorf("errors.Is(err, ErrLimitExceeded) = %v, want %v (%v)", got, tt.limit, err)
			}
		})
	}
}

func TestPackWriterStoresWhatIsFine(t *testing.T) {
	base := []byte("hello world")
	baseHash := plumbing.ComputeHash(plumbing.BlobObject, base)
	pack := packOfEntries(
		blobEntry(t, base),
		refDeltaEntry(t, baseHash, copyDelta(uint64(len(base)), 5, 5)),
	)

	st := newLimitedStorage(testLimits)
	w, err := st.PackfileWriter()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pack); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Both the object and what the delta makes of it can be read.
	for _, content := range []string{"hello world", "hello"} {
		hash := plumbing.ComputeHash(plumbing.BlobObject, []byte(content))
		obj, err := st.EncodedObject(plumbing.BlobObject, hash)
		if err != nil {
			t.Fatalf("object %q: %v", content, err)
		}
		if obj.Size() != int64(len(content)) {
			t.Errorf("object %q has size %d", content, obj.Size())
		}
	}
	if want := int64(11+5) + 2*perObjectOverhead; st.stored != want {
		t.Errorf("stored = %d, want %d", st.stored, want)
	}
}

func TestPackWriterRefusesWhatIsTooMuch(t *testing.T) {
	t.Run("more bytes than the transfer may be", func(t *testing.T) {
		st := newLimitedStorage(limits{maxTransfer: 100, maxObject: 100, maxRepository: 100, maxObjects: 10})
		w, _ := st.PackfileWriter()
		if _, err := w.Write(make([]byte, 60)); err != nil {
			t.Fatal(err)
		}
		_, err := w.Write(make([]byte, 60))
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("err = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("a packfile that is refused is not stored, also what is fine in it", func(t *testing.T) {
		st := newLimitedStorage(testLimits)
		w, _ := st.PackfileWriter()
		small := []byte("this one is fine")
		if _, err := w.Write(packOfEntries(blobEntry(t, small), blobEntry(t, make([]byte, int(testLimits.maxObject)+1)))); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("Close = %v, want ErrLimitExceeded", err)
		}
		if st.stored != 0 {
			t.Errorf("stored = %d for a packfile that was refused", st.stored)
		}
		if _, err := st.EncodedObject(plumbing.BlobObject, plumbing.ComputeHash(plumbing.BlobObject, small)); err == nil {
			t.Error("an object of a packfile that was refused is in the storage")
		}
	})
}

func TestReadVarint(t *testing.T) {
	tests := []struct {
		in   []byte
		want uint64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{varint(300), 300, 2},
		{varint(1 << 40), 1 << 40, 6},
		{append(varint(5), 0xaa, 0xbb), 5, 1}, // what follows is not part of it
		{nil, 0, 0},
		{[]byte{0x80}, 0, 0},                   // it does not end
		{bytes.Repeat([]byte{0xff}, 11), 0, 0}, // longer than a 64 bit integer
		{append(bytes.Repeat([]byte{0xff}, 9), 1), math.MaxUint64, 10}, // ten bytes is the most
	}
	for _, tt := range tests {
		if got, n := readVarint(tt.in); got != tt.want || n != tt.n {
			t.Errorf("readVarint(%x) = %d, %d; want %d, %d", tt.in, got, n, tt.want, tt.n)
		}
	}
}

func TestHeadWriterKeepsTheStart(t *testing.T) {
	w := &headWriter{max: 5}
	n, err := w.Write([]byte("abc"))
	if err != nil || n != 3 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	n, err = w.Write([]byte("defgh"))
	if err != nil || n != 5 {
		t.Fatalf("Write = %d, %v; a writer must say that it took all of it", n, err)
	}
	if string(w.data) != "abcde" {
		t.Errorf("data = %q, want abcde", w.data)
	}
	if n, _ := w.Write([]byte("more")); n != 4 || string(w.data) != "abcde" {
		t.Errorf("data = %q after more writes", w.data)
	}
}
