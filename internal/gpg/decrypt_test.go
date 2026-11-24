package gpg_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/sorend/passwordstore-operator/internal/gpg"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func mustDecrypter(t *testing.T, key *testutil.PGPKey, id string) *gpg.Decrypter {
	t.Helper()
	d, err := gpg.NewDecrypter(key.Private, id, []byte(key.Passphrase))
	if err != nil {
		t.Fatalf("NewDecrypter(%q): %v", id, err)
	}
	return d
}

func TestDecryptRoundTrip(t *testing.T) {
	keys := map[string]*testutil.PGPKey{
		"curve25519": testutil.NewPGPKey(t, "ed@example.com"),
		"rsa":        testutil.NewPGPKey(t, "rsa@example.com", testutil.WithRSA()),
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			d := mustDecrypter(t, key, key.Email)
			if d.Fingerprint() != key.Fingerprint {
				t.Errorf("Fingerprint() = %s, want %s", d.Fingerprint(), key.Fingerprint)
			}

			const plaintext = "correct horse battery staple\nusername: bob\n"
			for msgName, msg := range map[string][]byte{
				"binary":  testutil.Encrypt(t, plaintext, key),
				"armored": testutil.EncryptArmored(t, plaintext, key),
			} {
				got, err := d.Decrypt(msg)
				if err != nil {
					t.Fatalf("%s: Decrypt: %v", msgName, err)
				}
				if string(got) != plaintext {
					t.Errorf("%s: Decrypt = %q, want %q", msgName, got, plaintext)
				}
			}
		})
	}
}

func TestDecryptBinaryPrivateKey(t *testing.T) {
	key := testutil.NewPGPKey(t, "bin@example.com")
	var buf bytes.Buffer
	if err := key.Entity.SerializePrivateWithoutSigning(&buf, nil); err != nil {
		t.Fatal(err)
	}

	d, err := gpg.NewDecrypter(buf.Bytes(), key.Email, nil)
	if err != nil {
		t.Fatalf("NewDecrypter with binary key: %v", err)
	}
	got, err := d.Decrypt(testutil.Encrypt(t, "secret", key))
	if err != nil || string(got) != "secret" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
}

func TestDecryptEmptyAndBinaryPlaintext(t *testing.T) {
	key := testutil.NewPGPKey(t, "data@example.com")
	d := mustDecrypter(t, key, key.Email)

	for name, plaintext := range map[string]string{
		"empty":  "",
		"binary": "\x00\x01\x02\xff\xfe",
	} {
		got, err := d.Decrypt(testutil.Encrypt(t, plaintext, key))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != plaintext {
			t.Errorf("%s: got %q, want %q", name, got, plaintext)
		}
	}
}

func TestDecryptMultipleRecipients(t *testing.T) {
	a := testutil.NewPGPKey(t, "a@example.com")
	b := testutil.NewPGPKey(t, "b@example.com")
	msg := testutil.Encrypt(t, "shared", a, b)

	for _, key := range []*testutil.PGPKey{a, b} {
		got, err := mustDecrypter(t, key, key.Email).Decrypt(msg)
		if err != nil || string(got) != "shared" {
			t.Errorf("recipient %s: got %q, %v", key.Email, got, err)
		}
	}
}

func TestSelectKeyByID(t *testing.T) {
	key := testutil.NewPGPKey(t, "select@example.com")
	other := testutil.NewPGPKey(t, "other@example.com")

	// A key file holding two keys, as produced by exporting several keys at once.
	var ring bytes.Buffer
	for _, k := range []*testutil.PGPKey{other, key} {
		if err := k.Entity.SerializePrivateWithoutSigning(&ring, nil); err != nil {
			t.Fatal(err)
		}
	}

	fp := key.Fingerprint
	grouped := fp[0:4] + " " + fp[4:8] + " " + fp[8:12] + " " + fp[12:16] + " " + fp[16:20] + "  " +
		fp[20:24] + " " + fp[24:28] + " " + fp[28:32] + " " + fp[32:36] + " " + fp[36:40]

	for name, id := range map[string]string{
		"fingerprint":            fp,
		"lowercase fingerprint":  strings.ToLower(fp),
		"0x fingerprint":         "0x" + fp,
		"grouped fingerprint":    grouped,
		"long key id":            fp[24:],
		"0x long key id":         "0x" + fp[24:],
		"short key id":           fp[32:],
		"email":                  "select@example.com",
		"email in angle bracket": "<select@example.com>",
		"uppercase email":        "SELECT@EXAMPLE.COM",
		"name and email":         "Test <select@example.com>",
	} {
		t.Run(name, func(t *testing.T) {
			d, err := gpg.NewDecrypter(ring.Bytes(), id, nil)
			if err != nil {
				t.Fatalf("NewDecrypter(%q): %v", id, err)
			}
			if d.Fingerprint() != fp {
				t.Errorf("selected key %s, want %s", d.Fingerprint(), fp)
			}
		})
	}

	t.Run("no match lists available keys", func(t *testing.T) {
		_, err := gpg.NewDecrypter(ring.Bytes(), "nobody@example.com", nil)
		if !errors.Is(err, gpg.ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
		for _, k := range []*testutil.PGPKey{key, other} {
			if !strings.Contains(err.Error(), k.Fingerprint) {
				t.Errorf("error %q does not list key %s", err, k.Fingerprint)
			}
		}
	})

	t.Run("ambiguous", func(t *testing.T) {
		_, err := gpg.NewDecrypter(ring.Bytes(), "@example.com", nil)
		if !errors.Is(err, gpg.ErrAmbiguousKey) {
			t.Fatalf("err = %v, want ErrAmbiguousKey", err)
		}
	})

	t.Run("empty id", func(t *testing.T) {
		if _, err := gpg.NewDecrypter(ring.Bytes(), "  ", nil); !errors.Is(err, gpg.ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
	})
}

func TestNewDecrypterRejectsPublicKey(t *testing.T) {
	key := testutil.NewPGPKey(t, "pub@example.com")
	_, err := gpg.NewDecrypter(key.Public, key.Email, nil)
	if !errors.Is(err, gpg.ErrNoPrivateKey) {
		t.Fatalf("err = %v, want ErrNoPrivateKey", err)
	}
}

func TestNewDecrypterRejectsGarbage(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":   nil,
		"text":    []byte("not a key"),
		"armored": []byte("-----BEGIN PGP PRIVATE " + "KEY BLOCK-----\n\nbm9wZQ==\n=abcd\n-----END PGP PRIVATE " + "KEY BLOCK-----\n"),
	} {
		if _, err := gpg.NewDecrypter(data, "x@example.com", nil); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPassphrase(t *testing.T) {
	key := testutil.NewPGPKey(t, "locked@example.com", testutil.WithPassphrase("hunter2"))
	msg := testutil.Encrypt(t, "behind a passphrase", key)

	t.Run("missing", func(t *testing.T) {
		_, err := gpg.NewDecrypter(key.Private, key.Email, nil)
		if !errors.Is(err, gpg.ErrPassphraseRequired) {
			t.Fatalf("err = %v, want ErrPassphraseRequired", err)
		}
	})

	t.Run("wrong", func(t *testing.T) {
		_, err := gpg.NewDecrypter(key.Private, key.Email, []byte("wrong"))
		if !errors.Is(err, gpg.ErrWrongPassphrase) {
			t.Fatalf("err = %v, want ErrWrongPassphrase", err)
		}
	})

	t.Run("correct", func(t *testing.T) {
		d, err := gpg.NewDecrypter(key.Private, key.Email, []byte("hunter2"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.Decrypt(msg)
		if err != nil || string(got) != "behind a passphrase" {
			t.Fatalf("Decrypt = %q, %v", got, err)
		}
	})

	t.Run("unneeded passphrase is ignored", func(t *testing.T) {
		open := testutil.NewPGPKey(t, "open@example.com")
		if _, err := gpg.NewDecrypter(open.Private, open.Email, []byte("unused")); err != nil {
			t.Fatalf("passphrase for an unprotected key should be ignored: %v", err)
		}
	})
}

func TestDecryptRejectsBadMessages(t *testing.T) {
	key := testutil.NewPGPKey(t, "me@example.com")
	other := testutil.NewPGPKey(t, "someone@example.com")
	d := mustDecrypter(t, key, key.Email)

	t.Run("encrypted to another key", func(t *testing.T) {
		_, err := d.Decrypt(testutil.Encrypt(t, "x", other))
		if !errors.Is(err, gpg.ErrNotRecipient) {
			t.Fatalf("err = %v, want ErrNotRecipient", err)
		}
		if !strings.Contains(err.Error(), key.Fingerprint) {
			t.Errorf("error %q should name the key that was tried", err)
		}
	})

	t.Run("not openpgp", func(t *testing.T) {
		if _, err := d.Decrypt([]byte("just some text")); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, err := d.Decrypt(nil); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		msg := testutil.Encrypt(t, strings.Repeat("some secret data ", 100), key)
		if _, err := d.Decrypt(msg[:len(msg)/2]); err == nil {
			t.Fatal("expected an error for a truncated message")
		}
	})

	t.Run("tampered", func(t *testing.T) {
		msg := testutil.Encrypt(t, strings.Repeat("some secret data ", 100), key)
		// The encrypted payload follows the key packet, flip a bit in the middle of it.
		msg[len(msg)*3/4] ^= 0x01
		if _, err := d.Decrypt(msg); err == nil {
			t.Fatal("expected an error for a modified message")
		}
	})

	t.Run("not encrypted", func(t *testing.T) {
		var buf bytes.Buffer
		w, err := packet.SerializeLiteral(nopWriteCloser{&buf}, false, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("plain text"))
		_ = w.Close()

		if _, err := d.Decrypt(buf.Bytes()); !errors.Is(err, gpg.ErrNotEncrypted) {
			t.Fatalf("err = %v, want ErrNotEncrypted", err)
		}
	})

	t.Run("armor that is not a message", func(t *testing.T) {
		if _, err := d.Decrypt([]byte("-----BEGIN PGP MESSAGE-----\n\n!!!\n-----END PGP MESSAGE-----\n")); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestDecryptSizeLimit(t *testing.T) {
	key := testutil.NewPGPKey(t, "big@example.com")
	d := mustDecrypter(t, key, key.Email)

	t.Run("at the limit", func(t *testing.T) {
		msg := testutil.Encrypt(t, strings.Repeat("a", gpg.MaxPlaintextSize), key)
		got, err := d.Decrypt(msg)
		if err != nil || len(got) != gpg.MaxPlaintextSize {
			t.Fatalf("len = %d, err = %v", len(got), err)
		}
	})

	t.Run("just over the limit", func(t *testing.T) {
		msg := testutil.Encrypt(t, strings.Repeat("a", gpg.MaxPlaintextSize+1), key)
		if _, err := d.Decrypt(msg); !errors.Is(err, gpg.ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})

	t.Run("decompression bomb", func(t *testing.T) {
		// 64 MiB of zeros compresses to a few tens of KiB.
		msg := testutil.Encrypt(t, strings.Repeat("\x00", 64<<20), key)
		if len(msg) > 1<<20 {
			t.Fatalf("test setup: message is %d bytes, expected it to compress well", len(msg))
		}
		if _, err := d.Decrypt(msg); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestDecryptConcurrently(t *testing.T) {
	key := testutil.NewPGPKey(t, "conc@example.com")
	d := mustDecrypter(t, key, key.Email)
	msg := testutil.Encrypt(t, "same", key)

	errs := make(chan error, 8)
	for range 8 {
		go func() {
			got, err := d.Decrypt(msg)
			if err == nil && string(got) != "same" {
				err = errors.New("wrong plaintext")
			}
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

// An entity with an expired key must still decrypt: GnuPG does not apply expiry to decryption,
// so a store keeps working when its key is not extended on time.
func TestDecryptWithExpiredKey(t *testing.T) {
	past := func() (now func() time.Time) {
		start := time.Now().Add(-72 * time.Hour)
		return func() time.Time { return start }
	}()
	config := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Curve:           packet.Curve25519,
		KeyLifetimeSecs: 3600,
		Time:            past,
	}
	entity, err := openpgp.NewEntity("Expired", "", "expired@example.com", config)
	if err != nil {
		t.Fatal(err)
	}

	var msg bytes.Buffer
	w, err := openpgp.Encrypt(&msg, openpgp.EntityList{entity}, nil, nil, &packet.Config{Time: past})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("old secret"))
	_ = w.Close()

	var private bytes.Buffer
	if err := entity.SerializePrivateWithoutSigning(&private, nil); err != nil {
		t.Fatal(err)
	}

	d, err := gpg.NewDecrypter(private.Bytes(), "expired@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.Decrypt(msg.Bytes())
	if err != nil || string(got) != "old secret" {
		t.Fatalf("Decrypt with an expired key = %q, %v", got, err)
	}
}

func TestDecryptRecipientLimit(t *testing.T) {
	mine := testutil.NewPGPKey(t, "mine@example.com")
	d := mustDecrypter(t, mine, mine.Email)

	others := make([]*testutil.PGPKey, gpg.MaxRecipients)
	for i := range others {
		others[i] = testutil.NewPGPKey(t, fmt.Sprintf("other%d@example.com", i))
	}

	t.Run("an entry for as many keys as are allowed", func(t *testing.T) {
		keys := append([]*testutil.PGPKey{mine}, others[:gpg.MaxRecipients-1]...)
		got, err := d.Decrypt(testutil.Encrypt(t, "shared", keys...))
		if err != nil || string(got) != "shared" {
			t.Fatalf("Decrypt = %q, %v", got, err)
		}
	})

	over := func(position int) []*testutil.PGPKey {
		// The key of the decrypter is among the recipients, wherever the others put it.
		keys := append([]*testutil.PGPKey{}, others...)
		return slices.Insert(keys, position, mine)
	}
	for name, msg := range map[string][]byte{
		"one more, mine first":   testutil.Encrypt(t, "x", over(0)...),
		"one more, mine last":    testutil.Encrypt(t, "x", over(len(others))...),
		"one more, armored":      testutil.EncryptArmored(t, "x", over(5)...),
		"far too many, no key":   testutil.Encrypt(t, "x", append(others, testutil.NewPGPKey(t, "late@example.com"))...),
		"far too many, in armor": testutil.EncryptArmored(t, "x", append(others, testutil.NewPGPKey(t, "later@example.com"))...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := d.Decrypt(msg)
			if !errors.Is(err, gpg.ErrTooManyRecipients) {
				t.Fatalf("err = %v, want ErrTooManyRecipients", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(gpg.MaxRecipients)) {
				t.Errorf("the message does not say what the limit is: %v", err)
			}
		})
	}

	t.Run("what is not a message is not refused for this", func(t *testing.T) {
		if _, err := d.Decrypt([]byte("just some text")); errors.Is(err, gpg.ErrTooManyRecipients) {
			t.Errorf("err = %v", err)
		}
	})
}
