// Package gpg decrypts the entries of a pass(1) password store with OpenPGP.
package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// MaxPlaintextSize bounds the size of a decrypted entry. A Kubernetes Secret cannot hold
// more than 1 MiB anyway, and the bound protects against decompression bombs.
const MaxPlaintextSize = 1 << 20

// maxDecompressedSize bounds the size of the data after decompression, before it is
// compared with MaxPlaintextSize.
const maxDecompressedSize = 2 * MaxPlaintextSize

// MaxRecipients is the number of keys that an entry may be encrypted to. Every copy of the session key
// that is for this key, or for no key in particular, which is how GnuPG hides who an entry is for, has to
// be tried, and trying one costs a private key operation. An entry made to cost seconds could
// otherwise be pushed to the repository of a store.
const MaxRecipients = 32

var (
	// ErrNoPrivateKey means the key material has no private key, for example because only the
	// public key was exported.
	ErrNoPrivateKey = errors.New("key material contains no private key, export it with \"gpg --export-secret-keys\"")
	// ErrKeyNotFound means no private key matches the configured id.
	ErrKeyNotFound = errors.New("no private key matches the configured id")
	// ErrAmbiguousKey means more than one private key matches the configured id.
	ErrAmbiguousKey = errors.New("the configured id matches more than one private key")
	// ErrPassphraseRequired means the private key is protected by a passphrase and none was given.
	ErrPassphraseRequired = errors.New("private key is protected by a passphrase, but none was provided")
	// ErrWrongPassphrase means the passphrase does not unlock the private key.
	ErrWrongPassphrase = errors.New("passphrase does not unlock the private key")
	// ErrNotRecipient means the message is not encrypted to the configured key.
	ErrNotRecipient = errors.New("entry is not encrypted to the configured key")
	// ErrNotEncrypted means the data is not an encrypted OpenPGP message.
	ErrNotEncrypted = errors.New("entry is not an encrypted OpenPGP message")
	// ErrTooLarge means the decrypted entry exceeds MaxPlaintextSize.
	ErrTooLarge = errors.New("decrypted entry is too large")
	// ErrTooManyRecipients means the entry is encrypted to more than MaxRecipients keys.
	ErrTooManyRecipients = errors.New("entry is encrypted to too many keys")
)

// Decrypter decrypts OpenPGP messages with a single unlocked private key. It is safe for
// concurrent use.
type Decrypter struct {
	keyring     openpgp.EntityList
	fingerprint string
	config      *packet.Config
}

// NewDecrypter loads the private key selected by id from keyData and unlocks it with
// passphrase. keyData can be ASCII-armored or binary and can hold several keys. id is a
// fingerprint, a long or short key ID (optionally prefixed with 0x), or part of a user ID such
// as an email address. The passphrase is only needed if the key is protected by one.
func NewDecrypter(keyData []byte, id string, passphrase []byte) (*Decrypter, error) {
	entities, err := readKeyRing(keyData)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	var private openpgp.EntityList
	for _, e := range entities {
		if hasPrivateKeyMaterial(e) {
			private = append(private, e)
		}
	}
	if len(private) == 0 {
		return nil, ErrNoPrivateKey
	}

	var matched openpgp.EntityList
	for _, e := range private {
		if matches(e, id) {
			matched = append(matched, e)
		}
	}
	switch len(matched) {
	case 0:
		return nil, fmt.Errorf("%w %q, the key material contains: %s", ErrKeyNotFound, id, describe(private))
	case 1:
	default:
		return nil, fmt.Errorf("%w %q: %s", ErrAmbiguousKey, id, describe(matched))
	}

	entity := matched[0]
	if err := unlock(entity, passphrase); err != nil {
		return nil, err
	}

	maxDecompressed := int64(maxDecompressedSize)
	return &Decrypter{
		keyring:     openpgp.EntityList{entity},
		fingerprint: fingerprint(entity.PrimaryKey),
		config:      &packet.Config{MaxDecompressedMessageSize: &maxDecompressed},
	}, nil
}

// Fingerprint returns the upper-case hex fingerprint of the selected key.
func (d *Decrypter) Fingerprint() string {
	return d.fingerprint
}

// Decrypt decrypts an OpenPGP message, as found in the .gpg files of a password store. The
// message can be binary, which is what pass writes, or ASCII-armored. Signatures are not
// verified, but the integrity of the message is.
func (d *Decrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	data := ciphertext
	if isArmored(ciphertext) {
		block, err := armor.Decode(bytes.NewReader(ciphertext))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNotEncrypted, err)
		}
		if data, err = io.ReadAll(block.Body); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNotEncrypted, err)
		}
	}
	if err := checkRecipients(data); err != nil {
		return nil, err
	}

	prompt := func([]openpgp.Key, bool) ([]byte, error) {
		return nil, errors.New("private key is locked")
	}
	md, err := openpgp.ReadMessage(bytes.NewReader(data), d.keyring, prompt, d.config)
	if err != nil {
		return nil, d.classify(err)
	}
	if !md.IsEncrypted {
		return nil, ErrNotEncrypted
	}

	// The body must be read to the end: that is where the integrity of the message is checked.
	plaintext, err := io.ReadAll(io.LimitReader(md.UnverifiedBody, MaxPlaintextSize+1))
	if err != nil {
		return nil, d.classify(err)
	}
	if len(plaintext) > MaxPlaintextSize {
		return nil, fmt.Errorf("%w: the limit is %d bytes", ErrTooLarge, MaxPlaintextSize)
	}
	return plaintext, nil
}

// checkRecipients refuses a message that has more than MaxRecipients copies of its session key,
// before one of them is tried. It only reads the start of the message, as far as the packets that
// come before the encrypted data. What it does not understand it leaves to ReadMessage, which
// says what is wrong with it.
func checkRecipients(message []byte) error {
	r := packet.NewReader(bytes.NewReader(message))
	recipients := 0
	for {
		p, err := r.Next()
		if err != nil {
			return nil
		}
		switch p.(type) {
		case *packet.EncryptedKey:
			if recipients++; recipients > MaxRecipients {
				return fmt.Errorf("%w: the limit is %d", ErrTooManyRecipients, MaxRecipients)
			}
		case *packet.SymmetricKeyEncrypted, *packet.Marker:
			// These come before the encrypted data as well, and are not copies for a key.
		default:
			return nil
		}
	}
}

func (d *Decrypter) classify(err error) error {
	switch {
	case errors.Is(err, pgperrors.ErrKeyIncorrect):
		return fmt.Errorf("%w (key %s)", ErrNotRecipient, d.fingerprint)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%w: message is truncated", ErrNotEncrypted)
	default:
		return fmt.Errorf("decrypt: %w", err)
	}
}

func readKeyRing(data []byte) (openpgp.EntityList, error) {
	trimmed := bytes.TrimSpace(data)
	if isArmored(trimmed) {
		return openpgp.ReadArmoredKeyRing(bytes.NewReader(trimmed))
	}
	return openpgp.ReadKeyRing(bytes.NewReader(data))
}

func isArmored(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN PGP"))
}

// hasPrivateKeyMaterial reports whether the entity has at least one key that can decrypt.
// Keys exported with "gpg --export-secret-subkeys" have a stub in place of the primary key.
func hasPrivateKeyMaterial(e *openpgp.Entity) bool {
	if e.PrivateKey != nil && !e.PrivateKey.Dummy() {
		return true
	}
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Dummy() {
			return true
		}
	}
	return false
}

// unlock decrypts all private keys of the entity with the passphrase.
func unlock(e *openpgp.Entity, passphrase []byte) error {
	locked := e.PrivateKey != nil && !e.PrivateKey.Dummy() && e.PrivateKey.Encrypted
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Dummy() && sub.PrivateKey.Encrypted {
			locked = true
		}
	}
	if !locked {
		return nil
	}
	if len(passphrase) == 0 {
		return ErrPassphraseRequired
	}
	if err := e.DecryptPrivateKeys(passphrase); err != nil {
		return fmt.Errorf("%w: %w", ErrWrongPassphrase, err)
	}
	return nil
}

// matches reports whether id selects the entity: by fingerprint or key ID of the primary key
// or one of the subkeys, or as a case-insensitive part of a user ID.
func matches(e *openpgp.Entity, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}

	if want, ok := normalizeKeyID(id); ok {
		keys := []*packet.PublicKey{e.PrimaryKey}
		for _, sub := range e.Subkeys {
			keys = append(keys, sub.PublicKey)
		}
		for _, pk := range keys {
			if want == fingerprint(pk) || want == pk.KeyIdString() || want == pk.KeyIdShortString() {
				return true
			}
		}
	}

	lower := strings.ToLower(id)
	for _, ident := range e.Identities {
		if strings.Contains(strings.ToLower(ident.Name), lower) {
			return true
		}
	}
	return false
}

// normalizeKeyID turns a fingerprint or key ID, written with or without a 0x prefix and
// spaces, into upper-case hex. ok is false if id does not look like one.
func normalizeKeyID(id string) (hexID string, ok bool) {
	s := strings.NewReplacer(" ", "", "\t", "").Replace(id)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	switch len(s) {
	case 8, 16, 32, 40, 64:
	default:
		return "", false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return "", false
		}
	}
	return strings.ToUpper(s), true
}

func fingerprint(pk *packet.PublicKey) string {
	return strings.ToUpper(fmt.Sprintf("%x", pk.Fingerprint))
}

// describe lists the keys of a keyring for error messages. It only contains public information.
func describe(entities openpgp.EntityList) string {
	parts := make([]string, 0, len(entities))
	for _, e := range entities {
		names := make([]string, 0, len(e.Identities))
		for _, ident := range e.Identities {
			names = append(names, ident.Name)
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", fingerprint(e.PrimaryKey), strings.Join(names, ", ")))
	}
	return strings.Join(parts, "; ")
}
