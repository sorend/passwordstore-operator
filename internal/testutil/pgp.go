// Package testutil holds helpers shared by the tests of this module: throwaway PGP keys,
// Git servers and SSH servers. It must only be imported from tests.
package testutil

import (
	"bytes"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// PGPKey is a throwaway OpenPGP key.
type PGPKey struct {
	Entity *openpgp.Entity
	// Email is the email address of the only user ID of the key.
	Email string
	// Fingerprint is the upper-case hex fingerprint of the primary key.
	Fingerprint string
	// Private is the ASCII-armored private key, protected by Passphrase if that is not empty.
	Private []byte
	// Public is the ASCII-armored public key.
	Public []byte
	// Passphrase protects Private. It is empty for unprotected keys.
	Passphrase string
}

// PGPKeyOption customizes NewPGPKey.
type PGPKeyOption func(*pgpKeyConfig)

type pgpKeyConfig struct {
	passphrase string
	rsa        bool
}

// WithPassphrase protects the private key with a passphrase.
func WithPassphrase(passphrase string) PGPKeyOption {
	return func(c *pgpKeyConfig) { c.passphrase = passphrase }
}

// WithRSA generates an RSA key instead of the default Curve25519 key.
func WithRSA() PGPKeyOption {
	return func(c *pgpKeyConfig) { c.rsa = true }
}

// NewPGPKey generates a key with the user ID "Test <email>".
func NewPGPKey(t TB, email string, opts ...PGPKeyOption) *PGPKey {
	t.Helper()

	var cfg pgpKeyConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	// Like keys made by GnuPG, advertise zlib so that messages to this key are compressed.
	zlib := packet.CompressionZLIB
	pgpConfig := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519, DefaultCompressionAlgo: zlib}
	if cfg.rsa {
		pgpConfig = &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048, DefaultCompressionAlgo: zlib}
	}
	entity, err := openpgp.NewEntity("Test", "", email, pgpConfig)
	if err != nil {
		t.Fatalf("generate PGP key: %v", err)
	}

	key := &PGPKey{
		Entity:      entity,
		Email:       email,
		Fingerprint: strings.ToUpper(hexString(entity.PrimaryKey.Fingerprint)),
		Passphrase:  cfg.passphrase,
	}

	var public bytes.Buffer
	w, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor public key: %v", err)
	}
	if err := entity.Serialize(w); err != nil {
		t.Fatalf("serialize public key: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close armor: %v", err)
	}
	key.Public = public.Bytes()

	// The private key is serialized last: protecting it with a passphrase locks the key.
	if cfg.passphrase != "" {
		if err := entity.EncryptPrivateKeys([]byte(cfg.passphrase), nil); err != nil {
			t.Fatalf("protect private key: %v", err)
		}
	}
	var private bytes.Buffer
	w, err = armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor private key: %v", err)
	}
	if err := entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatalf("serialize private key: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close armor: %v", err)
	}
	key.Private = private.Bytes()

	return key
}

// Encrypt encrypts plaintext to the keys, as "pass insert" does, and returns the binary message
// that pass stores in a .gpg file. The data is compressed, like GnuPG does by default.
func Encrypt(t TB, plaintext string, keys ...*PGPKey) []byte {
	t.Helper()

	recipients := make([]*openpgp.Entity, 0, len(keys))
	for _, k := range keys {
		recipients = append(recipients, k.Entity)
	}

	var out bytes.Buffer
	w, err := openpgp.Encrypt(&out, recipients, nil, nil, &packet.Config{
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig:      &packet.CompressionConfig{Level: packet.DefaultCompression},
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return out.Bytes()
}

// EncryptArmored is like Encrypt but returns an ASCII-armored message.
func EncryptArmored(t TB, plaintext string, keys ...*PGPKey) []byte {
	t.Helper()

	var out bytes.Buffer
	w, err := armor.Encode(&out, "PGP MESSAGE", nil)
	if err != nil {
		t.Fatalf("armor message: %v", err)
	}
	if _, err := w.Write(Encrypt(t, plaintext, keys...)); err != nil {
		t.Fatalf("armor message: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor message: %v", err)
	}
	return out.Bytes()
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
