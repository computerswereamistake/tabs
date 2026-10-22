package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// SecretBox encrypts values at rest (TOTP secrets) with AES-256-GCM. Each
// value is bound to an ID (the user's) so a ciphertext copied onto another
// record doesn't decrypt.
type SecretBox struct {
	aead cipher.AEAD
}

const sealedPrefix = "v1:"

// ParseKey reads a 32-byte key written as hex (64 chars) or base64.
// Surrounding whitespace is ignored, so a key file may end in a newline.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("key must be 32 bytes, written as 64 hex characters or base64")
}

// NewKey returns a fresh key as hex, for `tabs genkey`.
func NewKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewSecretBox returns a SecretBox for a 32-byte key.
func NewSecretBox(key []byte) (*SecretBox, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: aead}, nil
}

func aad(id uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, id)
	return b
}

// Seal encrypts plaintext for record id.
func (b *SecretBox) Seal(id uint64, plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), aad(id))
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// Open decrypts a value from Seal for record id.
func (b *SecretBox) Open(id uint64, sealed string) (string, error) {
	rest, ok := strings.CutPrefix(sealed, sealedPrefix)
	if !ok {
		return "", errors.New("not a sealed value")
	}
	raw, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil || len(raw) < b.aead.NonceSize() {
		return "", errors.New("sealed value is corrupt")
	}
	n := b.aead.NonceSize()
	pt, err := b.aead.Open(nil, raw[:n], raw[n:], aad(id))
	if err != nil {
		return "", errors.New("sealed value does not decrypt with this key")
	}
	return string(pt), nil
}
