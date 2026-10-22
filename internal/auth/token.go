package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// NewToken returns a random 256-bit token, URL-safe base64 without padding.
// Used for session cookies, CSRF tokens, invite, reset and setup links.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is how tokens are stored and looked up: a stolen database holds
// no usable cookie or link. Tokens are high-entropy, so a plain hash is enough.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokensEqual compares two tokens in constant time.
func TokensEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// recoveryAlphabet avoids look-alike characters (0/O, 1/I/L).
const recoveryAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// RecoveryCodeCount is how many recovery codes are issued at a time.
const RecoveryCodeCount = 10

// NewRecoveryCodes returns fresh codes (shown once) and their hashes (stored).
// Each code is 10 characters from a 31-symbol alphabet, about 50 bits.
func NewRecoveryCodes() (codes, hashes []string, err error) {
	for range RecoveryCodeCount {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		var sb strings.Builder
		for i, c := range b {
			if i == 5 {
				sb.WriteByte('-')
			}
			// 256 % 31 != 0, so this is very slightly biased; at ~50 bits
			// per code it doesn't matter.
			sb.WriteByte(recoveryAlphabet[int(c)%len(recoveryAlphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
		hashes = append(hashes, HashToken(NormalizeRecoveryCode(code)))
	}
	return codes, hashes, nil
}

// NormalizeRecoveryCode makes entry forgiving: case, spaces and dashes
// don't matter.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(code)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, code)
}

// MatchRecoveryCode returns the index in hashes that code matches, or -1.
func MatchRecoveryCode(hashes []string, code string) int {
	h := HashToken(NormalizeRecoveryCode(code))
	found := -1
	for i, want := range hashes {
		if TokensEqual(h, want) {
			found = i
		}
	}
	return found
}
