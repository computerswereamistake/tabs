package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238 defaults, which every authenticator app supports).
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // steps either side of now that are accepted
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret, base32-encoded.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPURI returns the otpauth:// URI authenticator apps scan from a QR code.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpCode computes the code for a time step (RFC 4226 dynamic truncation).
func totpCode(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- steps are positive
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

// VerifyTOTP checks code against secret at now. lastStep is the step of the
// last code accepted for this secret; a code from that step or earlier is a
// replay and is refused. On success it returns the accepted step, which the
// caller must store as the new lastStep.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil || len(key) == 0 {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	var matched int64
	ok := false
	// Check every candidate step without stopping early, so timing doesn't
	// reveal which step matched.
	for s := cur - totpSkew; s <= cur+totpSkew; s++ {
		if hmac.Equal([]byte(totpCode(key, s)), []byte(code)) && s > lastStep {
			matched, ok = s, true
		}
	}
	return matched, ok
}

// TOTPCodeAt returns the code for secret at t. It is for tests and for
// tooling that drives the login flow; the server only ever verifies.
func TOTPCodeAt(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	return totpCode(key, t.Unix()/totpPeriod), nil
}
