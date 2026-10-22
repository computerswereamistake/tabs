// Package auth holds the credential primitives: password hashing, TOTP,
// recovery codes, random tokens and login throttling. It has no HTTP or
// storage dependencies.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. 64 MiB per hash, so hashes are also limited in how
// many run at once (see hashSlots).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// Password length limits, in characters. The upper bound keeps hashing cost
// predictable; argon2 itself doesn't care.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// hashSlots bounds concurrent argon2 runs, so a burst of logins can't
// allocate unbounded memory (4 x 64 MiB at most). Callers wait up to
// hashWait for a slot and otherwise get ErrBusy.
var (
	hashSlots = make(chan struct{}, 4)
	hashWait  = 5 * time.Second
)

// ErrBusy means every hashing slot stayed taken; the caller should answer
// 503 rather than queue without bound.
var ErrBusy = errors.New("too many password checks in progress")

func argonKey(password string, salt []byte, t, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	timer := time.NewTimer(hashWait)
	defer timer.Stop()
	select {
	case hashSlots <- struct{}{}:
	case <-timer.C:
		return nil, ErrBusy
	}
	defer func() { <-hashSlots }()
	return argon2.IDKey([]byte(password), salt, t, memory, threads, keyLen), nil
}

// ErrPasswordPolicy wraps every CheckPassword failure.
var ErrPasswordPolicy = errors.New("password policy")

// CheckPassword enforces the password policy.
func CheckPassword(password, username string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case !utf8.ValidString(password):
		return fmt.Errorf("%w: password is not valid text", ErrPasswordPolicy)
	case n < MinPasswordLen:
		return fmt.Errorf("%w: password must be at least %d characters", ErrPasswordPolicy, MinPasswordLen)
	case n > MaxPasswordLen:
		return fmt.Errorf("%w: password must be at most %d characters", ErrPasswordPolicy, MaxPasswordLen)
	case strings.EqualFold(password, username):
		return fmt.Errorf("%w: password must not be the username", ErrPasswordPolicy)
	}
	return nil
}

// HashPassword returns an argon2id hash in PHC string format.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := argonKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	if err != nil {
		return "", err
	}
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// dummyHash is verified against when the user doesn't exist, so a login
// for an unknown name costs the same as one with a wrong password.
// It uses the same parameters as real hashes.
var dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// VerifyPassword reports whether password matches hash. An empty hash (no
// such user, or a disabled one) is checked against a dummy hash so timing
// doesn't reveal which, and always fails. The only error is ErrBusy.
func VerifyPassword(hash, password string) (bool, error) {
	if hash == "" {
		_, err := verify(dummyHash, password)
		return false, err
	}
	return verify(hash, password)
}

type argonParams struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

// parseHash reads a PHC argon2id string. It refuses parameters far outside
// what HashPassword writes, so a tampered record can't make one login
// allocate gigabytes.
func parseHash(hash string) (argonParams, bool) {
	var p argonParams
	parts := strings.Split(hash, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return p, false
	}
	if p.memory == 0 || p.memory > 4*argonMemory || p.time == 0 || p.time > 4*argonTime || p.threads == 0 {
		return p, false
	}
	b64 := base64.RawStdEncoding
	var err error
	if p.salt, err = b64.DecodeString(parts[4]); err != nil {
		return p, false
	}
	if p.key, err = b64.DecodeString(parts[5]); err != nil || len(p.key) == 0 || len(p.key) > 64 {
		return p, false
	}
	return p, true
}

// verify checks password against hash. A malformed hash is a failed match.
func verify(hash, password string) (bool, error) {
	p, ok := parseHash(hash)
	if !ok {
		return false, nil
	}
	got, err := argonKey(password, p.salt, p.time, p.memory, p.threads, uint32(len(p.key))) // #nosec G115 -- len(key) <= 64
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, p.key) == 1, nil
}
