package auth

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); !ok || err != nil {
		t.Errorf("right password rejected: %v", err)
	}
	if ok, _ := VerifyPassword(h, "correct horse batterY"); ok {
		t.Error("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("two hashes of the same password are equal; salt not random")
	}
}

func TestVerifyPasswordRejectsBadHashes(t *testing.T) {
	for _, h := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$a2V5",
		"$argon2id$v=18$m=65536,t=3,p=2$c2FsdA$a2V5",
		"$argon2id$v=19$m=99999999,t=3,p=2$c2FsdA$a2V5", // memory bomb
		"$argon2id$v=19$m=65536,t=3,p=0$c2FsdA$a2V5",
		"$argon2id$v=19$m=65536,t=3,p=2$!!$a2V5",
		"$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$",
	} {
		if ok, _ := VerifyPassword(h, "x"); ok {
			t.Errorf("VerifyPassword(%q) = true", h)
		}
	}
}

func TestDummyHashParses(t *testing.T) {
	// The dummy must cost a full hash: a parse failure would return early
	// and make unknown usernames measurably faster.
	parts := strings.Split(dummyHash, "$")
	if len(parts) != 6 {
		t.Fatal("dummy hash malformed")
	}
	start := time.Now()
	if ok, err := VerifyPassword("", "x"); ok || err != nil {
		t.Fatalf("empty hash: ok=%v err=%v", ok, err)
	}
	h, _ := HashPassword("y")
	startReal := time.Now()
	_, _ = VerifyPassword(h, "x")
	if dummy, real := startReal.Sub(start), time.Since(startReal); dummy < real/3 {
		t.Errorf("dummy verify took %v, real %v", dummy, real)
	}
}

func TestBusy(t *testing.T) {
	old := hashWait
	hashWait = 10 * time.Millisecond
	defer func() { hashWait = old }()
	for range cap(hashSlots) {
		hashSlots <- struct{}{}
	}
	defer func() {
		for range cap(hashSlots) {
			<-hashSlots
		}
	}()
	if _, err := HashPassword("whatever whatever"); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
}

func TestCheckPassword(t *testing.T) {
	tests := []struct {
		pw, user string
		ok       bool
	}{
		{"short", "bob", false},
		{"twelve chars", "bob", true},
		{strings.Repeat("x", 257), "bob", false},
		{"AliceAliceAlice", "alicealicealice", false},
		{"\xff\xfe invalid utf8 here", "bob", false},
		{"ünïcödé-länger", "bob", true},
	}
	for _, tt := range tests {
		err := CheckPassword(tt.pw, tt.user)
		if (err == nil) != tt.ok {
			t.Errorf("CheckPassword(%q, %q) = %v, want ok=%v", tt.pw, tt.user, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrPasswordPolicy) {
			t.Errorf("error %v doesn't wrap ErrPasswordPolicy", err)
		}
	}
}

// RFC 6238 appendix B, SHA1, truncated to the last 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	vectors := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1111111111: "050471",
		1234567890: "005924",
		2000000000: "279037",
	}
	for ts, want := range vectors {
		got, err := TOTPCodeAt(secret, time.Unix(ts, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("code at %d = %s, want %s", ts, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	cur := now.Unix() / 30
	code := func(d time.Duration) string {
		c, _ := TOTPCodeAt(secret, now.Add(d))
		return c
	}

	if step, ok := VerifyTOTP(secret, code(0), now, 0); !ok || step != cur {
		t.Fatalf("current code: ok=%v step=%d want %d", ok, step, cur)
	}
	if _, ok := VerifyTOTP(secret, code(-30*time.Second), now, 0); !ok {
		t.Error("previous step rejected")
	}
	if _, ok := VerifyTOTP(secret, code(30*time.Second), now, 0); !ok {
		t.Error("next step rejected")
	}
	if _, ok := VerifyTOTP(secret, code(-90*time.Second), now, 0); ok {
		t.Error("code three steps old accepted")
	}
	if _, ok := VerifyTOTP(secret, code(0), now, cur); ok {
		t.Error("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, code(-30*time.Second), now, cur); ok {
		t.Error("code older than the last accepted step accepted")
	}
	c := code(0)
	if _, ok := VerifyTOTP(secret, c[:3]+" "+c[3:], now, 0); !ok {
		t.Error("code with a space rejected")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("code %q accepted", bad)
		}
	}
	if _, ok := VerifyTOTP("not base32!", "123456", now, 0); ok {
		t.Error("bad secret accepted")
	}
}

func TestTOTPURI(t *testing.T) {
	u := TOTPURI("My Tabs", "bob", "ABC")
	if !strings.HasPrefix(u, "otpauth://totp/My%20Tabs:bob?") || !strings.Contains(u, "secret=ABC") {
		t.Errorf("TOTPURI = %q", u)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("got %d codes, %d hashes", len(codes), len(hashes))
	}
	if i := MatchRecoveryCode(hashes, strings.ToLower(strings.ReplaceAll(codes[3], "-", " "))); i != 3 {
		t.Errorf("match = %d, want 3", i)
	}
	if i := MatchRecoveryCode(hashes, "XXXXX-XXXXX"); i != -1 {
		t.Errorf("bogus code matched %d", i)
	}
}

func TestTokens(t *testing.T) {
	a, _ := NewToken()
	b, _ := NewToken()
	if a == b || len(a) != 43 {
		t.Fatalf("tokens %q %q", a, b)
	}
	if HashToken(a) == a || len(HashToken(a)) != 64 {
		t.Error("HashToken")
	}
	if !TokensEqual(a, a) || TokensEqual(a, b) {
		t.Error("TokensEqual")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := &Limiter{Free: 2, Base: time.Second, Max: 8 * time.Second, Now: func() time.Time { return now }}
	for range 2 {
		l.Fail("bob")
	}
	if ok, _ := l.Allow("bob"); !ok {
		t.Fatal("blocked within free attempts")
	}
	l.Fail("bob") // 3rd: 1s
	if ok, wait := l.Allow("bob"); ok || wait != time.Second {
		t.Fatalf("after 3 failures: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Allow("alice"); !ok {
		t.Error("other key blocked")
	}
	for range 5 {
		l.Fail("bob")
	}
	if _, wait := l.Allow("bob"); wait != 8*time.Second {
		t.Errorf("delay not capped: %v", wait)
	}
	now = now.Add(9 * time.Second)
	if ok, _ := l.Allow("bob"); !ok {
		t.Error("still blocked after delay")
	}
	l.Succeed("bob")
	l.Fail("bob")
	if ok, _ := l.Allow("bob"); !ok {
		t.Error("success didn't reset")
	}
	now = now.Add(time.Hour)
	l.Prune()
	if len(l.entries) != 0 {
		t.Errorf("prune left %d entries", len(l.entries))
	}
}

func TestSecretBox(t *testing.T) {
	k, _ := NewKey()
	key, err := ParseKey(k + "\n")
	if err != nil {
		t.Fatal(err)
	}
	box, _ := NewSecretBox(key)
	sealed, err := box.Seal(7, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "JBSWY3DP") {
		t.Fatal("plaintext visible")
	}
	if got, err := box.Open(7, sealed); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := box.Open(8, sealed); err == nil {
		t.Error("opened with another record's id")
	}
	k2, _ := NewKey()
	key2, _ := ParseKey(k2)
	box2, _ := NewSecretBox(key2)
	if _, err := box2.Open(7, sealed); err == nil {
		t.Error("opened with another key")
	}
	for _, bad := range []string{"", "short", strings.Repeat("z", 64)} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) accepted", bad)
		}
	}
}

func TestBanner(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewBanner(3, time.Minute, time.Hour)
	b.Now = func() time.Time { return now }

	b.Fail("1.2.3.4")
	b.Fail("1.2.3.4")
	now = now.Add(2 * time.Minute) // first two fall out of the window
	if b.Fail("1.2.3.4") {
		t.Fatal("banned on failures outside the window")
	}
	b.Fail("1.2.3.4")
	if !b.Fail("1.2.3.4") {
		t.Fatal("not banned after 3 failures in the window")
	}
	if ok, until := b.Banned("1.2.3.4"); !ok || !until.Equal(now.Add(time.Hour)) {
		t.Fatalf("Banned = %v %v", ok, until)
	}
	if ok, _ := b.Banned("5.6.7.8"); ok {
		t.Error("other IP banned")
	}
	if bans := b.Bans(); len(bans) != 1 || bans[0].IP != "1.2.3.4" {
		t.Errorf("Bans = %v", bans)
	}
	b.Unban("1.2.3.4")
	if ok, _ := b.Banned("1.2.3.4"); ok {
		t.Error("still banned after Unban")
	}
	for range 3 {
		b.Fail("9.9.9.9")
	}
	now = now.Add(time.Hour)
	if ok, _ := b.Banned("9.9.9.9"); ok {
		t.Error("ban didn't expire")
	}

	off := NewBanner(0, time.Minute, time.Hour)
	for range 100 {
		if off.Fail("1.1.1.1") {
			t.Fatal("disabled banner banned")
		}
	}
}
