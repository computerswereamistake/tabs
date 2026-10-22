package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "tabs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustUser(t *testing.T, s *Store, name string, admin bool, groups ...string) User {
	t.Helper()
	u := &User{Username: name, Name: name, PasswordHash: "h", Admin: admin, Groups: groups}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return *u
}

var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestOpenLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tabs.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("second Open of a held file succeeded")
	}
}

func TestUsers(t *testing.T) {
	s := open(t)
	if err := s.CreateGroup(Group{Name: "users"}); err != nil {
		t.Fatal(err)
	}
	a := mustUser(t, s, "alice", true, "users")
	if a.ID == 0 || a.AuthEpoch != 1 {
		t.Fatalf("user = %+v", a)
	}
	if err := s.CreateUser(&User{Username: "alice"}); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("duplicate: %v", err)
	}
	if err := s.CreateUser(&User{Username: "Bob"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("non-canonical username: %v", err)
	}
	if err := s.CreateUser(&User{Username: "bob", Groups: []string{"nope"}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown group: %v", err)
	}
	got, err := s.UserByName("ALICE")
	if err != nil || got.ID != a.ID {
		t.Fatalf("UserByName: %v %+v", err, got)
	}
	if _, err := s.UserByName("nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user: %v", err)
	}
}

func TestEpochAndSessionRevocation(t *testing.T) {
	s := open(t)
	_ = s.CreateGroup(Group{Name: "users"})
	a := mustUser(t, s, "alice", true)
	mustUser(t, s, "root", true)
	sess := Session{ID: "s1", Hash: "h1", UserID: a.ID, State: StateFull, AuthEpoch: a.AuthEpoch, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGate(Gate{Hash: "g1", SessionID: "s1", Host: "tabs.example.com"}); err != nil {
		t.Fatal(err)
	}

	// Group and name changes leave sessions alone (requests read the live user).
	if _, err := s.UpdateUser(a.ID, func(u *User) error { u.Groups = []string{"users"}; u.Name = "Al"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.GateSession("g1", now, time.Hour); err != nil {
		t.Fatalf("gate lost after group change: %v", err)
	}

	// Using up a recovery code isn't a credential change; issuing codes is.
	if _, err := s.UpdateUser(a.ID, func(u *User) error { u.RecoveryHashes = []string{"x", "y"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionByToken("h1", now, time.Hour); err == nil {
		t.Fatal("session survived new recovery codes")
	}
	if _, _, _, err := s.GateSession("g1", now, time.Hour); err == nil {
		t.Fatal("gate survived its session")
	}
	u, _ := s.UserByID(a.ID)
	sess.ID, sess.Hash, sess.AuthEpoch = "s2", "h2", u.AuthEpoch
	_ = s.CreateSession(sess)
	if _, err := s.UpdateUser(a.ID, func(u *User) error { u.RecoveryHashes = []string{"y"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionByToken("h2", now, time.Hour); err != nil {
		t.Fatalf("using a recovery code ended the session: %v", err)
	}
	for _, change := range []func(*User){
		func(u *User) { u.PasswordHash = "new" },
		func(u *User) { u.TOTPSecret = "v1:x" },
		func(u *User) { u.Admin = false },
		func(u *User) { u.Disabled = true },
	} {
		u, _ := s.UserByID(a.ID)
		sess.AuthEpoch = u.AuthEpoch
		_ = s.CreateSession(sess)
		if _, err := s.UpdateUser(a.ID, func(u *User) error { change(u); return nil }); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.SessionByToken("h2", now, time.Hour); err == nil {
			t.Error("session survived a credential change")
		}
	}
}

func TestLastAdmin(t *testing.T) {
	s := open(t)
	a := mustUser(t, s, "alice", true)
	if _, err := s.UpdateUser(a.ID, func(u *User) error { u.Admin = false; return nil }); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote last admin: %v", err)
	}
	if _, err := s.UpdateUser(a.ID, func(u *User) error { u.Disabled = true; return nil }); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disable last admin: %v", err)
	}
	if err := s.DeleteUser(a.ID); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete last admin: %v", err)
	}
	b := mustUser(t, s, "bob", true)
	// Two admins demoting each other concurrently must leave one.
	var wg sync.WaitGroup
	for _, id := range []uint64{a.ID, b.ID} {
		wg.Go(func() { _, _ = s.UpdateUser(id, func(u *User) error { u.Admin = false; return nil }) })
	}
	wg.Wait()
	users, _ := s.Users()
	admins := 0
	for _, u := range users {
		if u.Admin {
			admins++
		}
	}
	if admins != 1 {
		t.Errorf("%d admins left, want 1", admins)
	}
}

func TestFirstAdmin(t *testing.T) {
	s := open(t)
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for i := range 5 {
		wg.Go(func() {
			errs <- s.CreateFirstAdmin(&User{Username: "admin" + string(rune('a'+i)), PasswordHash: "h"})
		})
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		if err == nil {
			ok++
		}
	}
	if n, _ := s.UserCount(); ok != 1 || n != 1 {
		t.Fatalf("%d setups succeeded, %d users", ok, n)
	}
}

func TestInvites(t *testing.T) {
	s := open(t)
	_ = s.CreateGroup(Group{Name: "users"})
	inv := Invite{Hash: "i1", Groups: []string{"users"}, ExpiresAt: now.Add(time.Hour), MaxUses: 2, CreatedAt: now}
	if err := s.CreateInvite(inv); err != nil {
		t.Fatal(err)
	}
	// A name clash fails without using up the invite.
	mustUser(t, s, "taken", false)
	if err := s.RedeemInvite("i1", now, &User{Username: "taken"}); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("clash: %v", err)
	}
	if got, _ := s.Invite("i1"); got.Uses != 0 {
		t.Fatal("clash used up the invite")
	}
	// Concurrent redemptions never exceed MaxUses.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range 10 {
		wg.Go(func() {
			u := &User{Username: "user" + string(rune('a'+i)), PasswordHash: "h", Admin: true}
			if s.RedeemInvite("i1", now, u) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
				if u.Admin || len(u.Groups) != 1 {
					t.Errorf("redeemed user = %+v", u)
				}
			}
		})
	}
	wg.Wait()
	if ok != 2 {
		t.Fatalf("%d redemptions, want 2", ok)
	}
	if _, err := s.Invite("i1"); !errors.Is(err, ErrNotFound) {
		t.Error("used-up invite not deleted")
	}

	_ = s.CreateInvite(Invite{Hash: "i2", ExpiresAt: now, MaxUses: 1})
	if err := s.RedeemInvite("i2", now, &User{Username: "late"}); !errors.Is(err, ErrInviteUsed) {
		t.Errorf("expired invite: %v", err)
	}
}

func TestDeleteGroupScrubs(t *testing.T) {
	s := open(t)
	_ = s.CreateGroup(Group{Name: "media"})
	u := mustUser(t, s, "alice", false, "media")
	_ = s.CreateInvite(Invite{Hash: "i", Groups: []string{"media"}, ExpiresAt: now.Add(time.Hour), MaxUses: 1})
	if err := s.DeleteGroup("media"); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateGroup(Group{Name: "media"})
	got, _ := s.UserByID(u.ID)
	inv, _ := s.Invite("i")
	if len(got.Groups) != 0 || len(inv.Groups) != 0 {
		t.Errorf("recreated group re-granted: user %v invite %v", got.Groups, inv.Groups)
	}
}

func TestResets(t *testing.T) {
	s := open(t)
	u := mustUser(t, s, "alice", false)
	_, _ = s.UpdateUser(u.ID, func(x *User) error { x.TOTPSecret = "v1:s"; x.MustChangePassword = true; return nil })
	u, _ = s.UserByID(u.ID)
	_ = s.CreateSession(Session{ID: "s", Hash: "h", UserID: u.ID, AuthEpoch: u.AuthEpoch, LastSeen: now, ExpiresAt: now.Add(time.Hour)})
	_ = s.CreateReset(Reset{Hash: "r1", UserID: u.ID, ExpiresAt: now.Add(time.Hour)})
	_ = s.CreateReset(Reset{Hash: "r2", UserID: u.ID, ExpiresAt: now.Add(time.Hour)})
	if _, err := s.Reset("r1", now); !errors.Is(err, ErrNotFound) {
		t.Error("older reset link still valid after a new one")
	}
	got, err := s.RedeemReset("r2", now, "newhash")
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "newhash" || got.MustChangePassword || got.TOTPSecret != "v1:s" {
		t.Errorf("after reset: %+v", got)
	}
	if _, err := s.RedeemReset("r2", now, "again"); err == nil {
		t.Error("reset link worked twice")
	}
	if _, _, err := s.SessionByToken("h", now, time.Hour); err == nil {
		t.Error("session survived reset")
	}
	_ = s.CreateReset(Reset{Hash: "r3", UserID: u.ID, ExpiresAt: now})
	if _, err := s.RedeemReset("r3", now, "x"); err == nil {
		t.Error("expired reset worked")
	}
}

func TestSessionsAndGates(t *testing.T) {
	s := open(t)
	u := mustUser(t, s, "alice", false)
	sess := Session{ID: "s", Hash: "h", UserID: u.ID, AuthEpoch: u.AuthEpoch, State: StateTOTPPending, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(24 * time.Hour)}
	_ = s.CreateSession(sess)
	if _, _, err := s.SessionByToken("h", now.Add(2*time.Hour), time.Hour); err == nil {
		t.Error("idle session accepted")
	}
	if _, _, err := s.SessionByToken("h", now.Add(25*time.Hour), 48*time.Hour); err == nil {
		t.Error("expired session accepted")
	}
	if err := s.RotateSession("s", "h2", func(x *Session) { x.State = StateFull }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionByToken("h", now, time.Hour); err == nil {
		t.Error("old token works after rotation")
	}
	got, _, err := s.SessionByToken("h2", now, time.Hour)
	if err != nil || got.State != StateFull || got.ID != "s" {
		t.Fatalf("rotated session: %v %+v", err, got)
	}

	if err := s.CreateCode(Code{Hash: "c", SessionID: "s", Host: "app.example.com", ExpiresAt: now.Add(time.Minute)}, now, 2); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateCode(Code{Hash: "c2", SessionID: "s", ExpiresAt: now.Add(time.Minute)}, now, 2)
	if err := s.CreateCode(Code{Hash: "c3", SessionID: "s", ExpiresAt: now.Add(time.Minute)}, now, 2); !errors.Is(err, ErrTooMany) {
		t.Errorf("code cap: %v", err)
	}
	if c, err := s.ConsumeCode("c", now); err != nil || c.Host != "app.example.com" {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if _, err := s.ConsumeCode("c", now); err == nil {
		t.Error("code worked twice")
	}
	if _, err := s.ConsumeCode("c2", now.Add(time.Minute)); err == nil {
		t.Error("expired code worked")
	}

	_ = s.CreateGate(Gate{Hash: "g", SessionID: "s", Host: "app.example.com"})
	if g, sess, _, err := s.GateSession("g", now, time.Hour); err != nil || g.Host != "app.example.com" || sess.ID != "s" {
		t.Fatalf("GateSession: %v", err)
	}
	if err := s.CreateGate(Gate{Hash: "g2", SessionID: "nope"}); err == nil {
		t.Error("gate for missing session created")
	}
	if err := s.DeleteSession("s"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.GateSession("g", now, time.Hour); err == nil {
		t.Error("gate outlived logout")
	}
}

func TestPrune(t *testing.T) {
	s := open(t)
	u := mustUser(t, s, "alice", false)
	_ = s.CreateSession(Session{ID: "old", Hash: "h", UserID: u.ID, LastSeen: now, ExpiresAt: now.Add(time.Minute)})
	_ = s.CreateGate(Gate{Hash: "g", SessionID: "old"})
	_ = s.CreateInvite(Invite{Hash: "i", ExpiresAt: now.Add(time.Minute), MaxUses: 1})
	if err := s.Prune(now.Add(time.Hour), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if ss, _ := s.UserSessions(u.ID); len(ss) != 0 {
		t.Error("expired session kept")
	}
	if invs, _ := s.Invites(); len(invs) != 0 {
		t.Error("expired invite kept")
	}
}

func TestValidation(t *testing.T) {
	for in, ok := range map[string]bool{"alice": true, " Alice ": true, "a.b_c-d": true, "-x": false, "a b": false, "a,b": false, "": false} {
		if _, err := NormalizeUsername(in); (err == nil) != ok {
			t.Errorf("NormalizeUsername(%q) = %v", in, err)
		}
	}
	for in, ok := range map[string]bool{"": true, "a@example.com": true, "a@b@c": false, "a@example.com\r\nX: y": false, "a,b@example.com": false, "x@": false, "\u212a@example.com": false, "o'brien+x@example.com": true, "a b@example.com": false} {
		if _, err := CleanEmail(in); (err == nil) != ok {
			t.Errorf("CleanEmail(%q) = %v", in, err)
		}
	}
	if _, err := CleanName("bad\nname"); err == nil {
		t.Error("CleanName accepted a newline")
	}
	s := open(t)
	if err := s.CreateGroup(Group{Name: "Bad Name"}); err == nil {
		t.Error("bad group name accepted")
	}
}

func TestEmailUnique(t *testing.T) {
	s := open(t)
	a := &User{Username: "alice", Email: "a@example.com"}
	if err := s.CreateUser(a); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&User{Username: "bob", Email: "A@example.com"}); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("duplicate email on create: %v", err)
	}
	b := &User{Username: "bob"}
	_ = s.CreateUser(b)
	if _, err := s.UpdateUser(b.ID, func(u *User) error { u.Email = "a@example.com"; return nil }); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("duplicate email on update: %v", err)
	}
	if _, err := s.UpdateUser(a.ID, func(u *User) error { u.Email = "A@EXAMPLE.COM"; return nil }); err != nil {
		t.Errorf("changing the case of your own email: %v", err)
	}
}

func TestPasswordChangeVoidsResets(t *testing.T) {
	s := open(t)
	u := mustUser(t, s, "alice", false)
	_ = s.CreateReset(Reset{Hash: "r", UserID: u.ID, ExpiresAt: now.Add(time.Hour)})
	if _, err := s.UpdateUser(u.ID, func(x *User) error { x.Name = "Al"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reset("r", now); err != nil {
		t.Fatal("a name change voided the reset link")
	}
	if _, err := s.UpdateUser(u.ID, func(x *User) error { x.PasswordHash = "new"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemReset("r", now, "attacker"); err == nil {
		t.Error("reset link still works after a password change")
	}
}
