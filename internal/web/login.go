package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
)

const maxTOTPAttempts = 5

type loginData struct {
	Next     string
	Username string
}

// badLogin is the one message for every failed login, so it doesn't say
// whether the username exists, is disabled or is locked.
const badLogin = "Wrong username or password."

// throttled reports whether a login attempt for name from ip must wait,
// writing the response if so (render shows the form again with a message,
// with status 429). When it returns false the caller holds a check slot
// for ip and must call s.release(ip) when done.
//
// Per address, at most maxInFlight checks run at once. Per username there
// is no such hard cap (that would let anyone hold a user's slots and lock
// them out); instead each attempt is counted as a failure before it runs,
// in the same step as the limit check, and a success clears it.
func (s *Server) throttled(w http.ResponseWriter, r *http.Request, name, ip string, render func(msg string)) bool {
	if banned, until := s.opts.Banner.Banned(ip); banned {
		s.audit(r, "banned-attempt", "user", name)
		w.Header().Set("Retry-After", fmt.Sprint(int(time.Until(until).Seconds())+1))
		http.Error(w, "too many failed attempts from your address; try again later", http.StatusTooManyRequests)
		return true
	}
	for _, c := range []struct {
		l   *auth.Limiter
		key string
	}{{s.pairLimit, ip + "|" + name}, {s.ipLimit, ip}} {
		if ok, wait := c.l.Allow(c.key); !ok {
			w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
			render(fmt.Sprintf("Too many attempts. Try again in %s.", wait.Round(time.Second)))
			return true
		}
	}
	if !s.acquire(ip) {
		w.Header().Set("Retry-After", "2")
		render("Too many attempts at once. Try again in a moment.")
		return true
	}
	if ok, wait := s.userLimit.Take(name); !ok {
		s.release(ip)
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		render(fmt.Sprintf("Too many attempts. Try again in %s.", wait.Round(time.Second)))
		return true
	}
	return false
}

// failed records a failed password or code: rate limits, the IP ban and,
// if enabled, the account lock.
func (s *Server) failed(r *http.Request, name, ip string, userID uint64, event string) {
	s.pairLimit.Fail(ip + "|" + name)
	s.ipLimit.Fail(ip) // userLimit counted this already, in throttled
	if s.opts.Banner.Fail(ip) {
		s.audit(r, "ip-banned", "user", name)
	}
	s.audit(r, event, "user", name)
	if userID == 0 || s.opts.LockAfter <= 0 {
		return
	}
	s.lockMu.Lock()
	s.failures[userID]++
	lock := s.failures[userID] >= s.opts.LockAfter
	if lock {
		delete(s.failures, userID)
	}
	s.lockMu.Unlock()
	if lock {
		locked := false
		// Admins are never locked: anyone who knows their usernames could
		// otherwise lock every admin out. They still get the backoff and
		// the address ban.
		if _, err := s.store.UpdateUser(userID, func(u *store.User) error {
			locked = !u.Admin
			u.Locked = u.Locked || locked
			return nil
		}); err != nil {
			s.log.Error("lock account", "err", err)
			return
		}
		if locked {
			s.audit(r, "account-locked", "user", name)
		}
	}
}

func (s *Server) succeeded(name, ip string, userID uint64) {
	s.pairLimit.Succeed(ip + "|" + name)
	s.userLimit.Succeed(name)
	s.lockMu.Lock()
	delete(s.failures, userID)
	s.lockMu.Unlock()
}

func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request, st *state) {
	if !allow(w, r, "GET", "HEAD", "POST") {
		return
	}
	next := authNext(r.FormValue("next"))
	show := func(status int, msg, username string) {
		s.showForm(w, r, nil, "login", "Log in", refuse(status, msg), loginData{Next: next, Username: username})
	}
	if r.Method != http.MethodPost {
		if a := s.loadAuth(r); a != nil {
			if a.state == effFull {
				s.redirectNext(w, r, next)
			} else {
				s.sendToState(w, r, a, next)
			}
			return
		}
		show(http.StatusOK, "", "")
		return
	}
	if !s.checkPost(w, r, nil) {
		return
	}
	next = authNext(r.PostFormValue("next"))
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("username")))
	if len(name) > 64 {
		name = name[:64]
	}
	password := r.PostFormValue("password")
	ip := s.limitKey(r)
	if s.throttled(w, r, name, ip, func(msg string) {
		s.showForm(w, r, nil, "login", "Log in", refuse(http.StatusTooManyRequests, msg), loginData{Next: next, Username: name})
	}) {
		return
	}
	defer s.release(ip)

	u, err := s.store.UserByName(name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	hash := u.PasswordHash
	if err != nil || u.Disabled || u.Locked {
		hash = "" // still spend the time, then fail
	}
	ok, verr := auth.VerifyPassword(hash, password)
	if errors.Is(verr, auth.ErrBusy) {
		http.Error(w, "busy; try again in a moment", http.StatusServiceUnavailable)
		return
	}
	if !ok {
		s.failed(r, name, ip, u.ID, "login-failed")
		show(http.StatusUnauthorized, badLogin, name)
		return
	}
	// Any session this browser had is replaced, so a planted cookie can't
	// become an authenticated one.
	if old := s.loadAuth(r); old != nil {
		_ = s.store.DeleteSession(old.sess.ID)
	}
	if u.HasTOTP() {
		if _, err := s.newSession(w, r, u, store.StateTOTPPending); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "login-password-ok", "user", u.Username)
		q := ""
		if next != "" {
			q = "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, pathLoginTOTP+q, http.StatusSeeOther)
		return
	}
	s.succeeded(name, ip, u.ID)
	sess, err := s.newSession(w, r, u, store.StateFull)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "login", "user", u.Username)
	setLogUser(r, u.Username)
	a := &authed{sess: sess, user: u, state: s.effective(sess, u)}
	if a.state != effFull {
		s.sendToState(w, r, a, next)
		return
	}
	s.redirectNext(w, r, next)
}

func (s *Server) serveLoginTOTP(w http.ResponseWriter, r *http.Request, st *state) {
	if !allow(w, r, "GET", "HEAD", "POST") {
		return
	}
	next := authNext(r.FormValue("next"))
	a := s.loadAuth(r)
	if a == nil || a.state != effPending {
		if a != nil {
			s.sendToState(w, r, a, next)
		} else {
			http.Redirect(w, r, pathLogin, http.StatusSeeOther)
		}
		return
	}
	show := func(status int, msg string) {
		s.showForm(w, r, a, "totp", "Two-factor code", refuse(status, msg), loginData{Next: next})
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, "")
		return
	}
	if !s.checkPost(w, r, a) {
		return
	}
	next = authNext(r.PostFormValue("next"))
	ip := s.limitKey(r)
	name := a.user.Username
	if s.throttled(w, r, name, ip, func(msg string) {
		s.showForm(w, r, a, "totp", "Two-factor code", refuse(http.StatusTooManyRequests, msg), loginData{Next: next})
	}) {
		return
	}
	defer s.release(ip)

	// Reserve this attempt before checking the code, in one transaction, so
	// parallel guesses can't all slip in under the cap.
	reserved := false
	if err := s.store.UpdateSession(a.sess.ID, func(x *store.Session) bool {
		if x.Attempts >= maxTOTPAttempts {
			return false
		}
		x.Attempts++
		reserved = true
		return true
	}); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	tooMany := func() {
		s.clearCookie(w, cookieAuth)
		s.showForm(w, r, nil, "login", "Log in", refuse(http.StatusUnauthorized, "Too many wrong codes. Log in again."), loginData{Next: next})
	}
	if !reserved {
		tooMany()
		return
	}

	code := strings.TrimSpace(r.PostFormValue("code"))
	used := ""
	_, err := s.store.UpdateUser(a.user.ID, func(u *store.User) error {
		// Checked and recorded in one transaction, so two requests racing
		// with the same code can't both pass.
		if u.AuthEpoch != a.sess.AuthEpoch || !u.HasTOTP() || u.Locked {
			return errBadCode
		}
		if digits := strings.ReplaceAll(code, " ", ""); len(digits) == 6 && strings.Trim(digits, "0123456789") == "" {
			secret, err := s.opts.Box.Open(u.ID, u.TOTPSecret)
			if err != nil {
				return err
			}
			step, ok := auth.VerifyTOTP(secret, digits, s.opts.Now(), u.TOTPLastStep)
			if !ok {
				return errBadCode
			}
			u.TOTPLastStep = step
			used = "totp"
			return nil
		}
		i := auth.MatchRecoveryCode(u.RecoveryHashes, code)
		if i < 0 {
			return errBadCode
		}
		u.RecoveryHashes = append(u.RecoveryHashes[:i:i], u.RecoveryHashes[i+1:]...)
		used = "recovery"
		return nil
	})
	if errors.Is(err, errBadCode) {
		s.failed(r, name, ip, a.user.ID, "totp-failed")
		gone := false
		_ = s.store.UpdateSession(a.sess.ID, func(x *store.Session) bool {
			gone = x.Attempts >= maxTOTPAttempts
			return !gone
		})
		if gone {
			tooMany()
			return
		}
		show(http.StatusUnauthorized, "That code didn't work.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.succeeded(name, ip, a.user.ID)
	if err := s.rotate(w, a.sess, func(x *store.Session) {
		x.State = store.StateFull
		x.Attempts = 0
		x.ExpiresAt = s.opts.Now().Add(s.opts.SessionMax)
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "login", "user", name, "factor", used)
	u, _ := s.store.UserByID(a.user.ID)
	if used == "recovery" {
		// Say how many are left before carrying on, so running out is no
		// surprise.
		s.showForm(w, r, nil, "message", "Recovery code used", result{}, messageData{
			Text:     fmt.Sprintf("You logged in with a recovery code and have %d left. You can make new ones on your account page.", len(u.RecoveryHashes)),
			Link:     s.nextURL(next),
			LinkText: "Continue",
		})
		return
	}
	sess, _, err := s.store.SessionByID(a.sess.ID, s.opts.Now(), s.opts.SessionIdle)
	if err == nil {
		if st := s.effective(sess, u); st != effFull {
			s.sendToState(w, r, &authed{sess: sess, user: u, state: st}, next)
			return
		}
	}
	s.redirectNext(w, r, next)
}

func (s *Server) nextURL(next string) string {
	if next = authNext(next); next != "" {
		return next
	}
	return s.portal + "/"
}

var errBadCode = errors.New("bad code")

// serveAuthLogout logs out from the auth host (account and admin pages).
func (s *Server) serveAuthLogout(w http.ResponseWriter, r *http.Request) {
	if !allow(w, r, "POST") {
		return
	}
	a := s.loadAuth(r)
	if !s.checkPost(w, r, a) {
		return
	}
	if a != nil {
		if err := s.store.DeleteSession(a.sess.ID); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "logout", "user", a.user.Username)
	}
	s.clearCookie(w, cookieAuth)
	http.Redirect(w, r, pathLoggedOut, http.StatusSeeOther)
}

// serveLoggedOut is where the portal's logout lands. The session is gone
// already; this clears the auth cookie if it no longer works. It never ends
// a live session, so a cross-site link to it does nothing.
func (s *Server) serveLoggedOut(w http.ResponseWriter, r *http.Request, st *state) {
	if !allow(w, r, "GET", "HEAD") {
		return
	}
	if s.cookie(r, cookieAuth) != "" && s.loadAuth(r) == nil {
		s.clearCookie(w, cookieAuth)
	}
	s.showForm(w, r, nil, "message", "Logged out", result{}, messageData{
		Text: "You have been logged out.", Link: pathLogin, LinkText: "Log in again",
	})
}
