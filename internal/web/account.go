package web

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"slices"
	"strings"

	"rsc.io/qr"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
)

type sessionRow struct {
	ID      string
	Current bool
	Created string
	Seen    string
	Agent   string
}

type enrolData struct {
	QR     template.URL // data: URI of a PNG
	Secret string       // for typing in by hand
}

type accountData struct {
	User           store.User
	State          string // "full", "must-change-pw" or "must-enrol"
	Next           string
	Sessions       []sessionRow
	Enrol          *enrolData
	RecoveryLeft   int
	TOTPRequired   bool
	MinPasswordLen int
}

func stateName(e effState) string {
	switch e {
	case effMustChangePW:
		return "must-change-pw"
	case effMustEnrol:
		return "must-enrol"
	}
	return "full"
}

func (s *Server) accountPage(a *authed, next string) (page, error) {
	d := accountData{
		User: a.user, State: stateName(a.state), Next: authNext(next),
		RecoveryLeft: len(a.user.RecoveryHashes), TOTPRequired: s.requiresTOTP(a.user),
		MinPasswordLen: auth.MinPasswordLen,
	}
	if a.state == effFull {
		ss, err := s.store.UserSessions(a.user.ID)
		if err != nil {
			return page{}, err
		}
		for _, x := range ss {
			d.Sessions = append(d.Sessions, sessionRow{
				ID: x.ID, Current: x.ID == a.sess.ID, Created: when(x.CreatedAt), Seen: when(x.LastSeen), Agent: x.UserAgent,
			})
		}
	}
	if a.sess.PendingTOTP != "" {
		// A secret that no longer opens (the key was rotated) just means
		// enrolment starts again.
		if secret, err := s.opts.Box.Open(a.user.ID, a.sess.PendingTOTP); err == nil {
			if d.Enrol, err = s.enrolData(a.user, secret); err != nil {
				return page{}, err
			}
		}
	}
	heading := "Your account"
	switch a.state {
	case effMustChangePW:
		heading = "Choose a new password"
	case effMustEnrol:
		heading = "Set up two-factor login"
	}
	return s.newPage(heading, a, d), nil
}

func (s *Server) enrolData(u store.User, secret string) (*enrolData, error) {
	uri := auth.TOTPURI(s.state.Load().cfg.Title, u.Username, secret)
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		return nil, err
	}
	code.Scale = 6
	// #nosec G203 -- a data: URI we just built from a PNG, not user input
	src := template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()))
	// Groups of four are easier to type.
	var sb strings.Builder
	for i, c := range secret {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(c)
	}
	return &enrolData{QR: src, Secret: sb.String()}, nil
}

func (s *Server) serveAccount(w http.ResponseWriter, r *http.Request, st *state) {
	if !allow(w, r, "GET", "HEAD", "POST") {
		return
	}
	a := s.loadAuth(r)
	next := authNext(r.FormValue("next"))
	if a == nil || a.state == effPending {
		if a != nil {
			s.sendToState(w, r, a, next)
		} else {
			http.Redirect(w, r, pathLogin+"?next="+pathAccount, http.StatusSeeOther)
		}
		return
	}
	c := &accountCtx{w: w, r: r, a: a, next: next}
	var res result
	if r.Method == http.MethodPost {
		if !s.checkPost(w, r, a) {
			return
		}
		c.next = authNext(r.PostFormValue("next"))
		if res = s.runAccountAction(c); res.written {
			return
		}
	}
	p, err := s.accountPage(c.a, c.next)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.showForm(w, r, c.a, "account", p.Heading, res, p.Data)
}

// accountCtx is one account-page request. Actions that reissue the
// session (after a change that ended it) replace a.
type accountCtx struct {
	w    http.ResponseWriter
	r    *http.Request
	a    *authed
	next string
}

// accountAction is one form on the account page. Every action is allowed
// in a full session; a limited one (must change password, must enrol) may
// only use the actions that clear it.
type accountAction struct {
	alsoIn []effState
	run    func(s *Server, c *accountCtx) result
}

var accountActions = map[string]accountAction{
	"profile":       {run: (*Server).accountProfile},
	"password":      {alsoIn: []effState{effMustChangePW}, run: (*Server).accountPassword},
	"totp-begin":    {alsoIn: []effState{effMustEnrol}, run: (*Server).accountTOTPBegin},
	"totp-confirm":  {alsoIn: []effState{effMustEnrol}, run: (*Server).accountTOTPConfirm},
	"totp-disable":  {run: (*Server).accountTOTPDisable},
	"recovery":      {run: (*Server).accountRecovery},
	"revoke":        {run: (*Server).accountRevoke},
	"revoke-others": {run: (*Server).accountRevokeOthers},
}

func (s *Server) runAccountAction(c *accountCtx) result {
	act, ok := accountActions[c.r.PostFormValue("action")]
	if !ok {
		return refuse(http.StatusBadRequest, "Unknown action.")
	}
	if c.a.state != effFull && !slices.Contains(act.alsoIn, c.a.state) {
		return refuse(http.StatusForbidden, "Finish this step first.")
	}
	return act.run(s, c)
}

// accountProfile changes the display name. Not the email: it's sent to
// apps as Remote-Email and some match accounts on it, so only admins set it.
func (s *Server) accountProfile(c *accountCtx) result {
	name, err := store.CleanName(c.r.PostFormValue("name"))
	if err == nil {
		c.a.user, err = s.store.UpdateUser(c.a.user.ID, func(u *store.User) error { u.Name = name; return nil })
	}
	if err != nil {
		return refuse(http.StatusBadRequest, userError(err))
	}
	return done("Saved.")
}

func (s *Server) accountPassword(c *accountCtx) result {
	if res, ok := s.recheckPassword(c); !ok {
		return res
	}
	pw := c.r.PostFormValue("new")
	if pw != c.r.PostFormValue("confirm") {
		return refuse(http.StatusBadRequest, "The new passwords don't match.")
	}
	if err := auth.CheckPassword(pw, c.a.user.Username); err != nil {
		return refuse(http.StatusBadRequest, userError(err))
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	u, err := s.store.UpdateUser(c.a.user.ID, func(u *store.User) error {
		u.PasswordHash, u.MustChangePassword = hash, false
		return nil
	})
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	s.audit(c.r, "password-changed", "user", u.Username)
	was := c.a.state
	if !s.reissueFor(c, u) {
		return handled
	}
	// Changing a temporary password clears the way; carry on to wherever
	// the login was going.
	if c.a.state == effFull && (was != effFull || c.next != "") {
		s.redirectNext(c.w, c.r, c.next)
		return handled
	}
	return done("Password changed. You've been logged out everywhere else.")
}

func (s *Server) accountTOTPBegin(c *accountCtx) result {
	if c.a.user.HasTOTP() {
		return refuse(http.StatusBadRequest, "Two-factor login is already set up.")
	}
	// Re-check the password, so a hijacked session can't bind its own
	// authenticator and lock the owner out. This applies to forced
	// enrolment too: a group can start requiring TOTP long after the
	// session logged in.
	if res, ok := s.recheckPassword(c); !ok {
		return res
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	sealed, err := s.opts.Box.Seal(c.a.user.ID, secret)
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	if err := s.store.UpdateSession(c.a.sess.ID, func(x *store.Session) bool { x.PendingTOTP = sealed; return true }); err != nil {
		return s.failResult(c.w, c.r, err)
	}
	c.a.sess.PendingTOTP = sealed
	return result{}
}

func (s *Server) accountTOTPConfirm(c *accountCtx) result {
	if c.a.sess.PendingTOTP == "" || c.a.user.HasTOTP() {
		return refuse(http.StatusBadRequest, "Start setting up two-factor login first.")
	}
	secret, err := s.opts.Box.Open(c.a.user.ID, c.a.sess.PendingTOTP)
	if err != nil {
		return refuse(http.StatusBadRequest, "Start setting up two-factor login again.")
	}
	step, ok := auth.VerifyTOTP(secret, c.r.PostFormValue("code"), s.opts.Now(), 0)
	if !ok {
		return refuse(http.StatusBadRequest, "That code didn't match. Check the time on your device and try again.")
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	pending := c.a.sess.PendingTOTP
	u, err := s.store.UpdateUser(c.a.user.ID, func(u *store.User) error {
		if u.HasTOTP() {
			return errors.New("already enrolled")
		}
		u.TOTPSecret, u.TOTPLastStep, u.RecoveryHashes = pending, step, hashes
		return nil
	})
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	s.audit(c.r, "totp-enrolled", "user", u.Username)
	if !s.reissueFor(c, u) {
		return handled
	}
	s.showRecovery(c.w, c.r, c.a, codes, c.next, "Two-factor login is on. You've been logged out everywhere else.")
	return handled
}

func (s *Server) accountTOTPDisable(c *accountCtx) result {
	if !c.a.user.HasTOTP() {
		return refuse(http.StatusBadRequest, "Two-factor login isn't set up.")
	}
	if s.requiresTOTP(c.a.user) {
		return refuse(http.StatusForbidden, "One of your groups requires two-factor login, so it can't be turned off.")
	}
	if res, ok := s.recheckPassword(c); !ok {
		return res
	}
	if res, ok := s.recheckCode(c); !ok {
		return res
	}
	u, err := s.store.UpdateUser(c.a.user.ID, func(u *store.User) error {
		u.TOTPSecret, u.TOTPLastStep, u.RecoveryHashes = "", 0, nil
		return nil
	})
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	s.audit(c.r, "totp-disabled", "user", u.Username)
	if !s.reissueFor(c, u) {
		return handled
	}
	return done("Two-factor login is off.")
}

// accountRecovery makes new recovery codes. They bypass the authenticator
// from then on, so it needs a current code as well as the password.
func (s *Server) accountRecovery(c *accountCtx) result {
	if !c.a.user.HasTOTP() {
		return refuse(http.StatusBadRequest, "Two-factor login isn't set up.")
	}
	if res, ok := s.recheckPassword(c); !ok {
		return res
	}
	if res, ok := s.recheckCode(c); !ok {
		return res
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	u, err := s.store.UpdateUser(c.a.user.ID, func(u *store.User) error { u.RecoveryHashes = hashes; return nil })
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	s.audit(c.r, "recovery-codes-regenerated", "user", u.Username)
	if !s.reissueFor(c, u) {
		return handled
	}
	s.showRecovery(c.w, c.r, c.a, codes, "", "New recovery codes made; the old ones no longer work.")
	return handled
}

// accountRevoke ends one of the user's other sessions.
func (s *Server) accountRevoke(c *accountCtx) result {
	id := c.r.PostFormValue("session")
	ss, err := s.store.UserSessions(c.a.user.ID)
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	for _, x := range ss {
		if x.ID == id && id != c.a.sess.ID {
			if err := s.store.DeleteSession(id); err != nil {
				return s.failResult(c.w, c.r, err)
			}
			s.audit(c.r, "session-revoked", "user", c.a.user.Username)
		}
	}
	return done("Session ended.")
}

func (s *Server) accountRevokeOthers(c *accountCtx) result {
	if err := s.store.DeleteUserSessions(c.a.user.ID, c.a.sess.ID); err != nil {
		return s.failResult(c.w, c.r, err)
	}
	s.audit(c.r, "sessions-revoked", "user", c.a.user.Username)
	return done("Logged out everywhere else.")
}

// reissue gives the acting user a fresh full session after a change that
// ended all their sessions (AuthEpoch moved).
func (s *Server) reissue(w http.ResponseWriter, r *http.Request, u store.User) (*authed, bool) {
	sess, err := s.newSession(w, r, u, store.StateFull)
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	return &authed{sess: sess, user: u, state: s.effective(sess, u)}, true
}

// reissueFor reissues the request's session for u and makes it current.
func (s *Server) reissueFor(c *accountCtx, u store.User) bool {
	na, ok := s.reissue(c.w, c.r, u)
	if ok {
		c.a = na
	}
	return ok
}

func (s *Server) showRecovery(w http.ResponseWriter, r *http.Request, a *authed, codes []string, next, notice string) {
	link := pathAccount
	if next = authNext(next); next != "" && a.state == effFull {
		link = next
	}
	s.showForm(w, r, a, "recovery", "Recovery codes", done(notice), recoveryData{Codes: codes, Next: link})
}

type recoveryData struct {
	Codes []string
	Next  string
}

// recheckPassword re-checks the password before a security change,
// throttled and counted like a login. On failure the result says what to
// show (or that the response was written).
func (s *Server) recheckPassword(c *accountCtx) (result, bool) {
	ip := s.limitKey(c.r)
	var msg string
	if s.throttled(c.w, c.r, c.a.user.Username, ip, func(m string) { msg = m }) {
		if msg == "" {
			return handled, false // banned; throttled answered
		}
		return refuse(http.StatusTooManyRequests, msg), false
	}
	defer s.release(ip)
	ok, err := auth.VerifyPassword(c.a.user.PasswordHash, c.r.PostFormValue("current"))
	if errors.Is(err, auth.ErrBusy) {
		http.Error(c.w, "busy; try again in a moment", http.StatusServiceUnavailable)
		return handled, false
	}
	if !ok {
		s.failed(c.r, c.a.user.Username, ip, 0, "reauth-failed")
		return refuse(http.StatusUnauthorized, "Your current password is wrong."), false
	}
	s.userLimit.Succeed(c.a.user.Username)
	return result{}, true
}

// recheckCode checks a current TOTP code before a security change,
// recording its step so it can't be replayed.
func (s *Server) recheckCode(c *accountCtx) (result, bool) {
	code := strings.ReplaceAll(strings.TrimSpace(c.r.PostFormValue("code")), " ", "")
	_, err := s.store.UpdateUser(c.a.user.ID, func(u *store.User) error {
		secret, err := s.opts.Box.Open(u.ID, u.TOTPSecret)
		if err != nil {
			return err
		}
		step, ok := auth.VerifyTOTP(secret, code, s.opts.Now(), u.TOTPLastStep)
		if !ok {
			return errBadCode
		}
		u.TOTPLastStep = step
		return nil
	})
	if errors.Is(err, errBadCode) {
		s.failed(c.r, c.a.user.Username, s.limitKey(c.r), 0, "reauth-totp-failed")
		return refuse(http.StatusUnauthorized, "That code didn't work."), false
	}
	if err != nil {
		return s.failResult(c.w, c.r, err), false
	}
	return result{}, true
}

// userError turns a validation error into text for the page. Only errors
// that are meant for users (policy and validation) get through.
func userError(err error) string {
	if errors.Is(err, auth.ErrPasswordPolicy) || errors.Is(err, store.ErrInvalid) ||
		errors.Is(err, store.ErrUsernameTaken) || errors.Is(err, store.ErrEmailTaken) || errors.Is(err, store.ErrGroupExists) || errors.Is(err, store.ErrLastAdmin) {
		msg := err.Error()
		for _, prefix := range []string{auth.ErrPasswordPolicy.Error() + ": ", store.ErrInvalid.Error() + ": "} {
			msg = strings.TrimPrefix(msg, prefix)
		}
		return strings.ToUpper(msg[:1]) + msg[1:] + "."
	}
	return "Something went wrong."
}
