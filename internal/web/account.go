package web

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
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
	show := func(status int, a *authed, errMsg, notice string) {
		p, err := s.accountPage(a, next)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		p.Error, p.Notice = errMsg, notice
		s.render(w, r, status, "account", p)
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, a, "", "")
		return
	}
	if !s.checkPost(w, r, a) {
		return
	}
	next = authNext(r.PostFormValue("next"))
	action := r.PostFormValue("action")
	// Each limited state may do only what clears it.
	allowed := map[effState][]string{
		effMustChangePW: {"password"},
		effMustEnrol:    {"totp-begin", "totp-confirm"},
	}
	if list, limited := allowed[a.state]; limited && !contains(list, action) {
		show(http.StatusForbidden, a, "Finish this step first.", "")
		return
	}

	switch action {
	case "profile":
		name, err := store.CleanName(r.PostFormValue("name"))
		if err == nil {
			var email string
			if email, err = store.CleanEmail(r.PostFormValue("email")); err == nil {
				_, err = s.store.UpdateUser(a.user.ID, func(u *store.User) error { u.Name, u.Email = name, email; return nil })
			}
		}
		if err != nil {
			show(http.StatusBadRequest, a, userError(err), "")
			return
		}
		a.user, _ = s.store.UserByID(a.user.ID)
		show(http.StatusOK, a, "", "Saved.")

	case "password":
		if !s.checkCurrentPassword(w, r, a, show) {
			return
		}
		pw := r.PostFormValue("new")
		if pw != r.PostFormValue("confirm") {
			show(http.StatusBadRequest, a, "The new passwords don't match.", "")
			return
		}
		if err := auth.CheckPassword(pw, a.user.Username); err != nil {
			show(http.StatusBadRequest, a, userError(err), "")
			return
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		u, err := s.store.UpdateUser(a.user.ID, func(u *store.User) error {
			u.PasswordHash, u.MustChangePassword = hash, false
			return nil
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "password-changed", "user", u.Username)
		na, ok := s.reissue(w, r, u)
		if !ok {
			return
		}
		if na.state == effFull && (a.state != effFull || next != "") {
			s.redirectNext(w, r, next)
			return
		}
		show(http.StatusOK, na, "", "Password changed. You've been logged out everywhere else.")

	case "totp-begin":
		if a.user.HasTOTP() {
			show(http.StatusBadRequest, a, "Two-factor login is already set up.", "")
			return
		}
		// Re-check the password, so a hijacked session can't bind its own
		// authenticator and lock the owner out. This applies to forced
		// enrolment too: a group can start requiring TOTP long after the
		// session logged in.
		if !s.checkCurrentPassword(w, r, a, show) {
			return
		}
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		sealed, err := s.opts.Box.Seal(a.user.ID, secret)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if err := s.store.UpdateSession(a.sess.ID, func(x *store.Session) bool { x.PendingTOTP = sealed; return true }); err != nil {
			s.fail(w, r, err)
			return
		}
		a.sess.PendingTOTP = sealed
		show(http.StatusOK, a, "", "")

	case "totp-confirm":
		if a.sess.PendingTOTP == "" || a.user.HasTOTP() {
			show(http.StatusBadRequest, a, "Start setting up two-factor login first.", "")
			return
		}
		secret, err := s.opts.Box.Open(a.user.ID, a.sess.PendingTOTP)
		if err != nil {
			show(http.StatusBadRequest, a, "Start setting up two-factor login again.", "")
			return
		}
		step, ok := auth.VerifyTOTP(secret, r.PostFormValue("code"), s.opts.Now(), 0)
		if !ok {
			show(http.StatusBadRequest, a, "That code didn't match. Check the time on your device and try again.", "")
			return
		}
		codes, hashes, err := auth.NewRecoveryCodes()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		u, err := s.store.UpdateUser(a.user.ID, func(u *store.User) error {
			if u.HasTOTP() {
				return errors.New("already enrolled")
			}
			u.TOTPSecret, u.TOTPLastStep, u.RecoveryHashes = a.sess.PendingTOTP, step, hashes
			return nil
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "totp-enrolled", "user", u.Username)
		na, ok := s.reissue(w, r, u)
		if !ok {
			return
		}
		s.showRecovery(w, r, na, codes, next, "Two-factor login is on. You've been logged out everywhere else.")

	case "totp-disable":
		if !a.user.HasTOTP() {
			show(http.StatusBadRequest, a, "Two-factor login isn't set up.", "")
			return
		}
		if s.requiresTOTP(a.user) {
			show(http.StatusForbidden, a, "One of your groups requires two-factor login, so it can't be turned off.", "")
			return
		}
		if !s.checkCurrentPassword(w, r, a, show) || !s.checkCurrentCode(w, r, a, show) {
			return
		}
		u, err := s.store.UpdateUser(a.user.ID, func(u *store.User) error {
			u.TOTPSecret, u.TOTPLastStep, u.RecoveryHashes = "", 0, nil
			return nil
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "totp-disabled", "user", u.Username)
		na, ok := s.reissue(w, r, u)
		if !ok {
			return
		}
		show(http.StatusOK, na, "", "Two-factor login is off.")

	case "recovery":
		if !a.user.HasTOTP() {
			show(http.StatusBadRequest, a, "Two-factor login isn't set up.", "")
			return
		}
		if !s.checkCurrentPassword(w, r, a, show) {
			return
		}
		codes, hashes, err := auth.NewRecoveryCodes()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		u, err := s.store.UpdateUser(a.user.ID, func(u *store.User) error { u.RecoveryHashes = hashes; return nil })
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "recovery-codes-regenerated", "user", u.Username)
		na, ok := s.reissue(w, r, u)
		if !ok {
			return
		}
		s.showRecovery(w, r, na, codes, "", "New recovery codes made; the old ones no longer work.")

	case "revoke":
		id := r.PostFormValue("session")
		ss, err := s.store.UserSessions(a.user.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, x := range ss {
			if x.ID == id && id != a.sess.ID {
				if err := s.store.DeleteSession(id); err != nil {
					s.fail(w, r, err)
					return
				}
				s.audit(r, "session-revoked", "user", a.user.Username)
			}
		}
		show(http.StatusOK, a, "", "Session ended.")

	case "revoke-others":
		if err := s.store.DeleteUserSessions(a.user.ID, a.sess.ID); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "sessions-revoked", "user", a.user.Username)
		show(http.StatusOK, a, "", "Logged out everywhere else.")

	default:
		show(http.StatusBadRequest, a, "Unknown action.", "")
	}
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

func (s *Server) showRecovery(w http.ResponseWriter, r *http.Request, a *authed, codes []string, next, notice string) {
	link := pathAccount
	if next = authNext(next); next != "" && a.state == effFull {
		link = next
	}
	p := s.newPage("Recovery codes", a, recoveryData{Codes: codes, Next: link})
	p.Notice = notice
	s.render(w, r, http.StatusOK, "recovery", p)
}

type recoveryData struct {
	Codes []string
	Next  string
}

// checkCurrentPassword re-checks the password before a security change,
// counting failures like a login.
func (s *Server) checkCurrentPassword(w http.ResponseWriter, r *http.Request, a *authed, show func(int, *authed, string, string)) bool {
	ip := s.clientIP(r)
	if s.throttled(w, r, a.user.Username, ip, func(msg string) { show(http.StatusTooManyRequests, a, msg, "") }) {
		return false
	}
	ok, err := auth.VerifyPassword(a.user.PasswordHash, r.PostFormValue("current"))
	if errors.Is(err, auth.ErrBusy) {
		http.Error(w, "busy; try again in a moment", http.StatusServiceUnavailable)
		return false
	}
	if !ok {
		s.failed(r, a.user.Username, ip, 0, "reauth-failed")
		show(http.StatusUnauthorized, a, "Your current password is wrong.", "")
		return false
	}
	return true
}

// checkCurrentCode checks a TOTP or recovery code before a security change,
// recording the step so it can't be replayed.
func (s *Server) checkCurrentCode(w http.ResponseWriter, r *http.Request, a *authed, show func(int, *authed, string, string)) bool {
	code := strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("code")), " ", "")
	_, err := s.store.UpdateUser(a.user.ID, func(u *store.User) error {
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
		s.failed(r, a.user.Username, s.clientIP(r), 0, "reauth-totp-failed")
		show(http.StatusUnauthorized, a, "That code didn't work.", "")
		return false
	}
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	return true
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

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
