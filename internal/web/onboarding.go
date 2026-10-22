package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
)

// Setup, invite and reset links carry a token in the URL. On the first GET
// the token moves into a short-lived HttpOnly cookie and the browser is
// sent to the same page without it, so the token doesn't stay in history
// or leak through Referer. Nothing is used up until the form is posted.

const linkCookieTTL = 30 * time.Minute

type newUserData struct {
	AskEmail       bool // only the first admin sets their own email
	Note           string
	Username       string
	Name           string
	Email          string
	MinPasswordLen int
}

type resetData struct {
	Username       string
	MinPasswordLen int
}

// swapToken handles the "/<base>/<token>" form of a link. It reports
// whether it wrote a response.
func (s *Server) swapToken(w http.ResponseWriter, r *http.Request, base, cookie string) bool {
	tok, ok := strings.CutPrefix(r.URL.Path, base+"/")
	if !ok {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		allow(w, r, "GET", "HEAD")
		return true
	}
	if tok == "" || len(tok) > 64 || strings.Contains(tok, "/") {
		http.NotFound(w, r)
		return true
	}
	s.setCookie(w, cookie, tok, linkCookieTTL)
	http.Redirect(w, r, base, http.StatusSeeOther)
	return true
}

// readNewUser validates the shared fields of the setup and invite forms.
func readNewUser(r *http.Request) (u store.User, password string, d newUserData, err error) {
	d = newUserData{
		Username: strings.TrimSpace(r.PostFormValue("username")),
		Name:     r.PostFormValue("name"),
		Email:    r.PostFormValue("email"),
	}
	name, err := store.NormalizeUsername(d.Username)
	if err != nil {
		return u, "", d, err
	}
	display, err := store.CleanName(d.Name)
	if err != nil {
		return u, "", d, err
	}
	email, err := store.CleanEmail(d.Email)
	if err != nil {
		return u, "", d, err
	}
	password = r.PostFormValue("password")
	if password != r.PostFormValue("confirm") {
		return u, "", d, errMismatch
	}
	if err := auth.CheckPassword(password, name); err != nil {
		return u, "", d, err
	}
	return store.User{Username: name, Name: display, Email: email}, password, d, nil
}

var errMismatch = errors.New("passwords don't match")

func formError(err error) string {
	if errors.Is(err, errMismatch) {
		return "The passwords don't match."
	}
	return userError(err)
}

// --- first admin ---

func (s *Server) setupOpen() string {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setupToken
}

func (s *Server) serveSetup(w http.ResponseWriter, r *http.Request, st *state) {
	if !allow(w, r, "GET", "HEAD", "POST") {
		return
	}
	want := s.setupOpen()
	if want == "" {
		s.message(w, r, http.StatusNotFound, "Setup is complete", "An admin account already exists.")
		return
	}
	if t := r.URL.Query().Get("token"); t != "" && r.Method != http.MethodPost {
		s.setCookie(w, cookieSetup, t, linkCookieTTL)
		http.Redirect(w, r, pathSetup, http.StatusSeeOther)
		return
	}
	if !auth.TokensEqual(s.cookie(r, cookieSetup), want) {
		s.message(w, r, http.StatusForbidden, "Setup link needed", "Open the setup link from the setup-token file next to the database.")
		return
	}
	show := func(status int, d newUserData, msg string) {
		d.MinPasswordLen, d.AskEmail = auth.MinPasswordLen, true
		s.showForm(w, r, nil, "setup", "Create the first admin", refuse(status, msg), d)
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, newUserData{}, "")
		return
	}
	if !s.checkPost(w, r, nil) {
		return
	}
	u, pw, d, err := readNewUser(r)
	if err != nil {
		show(http.StatusBadRequest, d, formError(err))
		return
	}
	if u.PasswordHash, err = auth.HashPassword(pw); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.CreateFirstAdmin(&u); err != nil {
		show(http.StatusBadRequest, d, userError(err))
		return
	}
	s.setupMu.Lock()
	s.setupToken = ""
	s.setupMu.Unlock()
	if s.opts.OnSetupDone != nil {
		s.opts.OnSetupDone()
	}
	s.clearCookie(w, cookieSetup)
	s.audit(r, "setup-complete", "user", u.Username)
	s.showForm(w, r, nil, "message", "Admin created", result{}, messageData{
		Text: "Your admin account is ready.", Link: pathLogin, LinkText: "Log in",
	})
}

// --- invites ---

func (s *Server) serveInvite(w http.ResponseWriter, r *http.Request, st *state) {
	if s.swapToken(w, r, pathInvite, cookieInvite) {
		return
	}
	if !allow(w, r, "GET", "HEAD", "POST") {
		return
	}
	tok := s.cookie(r, cookieInvite)
	inv, err := s.store.Invite(auth.HashToken(tok))
	if tok == "" || err != nil || !inv.Usable(s.opts.Now()) {
		s.message(w, r, http.StatusNotFound, "Invite not valid", "This invite has expired or been used. Ask whoever sent it for a new one.")
		return
	}
	show := func(status int, d newUserData, msg string) {
		d.Note, d.MinPasswordLen = inv.Note, auth.MinPasswordLen
		s.showForm(w, r, nil, "invite", "Create your account", refuse(status, msg), d)
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, newUserData{}, "")
		return
	}
	if !s.checkPost(w, r, nil) {
		return
	}
	u, pw, d, err := readNewUser(r)
	if err != nil {
		show(http.StatusBadRequest, d, formError(err))
		return
	}
	// Emails are sent to apps, which may match accounts on them, so an
	// invitee can't choose one; an admin can add it later.
	u.Email = ""
	if u.PasswordHash, err = auth.HashPassword(pw); err != nil {
		s.fail(w, r, err)
		return
	}
	err = s.store.RedeemInvite(inv.Hash, s.opts.Now(), &u)
	if errors.Is(err, store.ErrInviteUsed) {
		s.message(w, r, http.StatusGone, "Invite not valid", "This invite was used up while you were filling in the form.")
		return
	}
	if err != nil {
		show(http.StatusBadRequest, d, userError(err))
		return
	}
	s.clearCookie(w, cookieInvite)
	s.audit(r, "invite-redeemed", "user", u.Username, "invitedBy", inv.CreatedBy)
	if old := s.loadAuth(r); old != nil {
		_ = s.store.DeleteSession(old.sess.ID)
	}
	sess, err := s.newSession(w, r, u, store.StateFull)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a := &authed{sess: sess, user: u, state: s.effective(sess, u)}
	if a.state != effFull {
		s.sendToState(w, r, a, "")
		return
	}
	s.redirectNext(w, r, "")
}

// --- password reset links ---

func (s *Server) serveReset(w http.ResponseWriter, r *http.Request, st *state) {
	if s.swapToken(w, r, pathReset, cookieReset) {
		return
	}
	if !allow(w, r, "GET", "HEAD", "POST") {
		return
	}
	tok := s.cookie(r, cookieReset)
	now := s.opts.Now()
	rs, err := s.store.Reset(auth.HashToken(tok), now)
	var u store.User
	if err == nil {
		u, err = s.store.UserByID(rs.UserID)
	}
	if tok == "" || err != nil || u.Disabled {
		s.message(w, r, http.StatusNotFound, "Link not valid", "This password link has expired or been used. Ask an admin for a new one.")
		return
	}
	show := func(status int, msg string) {
		s.showForm(w, r, nil, "reset", "Choose a password", refuse(status, msg), resetData{Username: u.Username, MinPasswordLen: auth.MinPasswordLen})
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, "")
		return
	}
	if !s.checkPost(w, r, nil) {
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("confirm") {
		show(http.StatusBadRequest, "The passwords don't match.")
		return
	}
	if err := auth.CheckPassword(pw, u.Username); err != nil {
		show(http.StatusBadRequest, userError(err))
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.store.RedeemReset(rs.Hash, now, hash); err != nil {
		s.message(w, r, http.StatusGone, "Link not valid", "This password link has expired or been used. Ask an admin for a new one.")
		return
	}
	s.clearCookie(w, cookieReset)
	s.audit(r, "password-reset", "user", u.Username)
	s.showForm(w, r, nil, "message", "Password set", result{}, messageData{
		Text: "Your password has been set. You've been logged out everywhere.", Link: pathLogin, LinkText: "Log in",
	})
}
