package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
	"github.com/computerswereamistake/tabs/internal/tabs"
)

// Cookie names. In production they carry the __Host- prefix, which makes
// the browser insist on Secure, Path=/ and no Domain, so a sibling
// subdomain can't plant or shadow them.
const (
	cookieAuth   = "tabs_auth"
	cookieGate   = "tabs_gate"
	cookieState  = "tabs_state_" // + flow id
	cookieInvite = "tabs_invite"
	cookieReset  = "tabs_reset"
	cookieSetup  = "tabs_setup"
)

func (s *Server) cookieName(base string) string {
	if s.opts.Insecure {
		return base
	}
	return "__Host-" + base
}

func (s *Server) setCookie(w http.ResponseWriter, base, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(base),
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		Secure:   !s.opts.Insecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, base string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(base), Value: "", Path: "/", MaxAge: -1,
		Secure: !s.opts.Insecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// cookie returns a cookie's value, or "" if absent or repeated (a repeat
// means someone planted a second copy; refuse rather than guess).
func (s *Server) cookie(r *http.Request, base string) string {
	name := s.cookieName(base)
	var found []string
	for _, c := range r.Cookies() {
		if c.Name == name {
			found = append(found, c.Value)
		}
	}
	if len(found) != 1 || len(found[0]) > 128 {
		return ""
	}
	return found[0]
}

// effState is what a session may do right now. Only the first state is
// stored; the others come from the live user record and group settings, so
// an admin requiring TOTP for a group takes effect on the next request.
type effState int

const (
	effNone effState = iota
	effPending
	effMustChangePW
	effMustEnrol
	effFull
)

// authed is a request's auth-host session.
type authed struct {
	sess  store.Session
	user  store.User
	state effState
}

func (s *Server) effective(sess store.Session, u store.User) effState {
	switch {
	case sess.State == store.StateTOTPPending:
		return effPending
	case sess.State != store.StateFull:
		return effNone
	case u.MustChangePassword:
		return effMustChangePW
	case !u.HasTOTP() && s.requiresTOTP(u):
		return effMustEnrol
	}
	return effFull
}

func (s *Server) requiresTOTP(u store.User) bool {
	if len(u.Groups) == 0 {
		return false
	}
	groups, err := s.store.Groups()
	if err != nil {
		s.log.Error("load groups", "err", err)
		return true // fail closed
	}
	for _, g := range groups {
		if g.RequireTOTP && slices.Contains(u.Groups, g.Name) {
			return true
		}
	}
	return false
}

// loadAuth returns the auth-host session, or nil.
func (s *Server) loadAuth(r *http.Request) *authed {
	tok := s.cookie(r, cookieAuth)
	if tok == "" {
		return nil
	}
	now := s.opts.Now()
	sess, u, err := s.store.SessionByToken(auth.HashToken(tok), now, 0)
	if err != nil || !s.idleOK(sess, now) {
		return nil
	}
	a := &authed{sess: sess, user: u, state: s.effective(sess, u)}
	if a.state == effNone {
		return nil
	}
	setLogUser(r, u.Username)
	s.touch(sess.ID, now)
	return a
}

// idleOK applies the idle timeout using the latest activity, counting
// what's only in memory so far (see touch); the store checks the absolute
// lifetime.
func (s *Server) idleOK(sess store.Session, now time.Time) bool {
	last := sess.LastSeen
	s.seenMu.Lock()
	if t := s.seen[sess.ID]; t.After(last) {
		last = t
	}
	s.seenMu.Unlock()
	return now.Sub(last) <= s.opts.SessionIdle
}

// newSession creates a session for u and sets the auth cookie.
func (s *Server) newSession(w http.ResponseWriter, r *http.Request, u store.User, st store.SessionState) (store.Session, error) {
	tok, err := auth.NewToken()
	if err != nil {
		return store.Session{}, err
	}
	id, err := auth.NewToken()
	if err != nil {
		return store.Session{}, err
	}
	csrf, err := auth.NewToken()
	if err != nil {
		return store.Session{}, err
	}
	now := s.opts.Now()
	maxAge := s.opts.SessionMax
	if st == store.StateTOTPPending {
		maxAge = 5 * time.Minute
	}
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200]
	}
	sess := store.Session{
		ID: id, Hash: auth.HashToken(tok), UserID: u.ID, State: st, CSRF: csrf,
		AuthEpoch: u.AuthEpoch, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(maxAge), UserAgent: ua,
	}
	if err := s.store.CreateSession(sess); err != nil {
		return store.Session{}, err
	}
	s.setCookie(w, cookieAuth, tok, maxAge)
	return sess, nil
}

// rotate gives a session a new token (and applies fn), setting the cookie.
func (s *Server) rotate(w http.ResponseWriter, sess store.Session, fn func(*store.Session)) error {
	tok, err := auth.NewToken()
	if err != nil {
		return err
	}
	csrf, err := auth.NewToken()
	if err != nil {
		return err
	}
	var expires time.Time
	err = s.store.RotateSession(sess.ID, auth.HashToken(tok), func(x *store.Session) {
		x.CSRF = csrf
		if fn != nil {
			fn(x)
		}
		expires = x.ExpiresAt
	})
	if err != nil {
		return err
	}
	s.setCookie(w, cookieAuth, tok, expires.Sub(s.opts.Now()))
	return nil
}

// gated is a portal or app request's gate and session.
type gated struct {
	gate  store.Gate
	sess  store.Session
	user  store.User
	state effState
}

// loadGate returns the request's gate for host, or nil. It re-checks the
// session and user on every call, so revocations apply immediately.
func (s *Server) loadGate(r *http.Request, host string) *gated {
	tok := s.cookie(r, cookieGate)
	if tok == "" {
		return nil
	}
	return s.gateFromToken(tok, host)
}

func (s *Server) gateFromToken(tok, host string) *gated {
	now := s.opts.Now()
	g, sess, u, err := s.store.GateSession(auth.HashToken(tok), now, 0)
	if err != nil || g.Host != host || !s.idleOK(sess, now) {
		return nil
	}
	return &gated{gate: g, sess: sess, user: u, state: s.effective(sess, u)}
}

func viewerOf(u store.User) tabs.Viewer {
	name := u.Name
	if name == "" {
		name = u.Username
	}
	return tabs.Viewer{User: u.Username, Name: name, Groups: u.Groups}
}

// --- forms and CSRF ---

// sameOrigin reports whether a POST's Origin is one of allowed. A missing
// Origin is refused: every browser this app supports sends it on POST.
func sameOrigin(r *http.Request, allowed ...string) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return false
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "same-site" && sfs != "none" {
		return false
	}
	return slices.Contains(allowed, o)
}

// checkPost does the origin and (when a session is given) CSRF-token checks
// every auth-host POST needs. ServeHTTP has already limited and parsed the
// body. On failure it has already
// written the response.
func (s *Server) checkPost(w http.ResponseWriter, r *http.Request, a *authed) bool {
	if !sameOrigin(r, s.authOrigin) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return false
	}
	if a != nil && !auth.TokensEqual(r.PostFormValue("csrf"), a.sess.CSRF) {
		http.Error(w, "form expired; go back and try again", http.StatusForbidden)
		return false
	}
	return true
}

// --- redirect targets ---

// cleanPath accepts a same-origin path (with optional query) that is safe
// to redirect to: it starts with one "/", has no backslash, control
// characters or encoded slashes, and is short.
func cleanPath(p string) (string, bool) {
	if p == "" || len(p) > maxRedirectLen || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsAny(p, `\`) {
		return "", false
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	// Encoded slashes are refused in the path, where they could change
	// which route a proxy picks; in the query they're ordinary data.
	lower := strings.ToLower(p)
	pathPart, _, _ := strings.Cut(lower, "?")
	if strings.Contains(pathPart, "%2f") || strings.Contains(pathPart, "%5c") || strings.Contains(lower, "%00") {
		return "", false
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	return p, true
}

// appPath is a redirect target on a portal or app host: a clean path that
// isn't one of tabs' own routes (except "/").
func appPath(p string) (string, bool) {
	p, ok := cleanPath(p)
	if !ok {
		return "", false
	}
	u, _ := url.Parse(p)
	clean := strings.ToLower(u.Path)
	if clean == "/_tabs" || strings.HasPrefix(clean, "/_tabs/") {
		return "", false
	}
	return p, true
}

// authNext is a redirect target after login: a clean auth-host path under
// /_tabs/ (handoff, account, admin), or "" for the portal.
func authNext(p string) string {
	p, ok := cleanPath(p)
	if !ok || !strings.HasPrefix(p, "/_tabs/") || strings.HasPrefix(p, pathLogin) {
		return ""
	}
	return p
}

// redirectNext sends the browser on after login.
func (s *Server) redirectNext(w http.ResponseWriter, r *http.Request, next string) {
	if next = authNext(next); next == "" {
		next = s.portal + "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// sendToState sends a session that isn't full to the one page it may use.
func (s *Server) sendToState(w http.ResponseWriter, r *http.Request, a *authed, next string) {
	q := ""
	if next = authNext(next); next != "" {
		q = "?next=" + url.QueryEscape(next)
	}
	switch a.state {
	case effPending:
		http.Redirect(w, r, pathLoginTOTP+q, http.StatusSeeOther)
	case effMustChangePW, effMustEnrol:
		http.Redirect(w, r, pathAccount+q, http.StatusSeeOther)
	default:
		http.Redirect(w, r, pathLogin+q, http.StatusSeeOther)
	}
}

// requireFull returns the session if it is full; otherwise it redirects
// to wherever the session must go first and returns nil.
func (s *Server) requireFull(w http.ResponseWriter, r *http.Request) *authed {
	a := s.loadAuth(r)
	if a != nil && a.state == effFull {
		return a
	}
	next := r.URL.RequestURI()
	if r.Method != http.MethodGet {
		next = ""
	}
	if a == nil {
		q := ""
		if next = authNext(next); next != "" {
			q = "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, pathLogin+q, http.StatusSeeOther)
		return nil
	}
	s.sendToState(w, r, a, next)
	return nil
}
