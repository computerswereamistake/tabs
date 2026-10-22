package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
	"github.com/computerswereamistake/tabs/internal/tabs"
)

// The handoff gets a gate cookie onto a portal or app host:
//
//  1. start (on that host) sets a per-flow state cookie and redirects to
//     the auth host's handoff with the flow id, state and target path;
//  2. handoff (auth host) checks the auth session, logging in first if
//     needed, and redirects back with a one-time code bound to the
//     session, host, flow and path;
//  3. callback (on that host) swaps the code for a gate cookie, only if the
//     browser still holds the flow's state cookie. Someone else's code is
//     useless without their state cookie, so nobody can log a victim into
//     the attacker's account.

const (
	stateTTL      = 10 * time.Minute
	codeTTL       = time.Minute
	maxLiveCodes  = 20
	flowIDPattern = `^[A-Za-z0-9_-]{8,43}$`
)

var flowIDRE = regexp.MustCompile(flowIDPattern)

// serveStart begins a handoff for host.
func (s *Server) serveStart(w http.ResponseWriter, r *http.Request, host string) {
	rd, ok := appPath(r.URL.Query().Get("rd"))
	if !ok {
		rd = "/"
	}
	id, err := auth.NewToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id = id[:12]
	state, err := auth.NewToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.setCookie(w, cookieState+id, state, stateTTL)
	q := url.Values{}
	q.Set("host", host)
	q.Set("flow", id)
	q.Set("state", state)
	q.Set("rd", rd)
	if r.URL.Query().Get("retry") == "1" {
		q.Set("retry", "1")
	}
	http.Redirect(w, r, s.authOrigin+pathHandoff+"?"+q.Encode(), http.StatusFound)
}

// serveHandoff issues a code for a logged-in user (auth host).
func (s *Server) serveHandoff(w http.ResponseWriter, r *http.Request, st *state) {
	if !allow(w, r, "GET", "HEAD") {
		return
	}
	q := r.URL.Query()
	host := tabs.CanonicalHost(q.Get("host"))
	flow, stateVal := q.Get("flow"), q.Get("state")
	rd, rdOK := appPath(q.Get("rd"))
	if !st.gated[host] || q.Get("host") != host || !flowIDRE.MatchString(flow) || stateVal == "" || len(stateVal) > 64 || !rdOK {
		s.message(w, r, http.StatusBadRequest, "Bad sign-in link", "That sign-in link isn't valid. Go back to the app and try again.")
		return
	}
	a := s.requireFull(w, r)
	if a == nil {
		return
	}
	tok, err := auth.NewToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.opts.Now()
	err = s.store.CreateCode(store.Code{
		Hash: auth.HashToken(tok), SessionID: a.sess.ID, Host: host, StateID: flow,
		State: auth.HashToken(stateVal), Rd: rd, Retry: q.Get("retry") == "1", ExpiresAt: now.Add(codeTTL),
	}, now, maxLiveCodes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Built from configured values only; host was checked against them.
	cb := s.scheme() + "://" + host + pathCallback + "?code=" + url.QueryEscape(tok)
	if q.Get("retry") == "1" {
		cb += "&retry=1"
	}
	http.Redirect(w, r, cb, http.StatusFound)
}

// serveCallback swaps a code for a gate cookie on host.
func (s *Server) serveCallback(w http.ResponseWriter, r *http.Request, st *state, host string) {
	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 64 {
		http.NotFound(w, r)
		return
	}
	now := s.opts.Now()
	c, err := s.store.ConsumeCode(auth.HashToken(code), now)
	if err != nil && r.URL.Query().Get("retry") != "1" {
		// The code may have been pushed out by other sign-ins (the cap
		// drops the oldest); start over once rather than fail.
		http.Redirect(w, r, pathAuthStart+"?retry=1&rd=/", http.StatusFound)
		return
	}
	if err != nil || c.Host != host {
		s.message(w, r, http.StatusBadRequest, "Sign-in expired", "That sign-in link has expired. Go back to the app and try again.")
		return
	}
	stateVal := s.cookie(r, cookieState+c.StateID)
	s.clearCookie(w, cookieState+c.StateID)
	if stateVal == "" || !auth.TokensEqual(auth.HashToken(stateVal), c.State) {
		// Usually a parallel sign-in in another frame; start over once.
		if !c.Retry {
			http.Redirect(w, r, pathAuthStart+"?retry=1&rd="+url.QueryEscape(c.Rd), http.StatusFound)
			return
		}
		s.message(w, r, http.StatusBadRequest, "Sign-in failed", "This browser didn't start that sign-in. Go back to the app and try again.")
		return
	}
	sess, u, err := s.store.SessionByID(c.SessionID, now, s.opts.SessionIdle)
	if err != nil || s.effective(sess, u) != effFull {
		http.Redirect(w, r, pathAuthStart+"?rd="+url.QueryEscape(c.Rd), http.StatusFound)
		return
	}
	tok, err := auth.NewToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	csrf, err := auth.NewToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.CreateGate(store.Gate{Hash: auth.HashToken(tok), SessionID: sess.ID, Host: host, CSRF: csrf, CreatedAt: now}); err != nil {
		s.fail(w, r, err)
		return
	}
	s.setCookie(w, cookieGate, tok, sess.ExpiresAt.Sub(now))
	setLogUser(r, u.Username)
	http.Redirect(w, r, c.Rd, http.StatusSeeOther)
}

// serveVerify answers Caddy's forward_auth for one tab, named by ?tab= in
// the Caddy route. Tabs never guesses the tab from the URL: Caddy's path
// matching and ours could disagree about "..", "%2f" and the like.
func (s *Server) serveVerify(w http.ResponseWriter, r *http.Request, st *state) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.fromTrustedProxy(r) {
		http.NotFound(w, r)
		return
	}
	if !allow(w, r, "GET", "HEAD") {
		return
	}
	tab, ok := st.cfg.Tab(r.URL.Query().Get("tab"))
	if !ok {
		s.log.Error("verify: unknown tab in forward_auth uri", "tab", r.URL.Query().Get("tab"))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fwdHosts := r.Header.Values("X-Forwarded-Host")
	host := ""
	if len(fwdHosts) == 1 {
		host = tabs.CanonicalHost(fwdHosts[0])
	}
	tabHost := tab.Host()
	if tabHost == "" {
		tabHost = s.portalHost
	}
	if host == "" || host != tabHost {
		s.log.Error("verify: forwarded host doesn't match the tab", "tab", tab.Slug, "host", host, "want", tabHost)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	g := s.loadGate(r, host)
	if g == nil || g.state != effFull {
		s.verifyLogin(w, r, host)
		return
	}
	setLogUser(r, g.user.Username)
	v := viewerOf(g.user)
	if !v.CanSee(tab) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.store.TouchSession(g.sess, s.opts.Now(), time.Minute); err != nil {
		s.log.Error("touch session", "err", err)
	}
	h := w.Header()
	h.Set("Remote-User", v.User)
	h.Set("Remote-Name", v.Name)
	h.Set("Remote-Groups", strings.Join(v.Groups, ","))
	if g.user.Email != "" {
		h.Set("Remote-Email", g.user.Email)
	}
	w.WriteHeader(http.StatusOK)
}

// verifyLogin answers an unauthenticated forward_auth request. Only page
// loads (top level or in a frame) are redirected into the handoff; an
// app's scripts, images and API calls get 401, so a page with many failing
// requests doesn't start many parallel sign-ins.
func (s *Server) verifyLogin(w http.ResponseWriter, r *http.Request, host string) {
	method := r.Header.Get("X-Forwarded-Method")
	navigate := r.Header.Get("Sec-Fetch-Mode") == "navigate"
	if (method == "" || method == http.MethodGet) && navigate {
		rd, ok := appPath(r.Header.Get("X-Forwarded-Uri"))
		if !ok {
			rd = "/"
		}
		http.Redirect(w, r, s.scheme()+"://"+host+pathAuthStart+"?rd="+url.QueryEscape(rd), http.StatusFound)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
