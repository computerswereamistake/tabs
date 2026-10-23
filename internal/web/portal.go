package web

import (
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/tabs"
)

type pageTab struct {
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Icon    string `json:"-"`
	Initial string `json:"-"` // shown when there is no icon
}

type indexData struct {
	Title      string
	Viewer     tabs.Viewer
	Admin      bool
	AccountURL string
	AdminURL   string
	CSRF       string
	Tabs       []pageTab
}

// serveIndex renders the sidebar for a gated, fully logged-in viewer, and
// otherwise starts the handoff.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request, st *state, host string) {
	w.Header().Set("Cache-Control", "no-store")
	g := s.loadGate(r, host)
	if g == nil || g.state != effFull {
		http.Redirect(w, r, pathAuthStart+"?rd=/", http.StatusFound)
		return
	}
	setLogUser(r, g.user.Username)
	v := viewerOf(g.user)
	data := indexData{
		Title: st.cfg.Title, Viewer: v, Admin: g.user.Admin, CSRF: g.gate.CSRF,
		AccountURL: s.authOrigin + pathAccount, AdminURL: s.authOrigin + pathAdmin + "/users",
		Tabs: []pageTab{},
	}
	for _, t := range st.cfg.VisibleTo(v) {
		initial, _ := utf8.DecodeRuneInString(strings.TrimSpace(t.Name))
		data.Tabs = append(data.Tabs, pageTab{Slug: t.Slug, Name: t.Name, URL: t.URL, Icon: t.Icon, Initial: string(initial)})
	}
	s.render(w, r, http.StatusOK, "index", data)
}

// serveSession answers the page's session check: 204 while the gate and
// its session are good, 401 otherwise.
func (s *Server) serveSession(w http.ResponseWriter, r *http.Request, host string) {
	w.Header().Set("Cache-Control", "no-store")
	g := s.loadGate(r, host)
	if g == nil || g.state != effFull {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	setLogUser(r, g.user.Username)
	w.WriteHeader(http.StatusNoContent)
}

// servePortalLogout ends the whole session (every gate with it) from the
// sidebar, then lets the auth host clear its own cookie.
func (s *Server) servePortalLogout(w http.ResponseWriter, r *http.Request, host string) {
	w.Header().Set("Cache-Control", "no-store")
	if !sameOrigin(r, s.portal) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if tok := s.cookie(r, cookieGate); tok != "" {
		if g := s.gateFromToken(tok, host); g != nil {
			if !auth.TokensEqual(r.PostFormValue("csrf"), g.gate.CSRF) {
				http.Error(w, "form expired; reload and try again", http.StatusForbidden)
				return
			}
			if err := s.store.DeleteSession(g.sess.ID); err != nil {
				s.fail(w, r, err)
				return
			}
			s.audit(r, "logout", "user", g.user.Username)
		}
	}
	s.clearCookie(w, cookieGate)
	http.Redirect(w, r, s.authOrigin+pathLoggedOut, http.StatusSeeOther)
}
