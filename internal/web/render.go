package web

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"slices"
	"time"

	"github.com/computerswereamistake/tabs/internal/store"
)

// authPages are rendered inside templates/layout.html.
var authPages = []string{
	"login", "totp", "message", "account", "recovery", "invite", "reset", "setup",
	"admin_users", "admin_user", "admin_groups", "admin_invites", "admin_bans",
}

func when(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

var funcs = template.FuncMap{
	"when": when,
	// dict builds a map for passing several values to a sub-template.
	"dict": func(kv ...any) (map[string]any, error) {
		if len(kv)%2 != 0 {
			return nil, errors.New("dict needs key/value pairs")
		}
		m := make(map[string]any, len(kv)/2)
		for i := 0; i < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				return nil, errors.New("dict keys must be strings")
			}
			m[k] = kv[i+1]
		}
		return m, nil
	},
	// has reports whether list (a []string, or nil) contains s.
	"has": func(list any, s string) bool {
		l, _ := list.([]string)
		return slices.Contains(l, s)
	},
}

func parsePages() (map[string]*template.Template, error) {
	pages := map[string]*template.Template{}
	idx, err := template.New("index.html").Funcs(funcs).ParseFS(templateFS, "templates/index.html")
	if err != nil {
		return nil, err
	}
	pages["index"] = idx
	for _, name := range authPages {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return pages, nil
}

// page is what every auth-host template gets.
type page struct {
	Site    string      // configured title
	Heading string      // page heading
	Error   string      // shown in a red box
	Notice  string      // shown in a green box
	CSRF    string      // session CSRF token, for forms
	Me      *store.User // logged-in user, for the nav; nil before login
	Portal  string      // link back to the sidebar
	Data    any
}

func (s *Server) newPage(heading string, a *authed, data any) page {
	p := page{Site: s.state.Load().cfg.Title, Heading: heading, Portal: s.portal + "/", Data: data}
	if a != nil {
		p.CSRF = a.sess.CSRF
		if a.state == effFull {
			u := a.user
			p.Me = &u
		}
	}
	return p
}

// render executes a page into a buffer first, so a template error gives a
// clean 500 instead of half a page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	t := s.pages[name]
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		s.log.Error("render", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}

// result is what a form action wants shown next, on the same page.
type result struct {
	status  int    // 0 means 200
	err     string // shown in a red box
	notice  string // shown in a green box
	link    string // a one-time link to show (admin pages)
	linkFor string // whose link it is
	written bool   // the action already answered (redirect, 500, ...)
}

// done is a successful action with an optional notice.
func done(notice string) result { return result{notice: notice} }

// refuse is a failed action, shown with its message.
func refuse(status int, msg string) result { return result{status: status, err: msg} }

// handled means the action wrote the response itself.
var handled = result{written: true}

// failResult logs an unexpected error, answers 500 and returns handled.
func (s *Server) failResult(w http.ResponseWriter, r *http.Request, err error) result {
	s.fail(w, r, err)
	return handled
}

// showForm renders a form page with the outcome of the last action.
func (s *Server) showForm(w http.ResponseWriter, r *http.Request, a *authed, name, heading string, res result, data any) {
	p := s.newPage(heading, a, data)
	p.Error, p.Notice = res.err, res.notice
	status := res.status
	if status == 0 {
		status = http.StatusOK
	}
	s.render(w, r, status, name, p)
}

// messageData is a line of text and an optional link onward.
type messageData struct {
	Text, Link, LinkText string
}

// message renders a plain page with a heading and one line of text.
func (s *Server) message(w http.ResponseWriter, r *http.Request, status int, heading, text string) {
	s.render(w, r, status, "message", s.newPage(heading, nil, messageData{Text: text}))
}

// fail logs an unexpected error and answers 500 without details.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "path", redactPath(r.URL.Path), "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// audit logs a security-relevant event. Never pass secrets.
func (s *Server) audit(r *http.Request, event string, kv ...any) {
	args := append([]any{"event", event, "ip", s.clientIP(r)}, kv...)
	s.log.Info("auth", args...)
}
