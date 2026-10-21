// Package web serves the tabs page and its assets. It performs no
// authentication: identity comes from forward-auth headers, which are only
// believed when the request arrives from a trusted proxy address.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/computerswereamistake/tabs/internal/tabs"
)

//go:embed templates/index.html
var templateFS embed.FS

//go:embed static
var embeddedStatic embed.FS

var indexTmpl = template.Must(template.ParseFS(templateFS, "templates/index.html"))

const (
	prefixStatic = "/_tabs/static/"
	prefixIcons  = "/_tabs/icons/"
	pathHealthz  = "/_tabs/healthz"
	pathSession  = "/_tabs/session"
)

// state is swapped atomically on config reload.
type state struct {
	cfg tabs.Config
	csp string
}

// Server is the HTTP handler for the app.
type Server struct {
	state   atomic.Pointer[state]
	trusted []netip.Prefix
	icons   fs.FS
	static  fs.FS
	log     *slog.Logger
}

// New returns a Server. icons should be rooted so that traversal outside it
// is impossible (e.g. os.Root.FS).
func New(cfg tabs.Config, trusted []netip.Prefix, icons fs.FS, log *slog.Logger) *Server {
	static, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		panic(err)
	}
	s := &Server{trusted: trusted, icons: icons, static: static, log: log}
	s.SetConfig(cfg)
	return s
}

// SetConfig replaces the active config. The caller must have validated it.
func (s *Server) SetConfig(cfg tabs.Config) {
	s.state.Store(&state{cfg: cfg, csp: buildCSP(cfg.FrameOrigins())})
}

func buildCSP(frameOrigins []string) string {
	frameSrc := strings.Join(append([]string{"'self'"}, frameOrigins...), " ")
	// connect-src 'self' is only for the page's session check.
	return "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"frame-src " + frameSrc + "; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

// ParseTrustedProxies parses a comma-separated list of CIDRs or bare IPs.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for f := range strings.SplitSeq(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, err
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("%s would trust every address", f)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// isTrusted reports whether remoteAddr (ip:port) is inside a trusted prefix.
// X-Forwarded-For is deliberately ignored.
func (s *Server) isTrusted(remoteAddr string) bool {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	addr := ap.Addr().Unmap()
	for _, p := range s.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var identityHeaders = []string{"Remote-User", "Remote-Name", "Remote-Email", "Remote-Groups"}

func (s *Server) viewer(r *http.Request) (tabs.Viewer, bool) {
	if !s.isTrusted(r.RemoteAddr) {
		return tabs.Viewer{}, false
	}
	// A repeated identity header means a proxy appended instead of replacing,
	// and the first value may be the client's. Refuse rather than guess.
	for _, h := range identityHeaders {
		if len(r.Header.Values(h)) > 1 {
			return tabs.Viewer{}, false
		}
	}
	v, err := tabs.NewViewer(r.Header.Get("Remote-User"), r.Header.Get("Remote-Name"), r.Header.Get("Remote-Groups"))
	return v, err == nil
}

// ServeHTTP routes by exact path or prefix. It does not use http.ServeMux so
// that unclean paths (containing "..") are rejected with 404, not redirected.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	info := &reqInfo{}
	r = r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, info))
	st := s.state.Load()

	h := w.Header()
	h.Set("Content-Security-Policy", st.csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	// Other sites can't embed or probe anything here (e.g. /_tabs/session
	// as a logged-in oracle), whatever the auth cookie's SameSite setting.
	h.Set("Cross-Origin-Resource-Policy", "same-origin")

	defer func() {
		s.log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start),
			"user", info.user,
		)
	}()

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		http.Error(rec, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch p := r.URL.Path; {
	case p == "/":
		s.serveIndex(rec, r, st.cfg)
	case p == pathSession:
		s.serveSession(rec, r)
	case p == pathHealthz:
		h.Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(rec, "ok")
	case strings.HasPrefix(p, prefixStatic):
		// Embedded files have no mtime, so make browsers refetch after upgrades.
		h.Set("Cache-Control", "no-cache")
		serveFile(rec, r, s.static, strings.TrimPrefix(p, prefixStatic))
	case strings.HasPrefix(p, prefixIcons):
		name := strings.TrimPrefix(p, prefixIcons)
		ct, ok := tabs.IconContentType(name)
		if !ok {
			http.NotFound(rec, r)
			return
		}
		h.Set("Content-Type", ct)
		serveFile(rec, r, s.icons, name)
	default:
		http.NotFound(rec, r)
	}
}

type pageTab struct {
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Icon    string `json:"-"`
	Initial string `json:"-"` // shown when there is no icon
}

type pageData struct {
	Title     string
	LogoutURL string
	Viewer    tabs.Viewer
	Tabs      []pageTab
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request, cfg tabs.Config) {
	w.Header().Set("Cache-Control", "no-store")
	v, ok := s.viewer(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if info, _ := r.Context().Value(reqInfoKey{}).(*reqInfo); info != nil {
		info.user = v.User
	}
	data := pageData{Title: cfg.Title, LogoutURL: cfg.LogoutURL, Viewer: v, Tabs: []pageTab{}}
	for _, t := range cfg.VisibleTo(v) {
		initial, _ := utf8.DecodeRuneInString(strings.TrimSpace(t.Name))
		data.Tabs = append(data.Tabs, pageTab{Slug: t.Slug, Name: t.Name, URL: t.URL, Icon: t.Icon, Initial: string(initial)})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTmpl.Execute(w, data); err != nil {
		s.log.Error("render index", "err", err)
	}
}

// serveSession answers the page's session check: 204 while forward-auth is
// still passing identity through, 401 otherwise. In production an expired
// session never reaches here (the proxy redirects to login first); the page
// treats that redirect the same as a 401.
func (s *Server) serveSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	v, ok := s.viewer(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if info, _ := r.Context().Value(reqInfoKey{}).(*reqInfo); info != nil {
		info.user = v.User
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveFile serves a single regular file from fsys. Invalid paths ("..",
// leading "/", empty) and directories give 404, so there are no listings.
func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	if name == "" || !fs.ValidPath(name) || strings.Contains(name, `\`) {
		http.NotFound(w, r)
		return
	}
	f, err := fsys.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), rs)
}

type reqInfoKey struct{}

type reqInfo struct{ user string }

type recorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}
