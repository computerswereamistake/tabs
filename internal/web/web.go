// Package web serves tabs over three kinds of host, all on one listener:
//
//   - the auth host (login, account, admin, invites, handoff), which holds
//     the only cookie that can change anything;
//   - the portal host (the sidebar page, same-origin apps);
//   - app hosts (the hosts of absolute tab URLs).
//
// The portal and app hosts each get a per-host "gate" cookie through a
// one-time handoff from the auth host, and Caddy's forward_auth asks
// /_tabs/auth/verify whether a gate may reach a given tab. Keeping admin
// on its own host means a framed same-origin app can never script it.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
	"github.com/computerswereamistake/tabs/internal/tabs"
)

//go:embed templates
var templateFS embed.FS

//go:embed static
var embeddedStatic embed.FS

const (
	prefixStatic   = "/_tabs/static/"
	prefixIcons    = "/_tabs/icons/"
	pathHealthz    = "/_tabs/healthz"
	pathSession    = "/_tabs/session"
	pathLogin      = "/_tabs/login"
	pathLoginTOTP  = "/_tabs/login/totp"
	pathLogout     = "/_tabs/logout"
	pathLoggedOut  = "/_tabs/logged-out"
	pathAccount    = "/_tabs/account"
	pathSetup      = "/_tabs/setup"
	pathInvite     = "/_tabs/invite"
	pathReset      = "/_tabs/reset"
	pathAdmin      = "/_tabs/admin"
	pathAuthStart  = "/_tabs/auth/start"
	pathHandoff    = "/_tabs/auth/handoff"
	pathCallback   = "/_tabs/auth/callback"
	pathVerify     = "/_tabs/auth/verify"
	maxFormBytes   = 64 << 10
	maxRedirectLen = 2048
)

// Options configures a Server. AuthURL and PublicURL must be distinct
// origins (scheme://host[:port], no path).
type Options struct {
	AuthURL   *url.URL
	PublicURL *url.URL
	Trusted   []netip.Prefix // proxies allowed to call verify and to set X-Forwarded-For
	Insecure  bool           // plain-HTTP cookies, for local development only

	SessionIdle time.Duration
	SessionMax  time.Duration

	Box       *auth.SecretBox
	Banner    *auth.Banner
	LockAfter int // consecutive failures before an account locks; 0 = never

	// SetupToken, when non-empty, lets /_tabs/setup create the first admin.
	SetupToken string
	// OnSetupDone is called once the first admin exists, e.g. to delete
	// the token file. Optional.
	OnSetupDone func()

	Now func() time.Time
}

// state is swapped atomically on config reload.
type state struct {
	cfg        tabs.Config
	portalCSP  string
	authCSP    string
	appCSP     string
	gated      map[string]bool // canonical hosts that get gate cookies: portal + tab hosts
	tabOrigins []string
}

// Server is the HTTP handler for the app.
type Server struct {
	state  atomic.Pointer[state]
	store  *store.Store
	opts   Options
	icons  fs.FS
	static fs.FS
	log    *slog.Logger
	pages  map[string]*template.Template

	authHost, portalHost string
	authOrigin, portal   string

	pairLimit, userLimit, ipLimit *auth.Limiter

	setupMu    sync.Mutex
	setupToken string

	lockMu   sync.Mutex
	failures map[uint64]int // consecutive failed logins per user, for LockAfter

	flightMu sync.Mutex
	inFlight map[string]int // password/code checks running per address

	seenMu sync.Mutex
	seen   map[string]time.Time // session ID -> last use, flushed by FlushSeen
}

// New returns a Server. icons should be rooted so that traversal outside it
// is impossible (e.g. os.Root.FS).
func New(cfg tabs.Config, st *store.Store, opts Options, icons fs.FS, log *slog.Logger) (*Server, error) {
	static, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Banner == nil {
		opts.Banner = auth.NewBanner(0, 0, 0)
	}
	s := &Server{
		store: st, opts: opts, icons: icons, static: static, log: log,
		authHost:   tabs.CanonicalHost(opts.AuthURL.Host),
		portalHost: tabs.CanonicalHost(opts.PublicURL.Host),
		authOrigin: origin(opts.AuthURL),
		portal:     origin(opts.PublicURL),
		setupToken: opts.SetupToken,
		failures:   make(map[uint64]int),
		inFlight:   make(map[string]int),
		seen:       make(map[string]time.Time),
	}
	if s.authHost == "" || s.portalHost == "" || hostname(s.authHost) == hostname(s.portalHost) {
		return nil, fmt.Errorf("auth and portal URLs must have different hostnames (cookies ignore ports)")
	}
	// Strict backoff for one username from one address; looser ceilings
	// per username (so a spray from many addresses still slows) and per
	// address (so one address can't walk many usernames quickly).
	s.pairLimit = &auth.Limiter{Free: 5, Base: 2 * time.Second, Max: 15 * time.Minute, Now: opts.Now}
	s.userLimit = &auth.Limiter{Free: 30, Base: time.Second, Max: time.Minute, Now: opts.Now}
	s.ipLimit = &auth.Limiter{Free: 30, Base: time.Second, Max: 5 * time.Minute, Now: opts.Now}
	if s.pages, err = parsePages(); err != nil {
		return nil, err
	}
	if err := s.SetConfig(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// touch notes that a session was used. It's only memory: FlushSeen writes
// the batch, so forward-auth checks never wait on the disk.
func (s *Server) touch(id string, t time.Time) {
	s.seenMu.Lock()
	if t.After(s.seen[id]) {
		s.seen[id] = t
	}
	s.seenMu.Unlock()
}

// FlushSeen writes recent session activity in one transaction. Call it
// about once a minute and before shutdown; the idle timeout is measured
// from what was last flushed, so it can lag by that much.
func (s *Server) FlushSeen() error {
	s.seenMu.Lock()
	batch := s.seen
	s.seen = make(map[string]time.Time, len(batch))
	s.seenMu.Unlock()
	return s.store.TouchSessions(batch)
}

// Prune forgets stale rate-limit and ban entries. Call it periodically.
func (s *Server) Prune() {
	s.pairLimit.Prune()
	s.userLimit.Prune()
	s.ipLimit.Prune()
	s.opts.Banner.Prune()
}

// hostname drops the port from a canonical host[:port].
func hostname(h string) string {
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		return h[:i]
	}
	return h
}

func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

func (s *Server) scheme() string {
	if s.opts.Insecure {
		return "http"
	}
	return "https"
}

// SetConfig replaces the active config. The caller must have validated it.
// It fails if a tab would live on the auth host.
func (s *Server) SetConfig(cfg tabs.Config) error {
	gated := map[string]bool{s.portalHost: true}
	// Browsers send a host's cookies to every port on it, so each gated
	// host needs a hostname of its own, and none may be the auth host's:
	// otherwise an app's backend would receive the auth cookie or another
	// host's gate.
	names := map[string]string{hostname(s.portalHost): s.portalHost}
	var origins []string
	for _, t := range cfg.Tabs {
		h := t.Host()
		if h == "" {
			continue
		}
		if hostname(h) == hostname(s.authHost) {
			return fmt.Errorf("tab %q: may not be served from the auth host's hostname %s", t.Slug, hostname(s.authHost))
		}
		if other, ok := names[hostname(h)]; ok && other != h {
			return fmt.Errorf("tab %q: %s shares a hostname with %s on another port; cookies would be shared", t.Slug, h, other)
		}
		names[hostname(h)] = h
		if !gated[h] {
			gated[h] = true
			origins = append(origins, s.scheme()+"://"+h)
		}
	}
	frameSrc := strings.Join(append([]string{"'self'"}, cfg.FrameOrigins()...), " ")
	formTargets := strings.Join(append([]string{"'self'", s.portal}, origins...), " ")
	st := &state{
		cfg:        cfg,
		gated:      gated,
		tabOrigins: origins,
		// connect-src 'self' is only for the page's session check. The
		// logout form posts here and is then redirected to the auth host.
		portalCSP: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
			"frame-src " + frameSrc + "; base-uri 'none'; form-action 'self' " + s.authOrigin + "; frame-ancestors 'none'",
		// No scripts at all. Browsers apply form-action to the redirects
		// after a POST, and login ends with a redirect to a gated host.
		authCSP: "default-src 'none'; style-src 'self'; img-src 'self' data:; base-uri 'none'; " +
			"form-action " + formTargets + "; frame-ancestors 'none'",
		appCSP: "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
	}
	s.state.Store(st)
	return nil
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

func (s *Server) trustedAddr(a netip.Addr) bool {
	for _, p := range s.opts.Trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// fromTrustedProxy reports whether the connection comes from a trusted
// proxy address.
func (s *Server) fromTrustedProxy(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && s.trustedAddr(ap.Addr().Unmap())
}

// clientIP is the address used for bans, rate limits and logs: the
// connection's address, or, when that is a trusted proxy, the rightmost
// X-Forwarded-For entry that isn't one.
func (s *Server) clientIP(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		return host
	}
	addr := ap.Addr().Unmap()
	if !s.trustedAddr(addr) {
		return addr.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage: stop rather than trust what's left of it
		}
		a = a.Unmap()
		if !s.trustedAddr(a) {
			return a.String()
		}
		addr = a
	}
	return addr.String()
}

// limitKey is the client address as bans and rate limits see it: IPv4 as
// is, IPv6 by its /64, since one subscriber usually gets a whole /64 and
// could otherwise rotate addresses to dodge a ban.
func (s *Server) limitKey(r *http.Request) string {
	ip := s.clientIP(r)
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is4() {
		return ip
	}
	p, err := a.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// maxInFlight is how many password or code checks may run at once for one
// address or one username. Failures are only counted once a check ends,
// so without this a parallel burst could get many guesses in before the
// limits and ban saw any of them.
const maxInFlight = 2

// acquire reserves a check slot for every key, or none if any is full.
func (s *Server) acquire(keys ...string) bool {
	s.flightMu.Lock()
	defer s.flightMu.Unlock()
	for _, k := range keys {
		if s.inFlight[k] >= maxInFlight {
			return false
		}
	}
	for _, k := range keys {
		s.inFlight[k]++
	}
	return true
}

func (s *Server) release(keys ...string) {
	s.flightMu.Lock()
	defer s.flightMu.Unlock()
	for _, k := range keys {
		if s.inFlight[k]--; s.inFlight[k] <= 0 {
			delete(s.inFlight, k)
		}
	}
}

// ServeHTTP routes by host, then by exact path or prefix. It does not use
// http.ServeMux so that unclean paths (containing "..") are rejected with
// 404, not redirected.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	info := &reqInfo{}
	r = r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, info))
	st := s.state.Load()
	host := tabs.CanonicalHost(r.Host)

	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	// Other sites can't embed or probe anything here (e.g. /_tabs/session
	// as a logged-in oracle), whatever the cookie's SameSite setting.
	h.Set("Cross-Origin-Resource-Policy", "same-origin")

	defer func() {
		// Successful forward-auth checks are most of the traffic (apps
		// poll), so they're only logged at debug level.
		level := slog.LevelInfo
		if r.URL.Path == pathVerify && rec.status == http.StatusOK {
			level = slog.LevelDebug
		}
		s.log.Log(r.Context(), level, "request",
			"method", r.Method,
			"host", host,
			"path", redactPath(r.URL.Path),
			"status", rec.status,
			"duration", time.Since(start),
			"user", info.user,
			"ip", s.clientIP(r),
		)
	}()

	// Limit and parse every form body up front, before any handler can
	// read a form value: FormValue would otherwise parse an unlimited body
	// and cache it for every later check.
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(rec, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			h.Set("Content-Security-Policy", st.appCSP)
			http.Error(rec, "bad request", http.StatusBadRequest)
			return
		}
	}

	p := r.URL.Path
	switch {
	case p == pathHealthz:
		if !allow(rec, r, "GET", "HEAD") {
			return
		}
		h.Set("Content-Security-Policy", st.appCSP)
		h.Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(rec, "ok")
	case p == pathVerify:
		// Caddy's forward_auth keeps the original Host, so this can arrive
		// under any gated host; it only ever answers trusted proxies.
		h.Set("Content-Security-Policy", st.appCSP)
		s.serveVerify(rec, r, st)
	case host == s.authHost:
		h.Set("Content-Security-Policy", st.authCSP)
		h.Set("Referrer-Policy", "no-referrer")
		s.routeAuth(rec, r, st)
	case host == s.portalHost:
		h.Set("Content-Security-Policy", st.portalCSP)
		h.Set("Referrer-Policy", "same-origin")
		s.routePortal(rec, r, st, host)
	case st.gated[host]:
		h.Set("Content-Security-Policy", st.appCSP)
		h.Set("Referrer-Policy", "no-referrer")
		s.routeApp(rec, r, st, host)
	default:
		h.Set("Content-Security-Policy", st.appCSP)
		http.NotFound(rec, r)
	}
}

// allow answers 405 unless r.Method is one of methods.
func allow(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (s *Server) routeAuth(w http.ResponseWriter, r *http.Request, st *state) {
	p := r.URL.Path
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case p == "/":
		if allow(w, r, "GET", "HEAD") {
			http.Redirect(w, r, s.portal+"/", http.StatusSeeOther)
		}
	case strings.HasPrefix(p, prefixStatic):
		if allow(w, r, "GET", "HEAD") {
			w.Header().Set("Cache-Control", "no-cache")
			serveFile(w, r, s.static, strings.TrimPrefix(p, prefixStatic))
		}
	case p == pathLogin:
		s.serveLogin(w, r, st)
	case p == pathLoginTOTP:
		s.serveLoginTOTP(w, r, st)
	case p == pathLogout:
		s.serveAuthLogout(w, r)
	case p == pathLoggedOut:
		s.serveLoggedOut(w, r, st)
	case p == pathAccount:
		s.serveAccount(w, r, st)
	case p == pathSetup:
		s.serveSetup(w, r, st)
	case p == pathInvite || strings.HasPrefix(p, pathInvite+"/"):
		s.serveInvite(w, r, st)
	case p == pathReset || strings.HasPrefix(p, pathReset+"/"):
		s.serveReset(w, r, st)
	case p == pathHandoff:
		s.serveHandoff(w, r, st)
	case p == pathAdmin || strings.HasPrefix(p, pathAdmin+"/"):
		s.serveAdmin(w, r, st)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) routePortal(w http.ResponseWriter, r *http.Request, st *state, host string) {
	p := r.URL.Path
	switch {
	case p == "/":
		if allow(w, r, "GET", "HEAD") {
			s.serveIndex(w, r, st, host)
		}
	case p == pathSession:
		if allow(w, r, "GET", "HEAD") {
			s.serveSession(w, r, host)
		}
	case p == pathLogout:
		if allow(w, r, "POST") {
			s.servePortalLogout(w, r, host)
		}
	case p == pathAuthStart || p == pathCallback:
		s.routeApp(w, r, st, host)
	case strings.HasPrefix(p, prefixStatic):
		if allow(w, r, "GET", "HEAD") {
			// Embedded files have no mtime, so make browsers refetch after upgrades.
			w.Header().Set("Cache-Control", "no-cache")
			serveFile(w, r, s.static, strings.TrimPrefix(p, prefixStatic))
		}
	case strings.HasPrefix(p, prefixIcons):
		if !allow(w, r, "GET", "HEAD") {
			return
		}
		name := strings.TrimPrefix(p, prefixIcons)
		ct, ok := tabs.IconContentType(name)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ct)
		serveFile(w, r, s.icons, name)
	default:
		http.NotFound(w, r)
	}
}

// routeApp serves the two routes every gated host has.
func (s *Server) routeApp(w http.ResponseWriter, r *http.Request, st *state, host string) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case pathAuthStart:
		if allow(w, r, "GET", "HEAD") {
			s.serveStart(w, r, host)
		}
	case pathCallback:
		if allow(w, r, "GET") {
			s.serveCallback(w, r, st, host)
		}
	default:
		http.NotFound(w, r)
	}
}

// redactPath keeps link tokens out of logs.
func redactPath(p string) string {
	for _, pre := range []string{pathInvite + "/", pathReset + "/"} {
		if strings.HasPrefix(p, pre) {
			return pre + "REDACTED"
		}
	}
	return p
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

func setLogUser(r *http.Request, user string) {
	if info, _ := r.Context().Value(reqInfoKey{}).(*reqInfo); info != nil {
		info.user = user
	}
}

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
