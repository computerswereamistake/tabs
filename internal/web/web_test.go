package web

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
	"github.com/computerswereamistake/tabs/internal/tabs"
)

const (
	authBase   = "https://auth.example.com"
	portalBase = "https://tabs.example.com"
	betaBase   = "https://beta.example.com"
	proxyAddr  = "10.1.2.3:4567" // the trusted reverse proxy
	clientIP   = "198.51.100.7"
)

type env struct {
	t     *testing.T
	s     *Server
	st    *store.Store
	box   *auth.SecretBox
	now   time.Time
	setup string
}

func testConfig() tabs.Config {
	return tabs.Config{
		Title: "Media",
		Tabs: []tabs.Tab{
			{Slug: "alpha", Name: "Alpha", URL: "/alpha/", Icon: "alpha.svg", Groups: []string{"users"}},
			{Slug: "beta", Name: "Beta", URL: betaBase + "/", Icon: "beta.svg", Groups: []string{"admins"}},
			{Slug: "gamma", Name: "Gamma", URL: "/gamma/"},
		},
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "tabs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	k, _ := auth.NewKey()
	key, _ := auth.ParseKey(k)
	box, _ := auth.NewSecretBox(key)
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	e := &env{t: t, st: st, box: box, now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), setup: "setup-token-value"}
	au, _ := url.Parse(authBase)
	pu, _ := url.Parse(portalBase)
	icons := fstest.MapFS{
		"alpha.svg":     {Data: []byte("<svg/>")},
		"sub/inner.svg": {Data: []byte("<svg/>")},
		"phish.html":    {Data: []byte("<h1>log in</h1>")},
	}
	cfg := testConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	e.s, err = New(cfg, st, Options{
		AuthURL: au, PublicURL: pu, Trusted: trusted,
		SessionIdle: 24 * time.Hour, SessionMax: 7 * 24 * time.Hour,
		Box: box, Banner: auth.NewBanner(10, 15*time.Minute, time.Hour),
		SetupToken: e.setup, Now: func() time.Time { return e.now },
	}, icons, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"users", "admins"} {
		if err := st.CreateGroup(store.Group{Name: g}); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// user creates an account with password "password-for-<name>".
func (e *env) user(name string, admin bool, groups ...string) store.User {
	e.t.Helper()
	h, err := auth.HashPassword("password-for-" + name)
	if err != nil {
		e.t.Fatal(err)
	}
	u := &store.User{Username: name, Name: strings.ToUpper(name[:1]) + name[1:], PasswordHash: h, Admin: admin, Groups: groups}
	if err := e.st.CreateUser(u); err != nil {
		e.t.Fatal(err)
	}
	return *u
}

// browser is a minimal cookie-keeping client that talks to the handler
// directly. Requests come through the trusted proxy with the browser's IP
// in X-Forwarded-For, as Caddy would send them.
type browser struct {
	e       *env
	ip      string
	cookies map[string]map[string]string // host -> name -> value
	last    *httptest.ResponseRecorder
	lastURL string
}

func (e *env) browser() *browser {
	return &browser{e: e, ip: clientIP, cookies: map[string]map[string]string{}}
}

func (b *browser) request(method, rawURL string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		b.e.t.Fatal(err)
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, rawURL, body)
	req.RemoteAddr = proxyAddr
	req.Header.Set("X-Forwarded-For", b.ip)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
	for name, v := range b.cookies[u.Host] {
		req.AddCookie(&http.Cookie{Name: name, Value: v})
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rr := httptest.NewRecorder()
	b.e.s.ServeHTTP(rr, req)
	for _, c := range rr.Result().Cookies() {
		if b.cookies[u.Host] == nil {
			b.cookies[u.Host] = map[string]string{}
		}
		if c.MaxAge < 0 {
			delete(b.cookies[u.Host], c.Name)
		} else {
			b.cookies[u.Host][c.Name] = c.Value
		}
	}
	b.last, b.lastURL = rr, rawURL
	return rr
}

// follow does a request and follows redirects, returning the final response.
func (b *browser) follow(method, rawURL string, form url.Values) *httptest.ResponseRecorder {
	b.e.t.Helper()
	rr := b.request(method, rawURL, form, nil)
	for i := 0; i < 15 && rr.Code >= 300 && rr.Code < 400; i++ {
		next, err := url.Parse(b.lastURL)
		if err != nil {
			b.e.t.Fatal(err)
		}
		loc, err := next.Parse(rr.Header().Get("Location"))
		if err != nil {
			b.e.t.Fatal(err)
		}
		rr = b.request("GET", loc.String(), nil, nil)
	}
	return rr
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// csrf returns the CSRF token from the last page.
func (b *browser) csrf() string {
	b.e.t.Helper()
	m := csrfRE.FindStringSubmatch(b.last.Body.String())
	if m == nil {
		b.e.t.Fatalf("no csrf token on %s:\n%s", b.lastURL, b.last.Body.String())
	}
	return m[1]
}

// login logs in through the portal like a real visit and returns the
// final response (the sidebar on success).
func (b *browser) login(name, password string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	rr := b.follow("GET", portalBase+"/", nil)
	if !strings.Contains(b.lastURL, pathLogin) {
		return rr
	}
	next := mustQuery(b.e.t, b.lastURL).Get("next")
	return b.follow("POST", authBase+pathLogin, url.Values{"username": {name}, "password": {password}, "next": {next}})
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// verify asks forward_auth's question for tab on host, carrying the
// browser's cookies for that host.
func (b *browser) verify(tab, host string, hdr map[string]string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	h := map[string]string{"X-Forwarded-Host": host, "X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/x/?q=1"}
	for k, v := range hdr {
		h[k] = v
	}
	saved := b.cookies["verify"]
	b.cookies["verify"] = b.cookies[tabs.CanonicalHost(host)]
	defer func() { b.cookies["verify"] = saved }()
	return b.request("GET", "https://verify"+pathVerify+"?tab="+tab, nil, h)
}

func (e *env) totpCode(u store.User, at time.Time) string {
	e.t.Helper()
	got, err := e.st.UserByID(u.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	secret, err := e.box.Open(got.ID, got.TOTPSecret)
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := auth.TOTPCodeAt(secret, at)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// enrol turns on TOTP for the browser's logged-in user and returns the
// recovery codes shown.
func (b *browser) enrol(u store.User) []string {
	b.e.t.Helper()
	b.follow("GET", authBase+pathAccount, nil)
	b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"totp-begin"}, "current": {"password-for-" + u.Username}}, nil)
	m := regexp.MustCompile(`<code class="secret">([^<]+)</code>`).FindStringSubmatch(b.last.Body.String())
	if m == nil {
		b.e.t.Fatalf("no secret shown:\n%s", b.last.Body.String())
	}
	code, _ := auth.TOTPCodeAt(strings.ReplaceAll(m[1], " ", ""), b.e.now)
	rr := b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"totp-confirm"}, "code": {code}}, nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Recovery codes") {
		b.e.t.Fatalf("enrol confirm: %d\n%s", rr.Code, rr.Body.String())
	}
	var codes []string
	for _, m := range regexp.MustCompile(`<li><code>([A-Z0-9-]+)</code></li>`).FindAllStringSubmatch(rr.Body.String(), -1) {
		codes = append(codes, m[1])
	}
	if len(codes) != auth.RecoveryCodeCount {
		b.e.t.Fatalf("got %d recovery codes", len(codes))
	}
	b.e.now = b.e.now.Add(30 * time.Second) // the enrol code's step is used
	return codes
}

// --- tests ---

func TestSetup(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	if rr := b.follow("GET", authBase+pathSetup, nil); rr.Code != http.StatusForbidden {
		t.Fatalf("setup without token = %d", rr.Code)
	}
	b.follow("GET", authBase+pathSetup+"?token=wrong", nil)
	if b.last.Code != http.StatusForbidden {
		t.Fatalf("wrong token = %d", b.last.Code)
	}
	rr := b.follow("GET", authBase+pathSetup+"?token="+e.setup, nil)
	if rr.Code != http.StatusOK || !strings.HasSuffix(b.lastURL, pathSetup) {
		t.Fatalf("token swap: %d at %s", rr.Code, b.lastURL)
	}
	form := url.Values{"username": {"Root"}, "name": {"Root"}, "password": {"a long enough password"}, "confirm": {"a long enough password"}}
	if rr := b.request("POST", authBase+pathSetup, form, nil); rr.Code != http.StatusOK {
		t.Fatalf("setup POST = %d\n%s", rr.Code, rr.Body.String())
	}
	u, err := e.st.UserByName("root")
	if err != nil || !u.Admin {
		t.Fatalf("admin not created: %v %+v", err, u)
	}
	if rr := b.request("POST", authBase+pathSetup, form, nil); rr.Code != http.StatusNotFound {
		t.Errorf("second setup = %d", rr.Code)
	}
}

func TestLoginHandoffAndSidebar(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false, "users")
	b := e.browser()

	rr := b.follow("GET", portalBase+"/", nil)
	if !strings.HasPrefix(b.lastURL, authBase+pathLogin) || rr.Code != http.StatusOK {
		t.Fatalf("anonymous / ended at %s (%d)", b.lastURL, rr.Code)
	}
	if rr := b.login("bob", "wrong password!"); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), badLogin) {
		t.Fatalf("bad password: %d", rr.Code)
	}
	rr = b.login("BOB", "password-for-bob")
	if rr.Code != http.StatusOK || b.lastURL != portalBase+"/" {
		t.Fatalf("login ended at %s (%d)\n%s", b.lastURL, rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{`data-slug="alpha"`, `data-slug="gamma"`, authBase + pathAccount, `action="/_tabs/logout"`} {
		if !strings.Contains(body, want) {
			t.Errorf("sidebar missing %q", want)
		}
	}
	if strings.Contains(body, "beta") || strings.Contains(body, "/_tabs/admin") {
		t.Error("sidebar shows an admin tab or link to a non-admin")
	}
	if rr := b.request("GET", portalBase+pathSession, nil, nil); rr.Code != http.StatusNoContent {
		t.Errorf("session check = %d", rr.Code)
	}
	// The gate cookie is per host; the auth cookie never reaches the portal.
	if _, ok := b.cookies["tabs.example.com"]["__Host-tabs_auth"]; ok {
		t.Error("auth cookie set on the portal host")
	}
	if _, ok := b.cookies["auth.example.com"]["__Host-tabs_gate"]; ok {
		t.Error("gate cookie set on the auth host")
	}
}

// A deep link into an app survives the trip through login, query and all.
// A code evicted by other sign-ins restarts the flow once instead of failing.
func TestCallbackRetriesMissingCode(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	rr := b.request("GET", portalBase+pathCallback+"?code=gone", nil, nil)
	if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), pathAuthStart+"?retry=1") {
		t.Errorf("missing code: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if rr := b.request("GET", portalBase+pathCallback+"?code=gone&retry=1", nil, nil); rr.Code != http.StatusBadRequest {
		t.Errorf("missing code on retry = %d", rr.Code)
	}
}

func TestDeepLinkSurvivesLogin(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false, "users")
	b := e.browser()
	rr := b.verify("alpha", "tabs.example.com", map[string]string{"Sec-Fetch-Mode": "navigate", "X-Forwarded-Uri": "/alpha/deep/page?x=1&y=%2F"})
	b.follow("GET", rr.Header().Get("Location"), nil)
	next := mustQuery(t, b.lastURL).Get("next")
	if !strings.HasPrefix(next, pathHandoff+"?") {
		t.Fatalf("login page lost the handoff: %s", b.lastURL)
	}
	b.follow("POST", authBase+pathLogin, url.Values{"username": {"bob"}, "password": {"password-for-bob"}, "next": {next}})
	if want := portalBase + "/alpha/deep/page?x=1&y=%2F"; b.lastURL != want {
		t.Errorf("landed on %s, want %s", b.lastURL, want)
	}
}

func TestCleanPath(t *testing.T) {
	for in, ok := range map[string]bool{
		"/a/b?rd=%2Fx%2Fy": true,
		"/a%2fb":           false,
		"/a%5Cb":           false,
		"/a?x=%00":         false,
		"//evil":           false,
		"/a\\b":            false,
		"/a\nb":            false,
		"https://x/":       false,
	} {
		if _, got := cleanPath(in); got != ok {
			t.Errorf("cleanPath(%q) ok = %v, want %v", in, got, ok)
		}
	}
}

func TestCookieAttributes(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false)
	b := e.browser()
	b.follow("GET", portalBase+"/", nil)
	next := mustQuery(t, b.lastURL).Get("next")
	rr := b.request("POST", authBase+pathLogin, url.Values{"username": {"bob"}, "password": {"password-for-bob"}, "next": {next}}, nil)
	for _, c := range rr.Result().Cookies() {
		if !strings.HasPrefix(c.Name, "__Host-") || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %s: %+v", c.Name, c)
		}
	}
}

func TestVerify(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false, "users")
	e.user("ann", true, "admins")
	bob := e.browser()
	bob.login("bob", "password-for-bob")

	tests := []struct {
		name, tab, host string
		hdr             map[string]string
		want            int
	}{
		{"allowed", "alpha", "tabs.example.com", nil, http.StatusOK},
		{"no groups", "gamma", "tabs.example.com", nil, http.StatusOK},
		{"not in group", "beta", "beta.example.com", map[string]string{"Sec-Fetch-Mode": "navigate"}, http.StatusFound}, // no gate there yet
		{"host doesn't match the tab", "beta", "tabs.example.com", nil, http.StatusForbidden},
		{"unknown tab", "nope", "tabs.example.com", nil, http.StatusForbidden},
		{"host case and dot", "alpha", "TABS.example.com.", nil, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := bob.verify(tt.tab, tt.host, tt.hdr)
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d", rr.Code, tt.want)
			}
			if tt.want == http.StatusOK {
				if rr.Header().Get("Remote-User") != "bob" || rr.Header().Get("Remote-Groups") != "users" || rr.Header().Get("Remote-Name") != "Bob" {
					t.Errorf("identity headers %v", rr.Header())
				}
			}
		})
	}

	t.Run("untrusted caller", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://tabs.example.com"+pathVerify+"?tab=alpha", nil)
		req.RemoteAddr = "203.0.113.9:1"
		req.Header.Set("X-Forwarded-Host", "tabs.example.com")
		rr := httptest.NewRecorder()
		e.s.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d", rr.Code)
		}
	})
	t.Run("anonymous page load redirects to start", func(t *testing.T) {
		anon := e.browser()
		rr := anon.verify("alpha", "tabs.example.com", map[string]string{"Sec-Fetch-Mode": "navigate", "X-Forwarded-Uri": "/alpha/page?x=1"})
		want := portalBase + pathAuthStart + "?rd=" + url.QueryEscape("/alpha/page?x=1")
		if rr.Code != http.StatusFound || rr.Header().Get("Location") != want {
			t.Errorf("got %d %q", rr.Code, rr.Header().Get("Location"))
		}
	})
	t.Run("anonymous subresource gets 401", func(t *testing.T) {
		anon := e.browser()
		if rr := anon.verify("alpha", "tabs.example.com", map[string]string{"Sec-Fetch-Mode": "cors"}); rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d", rr.Code)
		}
	})
	t.Run("repeated forwarded host", func(t *testing.T) {
		saved := bob.cookies["verify"]
		bob.cookies["verify"] = bob.cookies["tabs.example.com"]
		defer func() { bob.cookies["verify"] = saved }()
		req := httptest.NewRequest(http.MethodGet, "https://verify"+pathVerify+"?tab=alpha", nil)
		req.RemoteAddr = proxyAddr
		req.Header.Add("X-Forwarded-Host", "tabs.example.com")
		req.Header.Add("X-Forwarded-Host", "evil.example.com")
		for n, v := range bob.cookies["verify"] {
			req.AddCookie(&http.Cookie{Name: n, Value: v})
		}
		rr := httptest.NewRecorder()
		e.s.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d", rr.Code)
		}
	})

	// An admin gets a gate on beta's own host by following the redirect.
	ann := e.browser()
	ann.login("ann", "password-for-ann")
	rr := ann.verify("beta", "beta.example.com", map[string]string{"Sec-Fetch-Mode": "navigate"})
	ann.follow("GET", rr.Header().Get("Location"), nil)
	if !strings.HasPrefix(ann.lastURL, betaBase+"/x/") {
		t.Fatalf("handoff to beta ended at %s (%d)", ann.lastURL, ann.last.Code)
	}
	if rr := ann.verify("beta", "beta.example.com", nil); rr.Code != http.StatusOK {
		t.Errorf("admin on beta = %d", rr.Code)
	}
	// A gate for one host is useless on another.
	ann.cookies["tabs.example.com"] = ann.cookies["beta.example.com"]
	if rr := ann.verify("gamma", "tabs.example.com", nil); rr.Code == http.StatusOK {
		t.Error("beta's gate accepted on the portal")
	}
}

func TestRevocationIsImmediate(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false, "users")
	b := e.browser()
	b.login("bob", "password-for-bob")
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
	// Removing the group takes effect on the next request.
	_, _ = e.st.UpdateUser(bob.ID, func(u *store.User) error { u.Groups = nil; return nil })
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code != http.StatusForbidden {
		t.Errorf("after group removal = %d", rr.Code)
	}
	// Disabling ends everything.
	_, _ = e.st.UpdateUser(bob.ID, func(u *store.User) error { u.Disabled = true; return nil })
	if rr := b.verify("gamma", "tabs.example.com", nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("after disable = %d", rr.Code)
	}
	if rr := b.request("GET", portalBase+pathSession, nil, nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("session after disable = %d", rr.Code)
	}
}

func TestPortalLogout(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false, "users")
	b := e.browser()
	rr := b.login("bob", "password-for-bob")
	csrf := csrfRE.FindStringSubmatch(rr.Body.String())[1]
	// Without the token (e.g. a form on another page) nothing happens.
	if rr := b.request("POST", portalBase+pathLogout, url.Values{"csrf": {"nope"}}, nil); rr.Code != http.StatusForbidden {
		t.Errorf("logout with bad csrf = %d", rr.Code)
	}
	if rr := b.request("POST", portalBase+pathLogout, url.Values{"csrf": {csrf}}, map[string]string{"Origin": "https://evil.example.com"}); rr.Code != http.StatusForbidden {
		t.Errorf("cross-origin logout = %d", rr.Code)
	}
	gate := b.cookies["tabs.example.com"]["__Host-tabs_gate"]
	b.follow("POST", portalBase+pathLogout, url.Values{"csrf": {csrf}})
	if b.lastURL != authBase+pathLoggedOut {
		t.Fatalf("logout ended at %s", b.lastURL)
	}
	if _, ok := b.cookies["auth.example.com"]["__Host-tabs_auth"]; ok {
		t.Error("auth cookie survived logout")
	}
	// The old gate is dead even if replayed.
	b.cookies["tabs.example.com"] = map[string]string{"__Host-tabs_gate": gate}
	if rr := b.verify("gamma", "tabs.example.com", nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("replayed gate after logout = %d", rr.Code)
	}
}

func TestCallbackStateBinding(t *testing.T) {
	e := newEnv(t)
	e.user("mallory", false, "users")
	e.user("victim", false, "users")
	m := e.browser()
	m.login("mallory", "password-for-mallory")
	// Mallory starts a flow and stops before the callback.
	m.request("GET", portalBase+pathAuthStart+"?rd=/alpha/", nil, nil)
	m.follow("GET", m.last.Header().Get("Location"), nil) // handoff → callback?code=...
	_ = m
	// Re-run without following the callback, to capture the code.
	m.request("GET", portalBase+pathAuthStart+"?rd=/alpha/", nil, nil)
	m.request("GET", m.last.Header().Get("Location"), nil, nil)
	callback := m.last.Header().Get("Location")
	if !strings.Contains(callback, pathCallback+"?code=") {
		t.Fatalf("no callback: %s", callback)
	}
	// The victim, who never started that flow, opens Mallory's link.
	v := e.browser()
	v.follow("GET", callback, nil)
	if strings.HasPrefix(v.lastURL, portalBase+"/alpha/") || v.cookies["tabs.example.com"]["__Host-tabs_gate"] != "" {
		t.Fatal("victim was logged in with someone else's code")
	}
	// A code works once.
	if rr := m.request("GET", callback, nil, nil); rr.Code == http.StatusSeeOther {
		t.Error("code worked after being tried")
	}
}

func TestRedirectTargets(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false)
	b := e.browser()
	for _, next := range []string{"//evil.example.com/", "https://evil.example.com/", `/\evil.example.com`, "/_tabs/login", "javascript:alert(1)", "/%2f%2fevil"} {
		b.cookies = map[string]map[string]string{}
		rr := b.request("POST", authBase+pathLogin, url.Values{"username": {"bob"}, "password": {"password-for-bob"}, "next": {next}}, nil)
		if loc := rr.Header().Get("Location"); loc != portalBase+"/" {
			t.Errorf("next=%q redirected to %q", next, loc)
		}
	}
	for _, rd := range []string{"https://evil.example.com/", "//evil.example.com", "/_tabs/admin/users", `/\x`} {
		rr := b.request("GET", portalBase+pathAuthStart+"?rd="+url.QueryEscape(rd), nil, nil)
		if got := mustQuery(t, rr.Header().Get("Location")).Get("rd"); got != "/" {
			t.Errorf("rd=%q became %q", rd, got)
		}
	}
	// The handoff only sends codes to gated hosts.
	for _, host := range []string{"evil.example.com", "auth.example.com", "tabs.example.com@evil.example.com", "TABS.EXAMPLE.COM"} {
		rr := b.request("GET", authBase+pathHandoff+"?host="+url.QueryEscape(host)+"&flow=abcdefghijkl&state=s&rd=/", nil, nil)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("handoff to %q = %d", host, rr.Code)
		}
	}
}

func TestTOTPLogin(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false, "users")
	b := e.browser()
	b.login("bob", "password-for-bob")
	recovery := b.enrol(bob)

	// Enrolling ended the old gate.
	if rr := b.request("GET", portalBase+pathSession, nil, nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("old gate after enrol = %d", rr.Code)
	}

	c := e.browser()
	c.login("bob", "password-for-bob")
	if !strings.HasPrefix(c.lastURL, authBase+pathLoginTOTP) {
		t.Fatalf("no TOTP step: %s", c.lastURL)
	}
	totpURL, csrf := c.lastURL, c.csrf()
	// A pending session can't reach the account page.
	if rr := c.request("GET", authBase+pathAccount, nil, nil); rr.Code != http.StatusSeeOther {
		t.Errorf("account while pending = %d", rr.Code)
	}
	next := mustQuery(t, totpURL).Get("next")
	code := e.totpCode(bob, e.now)
	c.follow("POST", authBase+pathLoginTOTP, url.Values{"csrf": {csrf}, "code": {code}, "next": {next}})
	if c.lastURL != portalBase+"/" {
		t.Fatalf("after TOTP: %s (%d)\n%s", c.lastURL, c.last.Code, c.last.Body.String())
	}

	// The same code can't be used again, even by a fresh login.
	d := e.browser()
	d.login("bob", "password-for-bob")
	if rr := d.request("POST", authBase+pathLoginTOTP, url.Values{"csrf": {d.csrf()}, "code": {code}}, nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("replayed code = %d", rr.Code)
	}
	// A recovery code works once.
	if rr := d.request("POST", authBase+pathLoginTOTP, url.Values{"csrf": {d.csrf()}, "code": {strings.ToLower(recovery[0])}}, nil); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "9 left") {
		t.Fatalf("recovery code: %d\n%s", rr.Code, rr.Body.String())
	}
	f := e.browser()
	f.login("bob", "password-for-bob")
	if rr := f.request("POST", authBase+pathLoginTOTP, url.Values{"csrf": {f.csrf()}, "code": {recovery[0]}}, nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("reused recovery code = %d", rr.Code)
	}
}

func TestVoluntaryEnrolNeedsPassword(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false)
	b := e.browser()
	b.login("bob", "password-for-bob")
	b.follow("GET", authBase+pathAccount, nil)
	rr := b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"totp-begin"}}, nil)
	if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), `class="secret"`) {
		t.Errorf("enrolment without the password: %d", rr.Code)
	}
}

func TestTOTPAttemptCap(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false)
	b := e.browser()
	b.login("bob", "password-for-bob")
	b.enrol(bob)
	c := e.browser()
	c.login("bob", "password-for-bob")
	csrf := c.csrf()
	for i := range maxTOTPAttempts {
		rr := c.request("POST", authBase+pathLoginTOTP, url.Values{"csrf": {csrf}, "code": {"000000"}}, nil)
		if i == maxTOTPAttempts-1 && !strings.Contains(rr.Body.String(), "Too many wrong codes") {
			t.Fatalf("attempt %d: %d %s", i, rr.Code, rr.Body.String())
		}
	}
	// The pending session is gone; a right code no longer helps.
	rr := c.request("POST", authBase+pathLoginTOTP, url.Values{"csrf": {csrf}, "code": {e.totpCode(bob, e.now)}}, nil)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != pathLogin {
		t.Errorf("after cap: %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestGroupRequiresTOTP(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false, "users")
	b := e.browser()
	b.login("bob", "password-for-bob")
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
	if err := e.st.UpdateGroup(store.Group{Name: "users", RequireTOTP: true}); err != nil {
		t.Fatal(err)
	}
	// Existing sessions are confined at once.
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code == http.StatusOK {
		t.Error("unenrolled member passed verify after the group required TOTP")
	}
	b.follow("GET", authBase+pathAdmin+"/users", nil)
	if !strings.HasPrefix(b.lastURL, authBase+pathAccount) || !strings.Contains(b.last.Body.String(), "Set up two-factor login") {
		t.Errorf("not sent to enrol: %s", b.lastURL)
	}
	// Even forced enrolment needs the password: this session logged in
	// before the group started requiring TOTP.
	if rr := b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"totp-begin"}}, nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("forced enrolment without the password = %d", rr.Code)
	}
	// Only enrolment is allowed in this state.
	if rr := b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"profile"}, "name": {"x"}}, nil); rr.Code != http.StatusForbidden {
		t.Errorf("profile edit while must-enrol = %d", rr.Code)
	}
	b.enrol(bob)
	// Turning it off is refused while the group requires it.
	b.follow("GET", authBase+pathAccount, nil)
	rr := b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"totp-disable"}, "current": {"password-for-bob"}, "code": {e.totpCode(bob, e.now)}}, nil)
	if rr.Code != http.StatusForbidden {
		t.Errorf("disable while required = %d", rr.Code)
	}
}

func TestMustChangePassword(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false, "users")
	_, _ = e.st.UpdateUser(bob.ID, func(u *store.User) error { u.MustChangePassword = true; return nil })
	b := e.browser()
	b.login("bob", "password-for-bob")
	if !strings.HasPrefix(b.lastURL, authBase+pathAccount) || !strings.Contains(b.last.Body.String(), "Choose a new password") {
		t.Fatalf("not sent to change password: %s", b.lastURL)
	}
	next, csrf := mustQuery(t, b.lastURL).Get("next"), b.csrf()
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code == http.StatusOK {
		t.Error("verify passed before the password was changed")
	}
	b.follow("POST", authBase+pathAccount, url.Values{
		"csrf": {csrf}, "action": {"password"}, "current": {"password-for-bob"},
		"new": {"my own new password"}, "confirm": {"my own new password"}, "next": {next},
	})
	if b.lastURL != portalBase+"/" {
		t.Fatalf("after change: %s (%d)\n%s", b.lastURL, b.last.Code, b.last.Body.String())
	}
}

func TestAdminAccess(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false, "users")
	e.user("ann", true)
	bob := e.browser()
	bob.login("bob", "password-for-bob")
	for _, p := range []string{"/users", "/users/1", "/groups", "/invites", "/bans"} {
		if rr := bob.request("GET", authBase+pathAdmin+p, nil, nil); rr.Code != http.StatusForbidden {
			t.Errorf("non-admin GET %s = %d", p, rr.Code)
		}
	}
	ann := e.browser()
	ann.login("ann", "password-for-ann")
	ann.follow("GET", authBase+pathAdmin+"/users", nil)
	if ann.last.Code != http.StatusOK {
		t.Fatalf("admin users page = %d", ann.last.Code)
	}
	csrf := ann.csrf()
	create := url.Values{"csrf": {csrf}, "action": {"create"}, "username": {"carol"}}
	if rr := ann.request("POST", authBase+pathAdmin+"/users", url.Values{"action": {"create"}, "username": {"carol"}}, nil); rr.Code != http.StatusForbidden {
		t.Errorf("POST without csrf = %d", rr.Code)
	}
	if rr := ann.request("POST", authBase+pathAdmin+"/users", create, map[string]string{"Origin": portalBase}); rr.Code != http.StatusForbidden {
		t.Errorf("POST from the portal origin = %d", rr.Code)
	}
	if rr := ann.request("POST", authBase+pathAdmin+"/users", create, map[string]string{"Origin": ""}); rr.Code != http.StatusForbidden {
		t.Errorf("POST without Origin = %d", rr.Code)
	}
	rr := ann.request("POST", authBase+pathAdmin+"/users", create, nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), authBase+pathReset+"/") {
		t.Fatalf("create user: %d\n%s", rr.Code, rr.Body.String())
	}
	// None of the auth pages exist on the portal or app hosts, so a framed
	// same-origin app can't script them.
	for _, base := range []string{portalBase, betaBase} {
		for _, p := range []string{pathAdmin + "/users", pathLogin, pathAccount, pathSetup, pathInvite, pathHandoff} {
			if rr := ann.request("GET", base+p, nil, nil); rr.Code != http.StatusNotFound {
				t.Errorf("GET %s%s = %d", base, p, rr.Code)
			}
		}
	}
}

func TestAdminSelfDemotionKeepsOneAdmin(t *testing.T) {
	e := newEnv(t)
	ann := e.user("ann", true)
	b := e.browser()
	b.login("ann", "password-for-ann")
	b.follow("GET", authBase+pathAdmin+"/users/"+itoa(ann.ID), nil)
	rr := b.request("POST", authBase+pathAdmin+"/users/"+itoa(ann.ID), url.Values{"csrf": {b.csrf()}, "action": {"save"}, "name": {"Ann"}}, nil)
	if !strings.Contains(rr.Body.String(), "no enabled admin") {
		t.Errorf("last admin demoted themselves: %d", rr.Code)
	}
}

func TestInvite(t *testing.T) {
	e := newEnv(t)
	e.user("ann", true)
	a := e.browser()
	a.login("ann", "password-for-ann")
	a.follow("GET", authBase+pathAdmin+"/invites", nil)
	rr := a.request("POST", authBase+pathAdmin+"/invites", url.Values{
		"csrf": {a.csrf()}, "action": {"create"}, "groups": {"users"}, "hours": {"24"}, "uses": {"1"}, "note": {"Welcome"},
	}, nil)
	m := regexp.MustCompile(`https://auth\.example\.com/_tabs/invite/[A-Za-z0-9_-]+`).FindString(rr.Body.String())
	if m == "" {
		t.Fatalf("no invite link:\n%s", rr.Body.String())
	}

	n := e.browser()
	n.follow("GET", m, nil)
	if n.lastURL != authBase+pathInvite || !strings.Contains(n.last.Body.String(), "Welcome") {
		t.Fatalf("invite page: %s %d", n.lastURL, n.last.Code)
	}
	if strings.Contains(n.lastURL, "/invite/") {
		t.Error("token still in the URL")
	}
	weak := url.Values{"username": {"newbie"}, "password": {"short"}, "confirm": {"short"}}
	if rr := n.request("POST", authBase+pathInvite, weak, nil); rr.Code != http.StatusBadRequest {
		t.Errorf("weak password = %d", rr.Code)
	}
	n.follow("POST", authBase+pathInvite, url.Values{"username": {"newbie"}, "name": {"New"}, "password": {"a good long password"}, "confirm": {"a good long password"}})
	if n.lastURL != portalBase+"/" || !strings.Contains(n.last.Body.String(), `data-slug="alpha"`) {
		t.Fatalf("after invite: %s %d", n.lastURL, n.last.Code)
	}
	u, _ := e.st.UserByName("newbie")
	if u.Admin || len(u.Groups) != 1 || u.Groups[0] != "users" {
		t.Errorf("invited user = %+v", u)
	}
	again := e.browser()
	if rr := again.follow("GET", m, nil); rr.Code != http.StatusNotFound {
		t.Errorf("used invite = %d", rr.Code)
	}
}

func TestResetLink(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false)
	tok, _ := auth.NewToken()
	_ = e.st.CreateReset(store.Reset{Hash: auth.HashToken(tok), UserID: bob.ID, ExpiresAt: e.now.Add(time.Hour)})
	b := e.browser()
	b.follow("GET", authBase+pathReset+"/"+tok, nil)
	if b.lastURL != authBase+pathReset {
		t.Fatalf("reset page at %s", b.lastURL)
	}
	rr := b.request("POST", authBase+pathReset, url.Values{"password": {"brand new password"}, "confirm": {"brand new password"}}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("reset: %d", rr.Code)
	}
	if rr := e.browser().login("bob", "brand new password"); rr.Code != http.StatusOK {
		t.Errorf("login with new password = %d", rr.Code)
	}
	if rr := b.request("POST", authBase+pathReset, url.Values{"password": {"another password!"}, "confirm": {"another password!"}}, nil); rr.Code != http.StatusNotFound {
		t.Errorf("reset link reused = %d", rr.Code)
	}
}

func TestBanAndLock(t *testing.T) {
	e := newEnv(t)
	e.s.opts.LockAfter = 3
	bob := e.user("bob", false)
	b := e.browser()
	for range 3 {
		b.request("POST", authBase+pathLogin, url.Values{"username": {"bob"}, "password": {"wrong password"}}, nil)
		e.now = e.now.Add(time.Hour) // step past the backoff
	}
	if u, _ := e.st.UserByID(bob.ID); !u.Locked {
		t.Fatal("account not locked after 3 failures")
	}
	if rr := e.browser().login("bob", "password-for-bob"); rr.Code != http.StatusUnauthorized {
		t.Errorf("locked account logged in: %d", rr.Code)
	}

	// Ten failures from one address within the window bans it outright.
	e.s.opts.LockAfter = 0
	m := e.browser()
	m.ip = "203.0.113.50"
	for i := range 10 {
		m.request("POST", authBase+pathLogin, url.Values{"username": {"user" + itoa(uint64(i))}, "password": {"x"}}, nil)
	}
	if rr := m.request("POST", authBase+pathLogin, url.Values{"username": {"bob"}, "password": {"password-for-bob"}}, nil); rr.Code != http.StatusTooManyRequests {
		t.Errorf("banned address = %d", rr.Code)
	}
	if bans := e.s.opts.Banner.Bans(); len(bans) != 1 || bans[0].IP != "203.0.113.50" {
		t.Errorf("bans = %v", bans)
	}
}

func TestClientIP(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:1", "1.2.3.4", "203.0.113.9"}, // untrusted: XFF ignored
		{proxyAddr, "1.2.3.4", "1.2.3.4"},           // via proxy
		{proxyAddr, "6.6.6.6, 1.2.3.4", "1.2.3.4"},  // spoofed left entry ignored
		{proxyAddr, "1.2.3.4, 10.9.9.9", "1.2.3.4"}, // inner proxy skipped
		{proxyAddr, "", "10.1.2.3"},                 // no header
		{proxyAddr, "garbage, 1.2.3.4", "1.2.3.4"},  // rightmost good entry
		{"[::ffff:10.0.0.5]:80", "2001:db8::1", "2001:db8::1"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tt.remote
		if tt.xff != "" {
			req.Header.Set("X-Forwarded-For", tt.xff)
		}
		if got := e.s.clientIP(req); got != tt.want {
			t.Errorf("clientIP(%s, %q) = %s, want %s", tt.remote, tt.xff, got, tt.want)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	portalCSP := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"frame-src 'self' https://beta.example.com; base-uri 'none'; form-action 'self' https://auth.example.com; frame-ancestors 'none'"
	authCSP := "default-src 'none'; style-src 'self'; img-src 'self' data:; base-uri 'none'; " +
		"form-action 'self' https://tabs.example.com https://beta.example.com; frame-ancestors 'none'"
	for _, tt := range []struct{ url, csp, referrer string }{
		{portalBase + "/", portalCSP, "same-origin"},
		{portalBase + "/_tabs/static/app.css", portalCSP, "same-origin"},
		{portalBase + "/nope", portalCSP, "same-origin"},
		{authBase + pathLogin, authCSP, "no-referrer"},
		{authBase + "/nope", authCSP, "no-referrer"},
	} {
		rr := b.request("GET", tt.url, nil, nil)
		h := rr.Header()
		if got := h.Get("Content-Security-Policy"); got != tt.csp {
			t.Errorf("%s CSP = %q", tt.url, got)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cross-Origin-Resource-Policy") != "same-origin" {
			t.Errorf("%s missing headers", tt.url)
		}
		if got := h.Get("Referrer-Policy"); got != tt.referrer {
			t.Errorf("%s Referrer-Policy = %q", tt.url, got)
		}
	}
	if rr := b.request("GET", authBase+pathLogin, nil, nil); !strings.Contains(rr.Header().Get("Cache-Control"), "no-store") {
		t.Error("login page cacheable")
	}
}

func TestRoutes(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	tests := []struct {
		method, url string
		want        int
	}{
		{"GET", portalBase + "/_tabs/healthz", http.StatusOK},
		{"GET", "https://unknown.example.com/_tabs/healthz", http.StatusOK},
		{"HEAD", portalBase + "/_tabs/healthz", http.StatusOK},
		{"GET", "https://unknown.example.com/", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/static/app.js", http.StatusOK},
		{"GET", portalBase + "/_tabs/static/app.css", http.StatusOK},
		{"GET", authBase + "/_tabs/static/app.css", http.StatusOK},
		{"GET", portalBase + "/_tabs/static/", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/static/missing.js", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/icons/alpha.svg", http.StatusOK},
		{"GET", portalBase + "/_tabs/icons/", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/icons/sub", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/icons/../tabs.yaml", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/icons/%2e%2e/tabs.yaml", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/icons/..%2ftabs.yaml", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/icons/..%5ctabs.yaml", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/static/../../web.go", http.StatusNotFound},
		{"GET", portalBase + "/_tabs/icons/phish.html", http.StatusNotFound},
		{"GET", portalBase + "/other-app/", http.StatusNotFound},
		{"GET", betaBase + "/", http.StatusNotFound},
		{"GET", betaBase + "/_tabs/icons/alpha.svg", http.StatusNotFound},
		{"POST", portalBase + "/", http.StatusMethodNotAllowed},
		{"PUT", portalBase + "/_tabs/healthz", http.StatusMethodNotAllowed},
		{"DELETE", portalBase + "/_tabs/icons/alpha.svg", http.StatusMethodNotAllowed},
		{"GET", portalBase + "/", http.StatusFound}, // to start
		{"GET", authBase + "/", http.StatusSeeOther},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.url, func(t *testing.T) {
			if rr := b.request(tt.method, tt.url, nil, nil); rr.Code != tt.want {
				t.Errorf("status = %d, want %d", rr.Code, tt.want)
			}
		})
	}
}

func TestIndexEscapesName(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false)
	_, _ = e.st.UpdateUser(bob.ID, func(u *store.User) error { u.Name = `<script>alert(1)</script>`; return nil })
	rr := e.browser().login("bob", "password-for-bob")
	body := rr.Body.String()
	if strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("name not escaped")
	}
}

func TestIndexEmptyState(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false)
	if err := e.s.SetConfig(tabs.Config{Title: "T", Tabs: []tabs.Tab{{Slug: "a", Name: "A", URL: "/a/", Groups: []string{"admins"}}}}); err != nil {
		t.Fatal(err)
	}
	if rr := e.browser().login("bob", "password-for-bob"); !strings.Contains(rr.Body.String(), "No apps are available") {
		t.Error("empty-state message missing")
	}
}

func TestSetConfigRejectsSharedHostnames(t *testing.T) {
	e := newEnv(t)
	for _, u := range []string{
		authBase + "/app/",
		"https://auth.example.com:8443/", // cookies ignore ports
		"https://tabs.example.com:8443/", // would share the portal's gate
	} {
		if err := e.s.SetConfig(tabs.Config{Title: "T", Tabs: []tabs.Tab{{Slug: "a", Name: "A", URL: u}}}); err == nil {
			t.Errorf("tab at %s accepted", u)
		}
	}
	err := e.s.SetConfig(tabs.Config{Title: "T", Tabs: []tabs.Tab{
		{Slug: "a", Name: "A", URL: "https://app.example.com/"},
		{Slug: "b", Name: "B", URL: "https://app.example.com:8443/"},
	}})
	if err == nil {
		t.Error("two tab hosts sharing a hostname accepted")
	}
}

func TestNewRejectsSharedHostname(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "tabs.db"))
	defer st.Close()
	au, _ := url.Parse("https://example.com:8443")
	pu, _ := url.Parse("https://example.com")
	_, err := New(testConfig(), st, Options{AuthURL: au, PublicURL: pu}, fstest.MapFS{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Error("auth and portal on one hostname accepted")
	}
}

func TestOversizedFormRefused(t *testing.T) {
	e := newEnv(t)
	e.user("bob", false)
	b := e.browser()
	big := url.Values{"username": {"bob"}, "password": {"password-for-bob"}, "pad": {strings.Repeat("x", maxFormBytes)}}
	if rr := b.request("POST", authBase+pathLogin, big, nil); rr.Code != http.StatusBadRequest {
		t.Errorf("oversized login = %d", rr.Code)
	}
	if _, ok := b.cookies["auth.example.com"]["__Host-tabs_auth"]; ok {
		t.Error("oversized login logged in")
	}
}

func TestRedactPath(t *testing.T) {
	for in, want := range map[string]string{
		"/_tabs/invite/secret": "/_tabs/invite/REDACTED",
		"/_tabs/reset/secret":  "/_tabs/reset/REDACTED",
		"/_tabs/login":         "/_tabs/login",
	} {
		if got := redactPath(in); got != want {
			t.Errorf("redactPath(%q) = %q", in, got)
		}
	}
}

func TestParseTrustedProxies(t *testing.T) {
	ps, err := ParseTrustedProxies(" 172.16.0.0/12 , ,fd00::/8,127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 {
		t.Fatalf("got %d prefixes", len(ps))
	}
	for _, bad := range []string{"nope", "10.0.0.0/33", "1.2.3", "0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

func TestLimitKeyGroupsIPv6(t *testing.T) {
	e := newEnv(t)
	for xff, want := range map[string]string{
		"2001:db8:1:2:aaaa::1": "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::9": "2001:db8:1:2::/64",
		"198.51.100.7":         "198.51.100.7",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = proxyAddr
		req.Header.Set("X-Forwarded-For", xff)
		if got := e.s.limitKey(req); got != want {
			t.Errorf("limitKey(%s) = %s, want %s", xff, got, want)
		}
	}
	// Rotating addresses inside one /64 still gets banned.
	b := e.browser()
	for i := range 10 {
		b.ip = fmt.Sprintf("2001:db8:1:2::%x", i+1)
		b.request("POST", authBase+pathLogin, url.Values{"username": {"nobody"}, "password": {"x"}}, nil)
		e.now = e.now.Add(time.Minute) // past the backoff
	}
	b.ip = "2001:db8:1:2::ffff"
	if rr := b.request("POST", authBase+pathLogin, url.Values{"username": {"x"}, "password": {"y"}}, nil); rr.Code != http.StatusTooManyRequests {
		t.Errorf("rotated /64 address = %d", rr.Code)
	}
}

func TestInFlightCap(t *testing.T) {
	e := newEnv(t)
	for i := range maxInFlight {
		if !e.s.acquire("1.2.3.4", "u:bob") {
			t.Fatalf("slot %d refused", i)
		}
	}
	if e.s.acquire("1.2.3.4", "u:ann") || e.s.acquire("5.6.7.8", "u:bob") {
		t.Error("third concurrent check allowed")
	}
	e.s.release("1.2.3.4", "u:bob")
	if !e.s.acquire("1.2.3.4", "u:ann") {
		t.Error("slot not freed")
	}
	e.s.release("1.2.3.4", "u:ann")
	e.s.release("1.2.3.4", "u:bob")
	if len(e.s.inFlight) != 0 {
		t.Errorf("leaked slots: %v", e.s.inFlight)
	}
	// Logins use per-address slots only, so a busy address elsewhere never
	// blocks a user's own login; and a login releases its slot.
	e.s.acquire("9.9.9.9")
	e.s.acquire("9.9.9.9")
	defer func() { e.s.release("9.9.9.9"); e.s.release("9.9.9.9") }()
	e.user("bob", false)
	if rr := e.browser().login("bob", "password-for-bob"); rr.Code != http.StatusOK {
		t.Fatalf("login while another address is busy = %d", rr.Code)
	}
	if len(e.s.inFlight) != 1 {
		t.Errorf("login leaked slots: %v", e.s.inFlight)
	}
}

func TestAdminsAreNeverLocked(t *testing.T) {
	e := newEnv(t)
	e.s.opts.LockAfter = 2
	ann := e.user("ann", true)
	b := e.browser()
	for range 3 {
		b.request("POST", authBase+pathLogin, url.Values{"username": {"ann"}, "password": {"wrong password"}}, nil)
		e.now = e.now.Add(time.Hour)
	}
	if u, _ := e.st.UserByID(ann.ID); u.Locked {
		t.Error("admin locked by failed logins")
	}
}

func TestLockedUserCantFinishTOTP(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false)
	b := e.browser()
	b.login("bob", "password-for-bob")
	b.enrol(bob)
	c := e.browser()
	c.login("bob", "password-for-bob") // now pending
	_, _ = e.st.UpdateUser(bob.ID, func(u *store.User) error { u.Locked = true; return nil })
	rr := c.request("POST", authBase+pathLoginTOTP, url.Values{"csrf": {c.csrf()}, "code": {e.totpCode(bob, e.now)}}, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("locked user passed the TOTP step: %d", rr.Code)
	}
}

func TestRecoveryRegenNeedsCode(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false)
	b := e.browser()
	b.login("bob", "password-for-bob")
	b.enrol(bob)
	b.follow("GET", authBase+pathAccount, nil)
	rr := b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"recovery"}, "current": {"password-for-bob"}}, nil)
	if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), "Recovery codes") {
		t.Errorf("recovery codes without a TOTP code: %d", rr.Code)
	}
	rr = b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"recovery"}, "current": {"password-for-bob"}, "code": {e.totpCode(bob, e.now)}}, nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Recovery codes") {
		t.Errorf("recovery codes with password and code: %d", rr.Code)
	}
}

func TestUsersCantSetTheirOwnEmail(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false)
	b := e.browser()
	b.login("bob", "password-for-bob")
	b.follow("GET", authBase+pathAccount, nil)
	b.request("POST", authBase+pathAccount, url.Values{"csrf": {b.csrf()}, "action": {"profile"}, "name": {"Bob"}, "email": {"ceo@example.com"}}, nil)
	if u, _ := e.st.UserByID(bob.ID); u.Email != "" || u.Name != "Bob" {
		t.Errorf("after profile save: name %q email %q", u.Name, u.Email)
	}
}

// Verify records activity in memory; the database is only written when the
// batch is flushed.
func TestVerifyDoesNotWrite(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", false, "users")
	b := e.browser()
	b.login("bob", "password-for-bob")
	if err := e.s.FlushSeen(); err != nil {
		t.Fatal(err)
	}
	ss, _ := e.st.UserSessions(bob.ID)
	before := ss[0].LastSeen
	e.now = e.now.Add(10 * time.Minute)
	for range 20 {
		if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code != http.StatusOK {
			t.Fatal(rr.Code)
		}
	}
	if ss, _ := e.st.UserSessions(bob.ID); !ss[0].LastSeen.Equal(before) {
		t.Error("verify wrote to the database")
	}
	if err := e.s.FlushSeen(); err != nil {
		t.Fatal(err)
	}
	if ss, _ := e.st.UserSessions(bob.ID); !ss[0].LastSeen.Equal(e.now) {
		t.Errorf("after flush LastSeen = %v, want %v", ss[0].LastSeen, e.now)
	}
}

// Activity that's only in memory (not flushed yet) still keeps a session
// from idling out.
func TestIdleCountsUnflushedActivity(t *testing.T) {
	e := newEnv(t) // idle timeout 24h
	e.user("bob", false, "users")
	b := e.browser()
	b.login("bob", "password-for-bob")
	if err := e.s.FlushSeen(); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(23 * time.Hour)
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code != http.StatusOK {
		t.Fatalf("at 23h = %d", rr.Code)
	}
	// Stored LastSeen is now 25h old, but the last use was 2h ago.
	e.now = e.now.Add(2 * time.Hour)
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code != http.StatusOK {
		t.Errorf("active session idled out before a flush: %d", rr.Code)
	}
	// Truly idle sessions still end.
	e.now = e.now.Add(25 * time.Hour)
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code == http.StatusOK {
		t.Error("idle session still valid")
	}
}

// A request that read the stored session just before a flush committed
// still sees the newer activity in memory.
func TestFlushKeepsActivityVisible(t *testing.T) {
	e := newEnv(t) // idle timeout 24h
	bob := e.user("bob", false, "users")
	b := e.browser()
	b.login("bob", "password-for-bob")
	if err := e.s.FlushSeen(); err != nil {
		t.Fatal(err)
	}
	ss, _ := e.st.UserSessions(bob.ID)
	stale := ss[0] // read "before the flush": LastSeen is login time
	e.now = e.now.Add(23 * time.Hour)
	b.verify("alpha", "tabs.example.com", nil) // activity, in memory only
	// Two flushes back to back (the minute and prune tickers coincide):
	// the entry must survive both.
	for range 2 {
		if err := e.s.FlushSeen(); err != nil {
			t.Fatal(err)
		}
	}
	if !e.s.idleOK(stale, e.now.Add(2*time.Hour)) {
		t.Error("activity vanished right after back-to-back flushes")
	}
	e.now = e.now.Add(2 * time.Hour) // stale LastSeen is 25h old; real activity 2h
	if !e.s.idleOK(stale, e.now) {
		t.Error("activity vanished after a flush")
	}
	// A later flush with no new activity drops the entry; the store has it.
	if err := e.s.FlushSeen(); err != nil {
		t.Fatal(err)
	}
	if len(e.s.seen) != 0 || len(e.s.flushed) != 0 {
		t.Errorf("cache not drained: seen %v, flushed %v", e.s.seen, e.s.flushed)
	}
	// And stays drained: further flushes don't resurrect anything.
	e.now = e.now.Add(time.Hour)
	_ = e.s.FlushSeen()
	if len(e.s.seen) != 0 || len(e.s.flushed) != 0 {
		t.Errorf("cache grew back: seen %v, flushed %v", e.s.seen, e.s.flushed)
	}
	if rr := b.verify("alpha", "tabs.example.com", nil); rr.Code != http.StatusOK {
		t.Errorf("after drain = %d", rr.Code)
	}
}

// An admin demoted while a request was in flight can't create users.
func TestDemotedAdminCantCreate(t *testing.T) {
	e := newEnv(t)
	ann := e.user("ann", true)
	e.user("root", true)
	b := e.browser()
	b.login("ann", "password-for-ann")
	b.follow("GET", authBase+pathAdmin+"/users", nil)
	csrf := b.csrf()
	// Simulate the demotion landing mid-request: the request's session was
	// loaded as an admin, but the write sees the change.
	ss, _ := e.st.UserSessions(ann.ID)
	a := &authed{sess: ss[0], user: ann, state: effFull}
	_, _ = e.st.UpdateUser(ann.ID, func(u *store.User) error { u.Admin = false; return nil })
	c := &adminCtx{w: httptest.NewRecorder(), r: httptest.NewRequest(http.MethodPost, "/", nil), a: a,
		db: e.st.As(store.Actor{SessionID: a.sess.ID, Admin: true})}
	c.r.PostForm = url.Values{"csrf": {csrf}, "action": {"create"}, "username": {"evil"}, "admin": {"on"}}
	rec := c.w.(*httptest.ResponseRecorder)
	if res := e.s.adminCreateUser(c); !res.written || rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != pathLogin {
		t.Errorf("result = %+v, response %d %q", res, rec.Code, rec.Header().Get("Location"))
	}
	if _, err := e.st.UserByName("evil"); err == nil {
		t.Error("demoted admin created an account")
	}
}
