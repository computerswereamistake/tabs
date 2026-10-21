package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/computerswereamistake/tabs/internal/tabs"
)

const trustedAddr = "10.1.2.3:4567"

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := tabs.Config{
		Title:     "Media",
		LogoutURL: "https://auth.example.com/logout",
		Tabs: []tabs.Tab{
			{Slug: "alpha", Name: "Alpha", URL: "/alpha/", Icon: "alpha.svg", Groups: []string{"users"}},
			{Slug: "beta", Name: "Beta", URL: "https://beta.example.com/", Icon: "beta.svg", Groups: []string{"admins"}},
			{Slug: "gamma", Name: "Gamma", URL: "/gamma/"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	trusted, err := ParseTrustedProxies("10.0.0.0/8, 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	icons := fstest.MapFS{
		"alpha.svg":     {Data: []byte("<svg/>")},
		"sub/inner.svg": {Data: []byte("<svg/>")},
	}
	return New(cfg, trusted, icons, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func do(s *Server, method, path, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func TestIndexAuth(t *testing.T) {
	s := testServer(t)
	tests := []struct {
		name   string
		remote string
		hdr    map[string]string
		want   int
	}{
		{"no headers", trustedAddr, nil, http.StatusUnauthorized},
		{"empty user", trustedAddr, map[string]string{"Remote-User": ""}, http.StatusUnauthorized},
		{"untrusted address", "203.0.113.9:1234", map[string]string{"Remote-User": "bob"}, http.StatusUnauthorized},
		{"untrusted with XFF", "203.0.113.9:1234", map[string]string{"Remote-User": "bob", "X-Forwarded-For": "10.0.0.1"}, http.StatusUnauthorized},
		{"trusted single IP", "192.0.2.1:80", map[string]string{"Remote-User": "bob"}, http.StatusOK},
		{"trusted v4-mapped v6", "[::ffff:10.0.0.5]:80", map[string]string{"Remote-User": "bob"}, http.StatusOK},
		{"trusted", trustedAddr, map[string]string{"Remote-User": "bob"}, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := do(s, "GET", "/", tt.remote, tt.hdr)
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d", rr.Code, tt.want)
			}
			if got := rr.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q", got)
			}
		})
	}
}

func TestIndexFiltersTabs(t *testing.T) {
	s := testServer(t)
	rr := do(s, "GET", "/", trustedAddr, map[string]string{"Remote-User": "bob", "Remote-Groups": "users, other"})
	body := rr.Body.String()
	for _, want := range []string{`data-slug="alpha"`, `data-slug="gamma"`, `"slug":"alpha"`, `https://auth.example.com/logout`} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Contains(body, "beta") {
		t.Error("body contains tab the viewer may not see")
	}
	if strings.Index(body, `data-slug="alpha"`) > strings.Index(body, `data-slug="gamma"`) {
		t.Error("tabs out of config order")
	}
}

func TestIndexEmptyState(t *testing.T) {
	s := testServer(t)
	s.SetConfig(tabs.Config{Title: "T", Tabs: []tabs.Tab{{Slug: "a", Name: "A", URL: "/a/", Groups: []string{"admins"}}}})
	rr := do(s, "GET", "/", trustedAddr, map[string]string{"Remote-User": "bob"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "No apps are available") {
		t.Error("empty-state message missing")
	}
}

func TestIndexEscapesName(t *testing.T) {
	s := testServer(t)
	rr := do(s, "GET", "/", trustedAddr, map[string]string{
		"Remote-User": `bob"><script>alert(1)</script>`,
		"Remote-Name": `<script>alert(1)</script>`,
	})
	body := rr.Body.String()
	if strings.Contains(body, "<script>alert") {
		t.Error("header value rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped name not found")
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := testServer(t)
	wantCSP := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"frame-src 'self' https://beta.example.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	for _, path := range []string{"/", "/_tabs/healthz", "/_tabs/static/app.css", "/nope"} {
		t.Run(path, func(t *testing.T) {
			rr := do(s, "GET", path, trustedAddr, map[string]string{"Remote-User": "bob"})
			h := rr.Header()
			if got := h.Get("Content-Security-Policy"); got != wantCSP {
				t.Errorf("CSP = %q", got)
			}
			if h.Get("X-Content-Type-Options") != "nosniff" {
				t.Error("missing nosniff")
			}
			if h.Get("Referrer-Policy") != "same-origin" {
				t.Error("missing Referrer-Policy")
			}
		})
	}
}

func TestRoutes(t *testing.T) {
	s := testServer(t)
	tests := []struct {
		method, path string
		want         int
	}{
		{"GET", "/_tabs/healthz", http.StatusOK},
		{"HEAD", "/_tabs/healthz", http.StatusOK},
		{"GET", "/_tabs/static/app.js", http.StatusOK},
		{"GET", "/_tabs/static/app.css", http.StatusOK},
		{"GET", "/_tabs/static/", http.StatusNotFound},
		{"GET", "/_tabs/static/missing.js", http.StatusNotFound},
		{"GET", "/_tabs/icons/alpha.svg", http.StatusOK},
		{"GET", "/_tabs/icons/", http.StatusNotFound},
		{"GET", "/_tabs/icons/sub", http.StatusNotFound},
		{"GET", "/_tabs/icons/../tabs.yaml", http.StatusNotFound},
		{"GET", "/_tabs/icons/%2e%2e/tabs.yaml", http.StatusNotFound},
		{"GET", "/_tabs/icons/..%2ftabs.yaml", http.StatusNotFound},
		{"GET", "/_tabs/icons/..%5ctabs.yaml", http.StatusNotFound},
		{"GET", "/_tabs/static/../../web.go", http.StatusNotFound},
		{"GET", "/other-app/", http.StatusNotFound},
		{"POST", "/", http.StatusMethodNotAllowed},
		{"PUT", "/_tabs/healthz", http.StatusMethodNotAllowed},
		{"DELETE", "/_tabs/icons/alpha.svg", http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			rr := do(s, tt.method, tt.path, "203.0.113.9:1", nil)
			if rr.Code != tt.want {
				t.Errorf("status = %d, want %d", rr.Code, tt.want)
			}
		})
	}
}

func TestStaticContentType(t *testing.T) {
	s := testServer(t)
	rr := do(s, "GET", "/_tabs/static/app.js", trustedAddr, nil)
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q", ct)
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
	for _, bad := range []string{"nope", "10.0.0.0/33", "1.2.3"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
