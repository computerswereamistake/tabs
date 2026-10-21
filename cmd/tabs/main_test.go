package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeConfig(t *testing.T, path, title string) {
	t.Helper()
	cfg := "title: " + title + "\ntabs:\n  - slug: one\n    name: One\n    url: /one/\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

type fixture struct {
	dir, cfg, icons string
	env             map[string]string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{dir: dir, cfg: filepath.Join(dir, "tabs.yaml"), icons: filepath.Join(dir, "icons")}
	if err := os.Mkdir(f.icons, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, f.cfg, "First")
	f.env = map[string]string{
		"TABS_CONFIG":          f.cfg,
		"TABS_ICONS_DIR":       f.icons,
		"TABS_LISTEN":          "127.0.0.1:0",
		"TABS_TRUSTED_PROXIES": "127.0.0.1",
	}
	return f
}

func (f *fixture) deps(sigs chan os.Signal) deps {
	return deps{
		getenv: func(k string) string { return f.env[k] },
		sigs:   sigs,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestRunStartupErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fixture)
		want   string
	}{
		{"no trusted proxies", func(f *fixture) { delete(f.env, "TABS_TRUSTED_PROXIES") }, "TABS_TRUSTED_PROXIES is required"},
		{"blank trusted proxies", func(f *fixture) { f.env["TABS_TRUSTED_PROXIES"] = " , " }, "no entries"},
		{"bad trusted proxies", func(f *fixture) { f.env["TABS_TRUSTED_PROXIES"] = "nope" }, "TABS_TRUSTED_PROXIES"},
		{"trust everyone", func(f *fixture) { f.env["TABS_TRUSTED_PROXIES"] = "0.0.0.0/0" }, "every address"},
		{"missing config", func(f *fixture) { f.env["TABS_CONFIG"] = filepath.Join(f.dir, "nope.yaml") }, "nope.yaml"},
		{"invalid config", func(f *fixture) { os.WriteFile(f.cfg, []byte("tabs: []\n"), 0o600) }, "at least one tab"},
		{"missing icons dir", func(f *fixture) { f.env["TABS_ICONS_DIR"] = filepath.Join(f.dir, "nope") }, "icons dir"},
		{"bad listen address", func(f *fixture) { f.env["TABS_LISTEN"] = "not-an-address" }, "not-an-address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.mutate(f)
			err := run(f.deps(make(chan os.Signal)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

var titleRE = regexp.MustCompile(`<title>([^<]*)</title>`)

func getTitle(t *testing.T, base string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Header.Set("Remote-User", "bob")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	m := titleRE.FindSubmatch(body)
	if m == nil {
		t.Fatal("no <title> in page")
	}
	return string(m[1])
}

// TestRunLifecycle starts the real server, reloads good and bad config via
// SIGHUP, probes it with the healthcheck subcommand, then shuts it down.
func TestRunLifecycle(t *testing.T) {
	f := newFixture(t)
	sigs := make(chan os.Signal)
	addrc := make(chan net.Addr, 1)
	reloads := make(chan error)
	d := f.deps(sigs)
	d.onListen = func(a net.Addr) { addrc <- a }
	d.onReload = func(err error) { reloads <- err }

	done := make(chan error, 1)
	go func() { done <- run(d) }()

	var addr net.Addr
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatalf("run exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	base := "http://" + addr.String()

	if err := healthcheck(addr.String()); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
	if got := getTitle(t, base); got != "First" {
		t.Fatalf("title = %q, want First", got)
	}

	writeConfig(t, f.cfg, "Second")
	sigs <- syscall.SIGHUP
	if err := <-reloads; err != nil {
		t.Fatalf("good reload failed: %v", err)
	}
	if got := getTitle(t, base); got != "Second" {
		t.Fatalf("after reload title = %q, want Second", got)
	}

	if err := os.WriteFile(f.cfg, []byte("title: Broken\nbogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sigs <- syscall.SIGHUP
	if err := <-reloads; err == nil {
		t.Fatal("bad reload reported success")
	}
	if got := getTitle(t, base); got != "Second" {
		t.Fatalf("after bad reload title = %q, want previous config kept", got)
	}

	// Drop the test client's keep-alive connections so Shutdown has nothing
	// to wait out.
	http.DefaultClient.CloseIdleConnections()
	sigs <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
	if err := healthcheck(addr.String()); err == nil {
		t.Fatal("healthcheck passed after shutdown")
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_tabs/healthz" {
			http.NotFound(w, r)
		}
	}))
	defer ok.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer failing.Close()

	_, okPort, _ := net.SplitHostPort(ok.Listener.Addr().String())
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()

	tests := []struct {
		name, listen string
		wantErr      bool
	}{
		{"healthy", ok.Listener.Addr().String(), false},
		{"any-address listen dials loopback", ":" + okPort, false},
		{"unspecified IPv4 dials loopback", "0.0.0.0:" + okPort, false},
		{"unhealthy", failing.Listener.Addr().String(), true},
		{"nothing listening", closedAddr, true},
		{"malformed listen", "nope", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := healthcheck(tt.listen); (err != nil) != tt.wantErr {
				t.Errorf("healthcheck(%q) err = %v, wantErr %v", tt.listen, err, tt.wantErr)
			}
		})
	}
}
