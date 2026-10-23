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

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
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
	out             strings.Builder
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{dir: dir, cfg: filepath.Join(dir, "tabs.yaml"), icons: filepath.Join(dir, "icons")}
	if err := os.Mkdir(f.icons, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, f.cfg, "First")
	key, _ := auth.NewKey()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.env = map[string]string{
		"TABS_CONFIG":           f.cfg,
		"TABS_ICONS_DIR":        f.icons,
		"TABS_LISTEN":           "127.0.0.1:0",
		"TABS_TRUSTED_PROXIES":  "127.0.0.1",
		"TABS_AUTH_URL":         "http://auth.localhost",
		"TABS_PUBLIC_URL":       "http://tabs.localhost",
		"TABS_INSECURE_COOKIES": "1",
		"TABS_DB":               filepath.Join(dir, "tabs.db"),
		"TABS_SECRET_KEY_FILE":  keyFile,
	}
	return f
}

func (f *fixture) deps(sigs chan os.Signal) deps {
	return deps{
		getenv: func(k string) string { return f.env[k] },
		sigs:   sigs,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		stdout: &f.out,
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
		{"no auth url", func(f *fixture) { delete(f.env, "TABS_AUTH_URL") }, "TABS_AUTH_URL is required"},
		{"auth url with path", func(f *fixture) { f.env["TABS_AUTH_URL"] = "http://auth.localhost/x" }, "bare"},
		{"https required", func(f *fixture) { delete(f.env, "TABS_INSECURE_COOKIES") }, "bare https://"},
		{"same host twice", func(f *fixture) { f.env["TABS_PUBLIC_URL"] = "http://AUTH.localhost" }, "different hostnames"},
		{"same hostname, other port", func(f *fixture) { f.env["TABS_PUBLIC_URL"] = "http://auth.localhost:8443" }, "different hostnames"},
		{"insecure off localhost", func(f *fixture) {
			f.env["TABS_AUTH_URL"] = "http://auth.example.com"
		}, "only allowed for localhost"},
		{"no key file", func(f *fixture) { delete(f.env, "TABS_SECRET_KEY_FILE") }, "TABS_SECRET_KEY_FILE is required"},
		{"bad key", func(f *fixture) { os.WriteFile(f.env["TABS_SECRET_KEY_FILE"], []byte("short"), 0o600) }, "32 bytes"},
		{"bad duration", func(f *fixture) { f.env["TABS_SESSION_IDLE"] = "soon" }, "TABS_SESSION_IDLE"},
		{"bad ban count", func(f *fixture) { f.env["TABS_BAN_AFTER"] = "-1" }, "TABS_BAN_AFTER"},
		{"db dir missing", func(f *fixture) { f.env["TABS_DB"] = filepath.Join(f.dir, "nope", "tabs.db") }, "database"},
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

// getTitle fetches the login page on the auth host.
func getTitle(t *testing.T, base string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/_tabs/login", nil)
	req.Host = "auth.localhost"
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
	backups := make(chan error)
	d := f.deps(sigs)
	d.onListen = func(a net.Addr) { addrc <- a }
	d.onReload = func(err error) { reloads <- err }
	d.onBackup = func(err error) { backups <- err }

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
	if got := getTitle(t, base); got != "Log in · First" {
		t.Fatalf("title = %q, want First", got)
	}
	// With no users yet, the setup link is in a file next to the database.
	link, err := os.ReadFile(filepath.Join(f.dir, "setup-token"))
	if err != nil || !strings.HasPrefix(string(link), "http://auth.localhost/_tabs/setup?token=") {
		t.Fatalf("setup-token file: %v %q", err, link)
	}

	writeConfig(t, f.cfg, "Second")
	sigs <- syscall.SIGHUP
	if err := <-reloads; err != nil {
		t.Fatalf("good reload failed: %v", err)
	}
	if got := getTitle(t, base); got != "Log in · Second" {
		t.Fatalf("after reload title = %q, want Second", got)
	}

	if err := os.WriteFile(f.cfg, []byte("title: Broken\nbogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sigs <- syscall.SIGHUP
	if err := <-reloads; err == nil {
		t.Fatal("bad reload reported success")
	}
	if got := getTitle(t, base); got != "Log in · Second" {
		t.Fatalf("after bad reload title = %q, want previous config kept", got)
	}

	sigs <- syscall.SIGUSR1
	if err := <-backups; err != nil {
		t.Fatalf("backup: %v", err)
	}
	if fi, err := os.Stat(f.env["TABS_DB"] + ".bak"); err != nil || fi.Size() == 0 {
		t.Fatalf("backup file: %v", err)
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

func TestWrongKeyRefused(t *testing.T) {
	f := newFixture(t)
	st, err := store.Open(f.env["TABS_DB"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadBox(f.env["TABS_SECRET_KEY_FILE"], st); err != nil {
		t.Fatal(err)
	}
	st.Close()
	other, _ := auth.NewKey()
	os.WriteFile(f.env["TABS_SECRET_KEY_FILE"], []byte(other), 0o600)
	if err := run(f.deps(make(chan os.Signal))); err == nil || !strings.Contains(err.Error(), "not the key") {
		t.Fatalf("err = %v", err)
	}
}

func TestRecoverAndRekey(t *testing.T) {
	f := newFixture(t)
	st, err := store.Open(f.env["TABS_DB"])
	if err != nil {
		t.Fatal(err)
	}
	box, err := loadBox(f.env["TABS_SECRET_KEY_FILE"], st)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "root", Admin: true, Locked: true}
	if err := st.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	sealed, _ := box.Seal(u.ID, "JBSWY3DPEHPK3PXP")
	_, _ = st.UpdateUser(u.ID, func(x *store.User) error { x.TOTPSecret = sealed; return nil })
	st.Close()

	d := f.deps(nil)
	if err := recoverCmd(d, []string{"nobody"}); err == nil {
		t.Error("recover of a missing user succeeded")
	}
	if err := recoverCmd(d, nil); err == nil {
		t.Error("recover without a username succeeded")
	}

	// Rekey to a new file; the old key then no longer starts the server.
	newKey, _ := auth.NewKey()
	newFile := filepath.Join(f.dir, "key2")
	os.WriteFile(newFile, []byte(newKey), 0o600)
	if err := rekeyCmd(d, []string{newFile}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "Re-encrypted 1 secrets") {
		t.Errorf("rekey output %q", f.out.String())
	}
	oldFile := f.env["TABS_SECRET_KEY_FILE"]
	f.env["TABS_SECRET_KEY_FILE"] = newFile
	st, _ = store.Open(f.env["TABS_DB"])
	box2, err := loadBox(newFile, st)
	if err != nil {
		t.Fatalf("new key refused: %v", err)
	}
	got, _ := st.UserByID(u.ID)
	if plain, err := box2.Open(u.ID, got.TOTPSecret); err != nil || plain != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("secret after rekey: %q %v", plain, err)
	}
	if _, err := loadBox(oldFile, st); err == nil {
		t.Error("old key still accepted")
	}
	st.Close()

	f.out.Reset()
	if err := recoverCmd(d, []string{"ROOT", "--reset-totp"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "http://auth.localhost/_tabs/reset/") {
		t.Errorf("recover output %q", f.out.String())
	}
	st, _ = store.Open(f.env["TABS_DB"])
	defer st.Close()
	got, _ = st.UserByID(u.ID)
	if got.Locked || got.HasTOTP() {
		t.Errorf("after recover: %+v", got)
	}
	var logged strings.Builder
	if err := logOffline(st, slog.New(slog.NewTextHandler(&logged, nil))); err != nil {
		t.Fatal(err)
	}
	if out := logged.String(); !strings.Contains(out, "rekey secrets=1") || !strings.Contains(out, "recover user=root reset-totp") {
		t.Errorf("offline audit log: %q", out)
	}
	if raw, _ := st.Meta(offlineAuditMeta); len(raw) != 0 {
		t.Error("offline audit not cleared after logging")
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
