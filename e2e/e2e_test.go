// Package e2e runs tabs as a real process and drives it with a real,
// headless Chrome (signup.mjs), covering what in-process handler tests
// can't: how a browser actually sends Origin, Referer and cookies.
package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSignupInBrowser needs Node (22+, for its built-in WebSocket) and
// Chrome or Chromium. Locally it skips when either is missing; in CI (CI
// is set by GitHub Actions) that's a failure, so the test can't silently
// stop running. TABS_E2E_CHROME overrides where Chrome is found.
func TestSignupInBrowser(t *testing.T) {
	node, err := exec.LookPath("node")
	if err == nil {
		// The script needs Node's built-in WebSocket (Node 22+).
		if exec.Command(node, "-e", "process.exit(typeof WebSocket === 'function' ? 0 : 1)").Run() != nil {
			err = fmt.Errorf("%s has no built-in WebSocket; Node 22 or newer is needed", node)
		}
	}
	chrome := findChrome()
	if err != nil || chrome == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("Node 22+ and Chrome are required in CI (node: %v, chrome: %q)", err, chrome)
		}
		t.Skipf("skipping the browser test: needs Node 22+ and Chrome (node: %v, chrome: %q)", err, chrome)
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "tabs")
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/tabs").CombinedOutput(); err != nil {
		t.Fatalf("building tabs: %v\n%s", err, out)
	}
	key, err := exec.Command(bin, "genkey").Output()
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "tabs.key"), string(key))
	write(t, filepath.Join(dir, "tabs.yaml"), "title: E2E\ntabs:\n  - slug: app\n    name: App\n    url: /app/\n    groups: [users]\n")
	if err := os.Mkdir(filepath.Join(dir, "icons"), 0o755); err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	auth := fmt.Sprintf("http://auth.localhost:%d", port)
	portal := fmt.Sprintf("http://tabs.localhost:%d", port)
	srv := exec.Command(bin)
	srv.Env = append(os.Environ(),
		"TABS_LISTEN=127.0.0.1:"+fmt.Sprint(port),
		"TABS_AUTH_URL="+auth,
		"TABS_PUBLIC_URL="+portal,
		"TABS_INSECURE_COOKIES=1",
		"TABS_TRUSTED_PROXIES=127.0.0.1",
		"TABS_CONFIG="+filepath.Join(dir, "tabs.yaml"),
		"TABS_ICONS_DIR="+filepath.Join(dir, "icons"),
		"TABS_DB="+filepath.Join(dir, "tabs.db"),
		"TABS_SECRET_KEY_FILE="+filepath.Join(dir, "tabs.key"),
	)
	var logs strings.Builder
	srv.Stdout, srv.Stderr = &logs, &logs
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.Process.Kill()
		_ = srv.Wait()
		if t.Failed() {
			t.Logf("tabs log:\n%s", logs.String())
		}
	})
	waitHealthy(t, port)

	setup, err := os.ReadFile(filepath.Join(dir, "setup-token"))
	if err != nil {
		t.Fatalf("setup link: %v", err)
	}
	ctx := t.Context()
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline.Add(-10*time.Second))
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, node, "signup.mjs")
	// On the deadline, ask nicely first, so the script can shut Chrome
	// down; kill it outright only if it doesn't exit.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(os.Environ(), "CHROME="+chrome, "AUTH="+auth, "PORTAL="+portal, "SETUP="+strings.TrimSpace(string(setup)))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser test failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

func findChrome() string {
	if p := os.Getenv("TABS_E2E_CHROME"); p != "" {
		return p
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitHealthy(t *testing.T, port int) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/_tabs/healthz", port)
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if resp, err := http.Get(url); err == nil { // #nosec G107 -- local test server
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
	t.Fatal("tabs didn't become healthy")
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
