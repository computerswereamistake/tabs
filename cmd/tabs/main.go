// Command tabs serves a sidebar of apps, each loaded in an iframe, with its
// own users, groups, invites and two-factor login, and a forward-auth
// endpoint so the reverse proxy can gate each app on the same groups.
//
// Usage:
//
//	tabs                              run the server
//	tabs healthcheck                  GET /_tabs/healthz on the local listener; exit 0 or 1
//	tabs genkey                       print a new key for TABS_SECRET_KEY_FILE
//	tabs recover <user> [--reset-totp] print a one-hour password link (server stopped)
//	tabs rekey <new-key-file>         re-encrypt TOTP secrets under a new key (server stopped)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
	"github.com/computerswereamistake/tabs/internal/tabs"
	"github.com/computerswereamistake/tabs/internal/web"
)

// deps is what run needs from the outside world, so tests can supply their
// own environment, signals and observation hooks.
type deps struct {
	getenv   func(string) string
	sigs     <-chan os.Signal
	log      *slog.Logger
	stdout   io.Writer
	onListen func(net.Addr) // optional: called once listening
	onReload func(error)    // optional: called after each SIGHUP
}

func (d deps) env(key, def string) string {
	if v := d.getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	d := deps{getenv: os.Getenv, log: slog.New(slog.NewJSONHandler(os.Stderr, nil)), stdout: os.Stdout}

	if len(os.Args) > 1 {
		var err error
		switch os.Args[1] {
		case "healthcheck":
			err = healthcheck(d.env("TABS_LISTEN", ":8080"))
		case "genkey":
			var k string
			if k, err = auth.NewKey(); err == nil {
				fmt.Println(k)
			}
		case "recover":
			err = recoverCmd(d, os.Args[2:])
		case "rekey":
			err = rekeyCmd(d, os.Args[2:])
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	d.sigs = sigs

	if err := run(d); err != nil {
		d.log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// settings is the parsed environment shared by run and the subcommands.
type settings struct {
	authURL, publicURL *url.URL
	insecure           bool
	dbPath             string
}

func loadSettings(d deps) (settings, error) {
	st := settings{
		insecure: d.getenv("TABS_INSECURE_COOKIES") == "1",
		dbPath:   d.env("TABS_DB", "/data/tabs.db"),
	}
	var err error
	if st.authURL, err = originURL("TABS_AUTH_URL", d.getenv("TABS_AUTH_URL"), st.insecure); err != nil {
		return st, err
	}
	if st.publicURL, err = originURL("TABS_PUBLIC_URL", d.getenv("TABS_PUBLIC_URL"), st.insecure); err != nil {
		return st, err
	}
	if tabs.CanonicalHost(st.authURL.Host) == tabs.CanonicalHost(st.publicURL.Host) {
		return st, errors.New("TABS_AUTH_URL and TABS_PUBLIC_URL must be different hosts, so framed apps can't reach the admin pages")
	}
	return st, nil
}

// originURL parses an env var that must be a bare origin.
func originURL(name, v string, insecure bool) (*url.URL, error) {
	if v == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	u, err := url.Parse(strings.TrimSuffix(v, "/"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	want := "https"
	if insecure {
		want = "http"
	}
	if u.Scheme != want || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
		tabs.CanonicalHost(u.Host) == "" {
		return nil, fmt.Errorf("%s must be a bare %s:// origin like %s://tabs.example.com", name, want, want)
	}
	if insecure && !isLocalHost(u.Hostname()) {
		return nil, fmt.Errorf("TABS_INSECURE_COOKIES is only allowed for localhost, but %s is %s", name, u.Hostname())
	}
	return u, nil
}

func isLocalHost(h string) bool {
	h = strings.ToLower(h)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func duration(d deps, key string, def time.Duration) (time.Duration, error) {
	v := d.getenv(key)
	if v == "" {
		return def, nil
	}
	// Allow "7d" as well as Go durations like "168h".
	if n, ok := strings.CutSuffix(v, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("%s: %q is not a duration", key, v)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	t, err := time.ParseDuration(v)
	if err != nil || t <= 0 {
		return 0, fmt.Errorf("%s: %q is not a duration", key, v)
	}
	return t, nil
}

func integer(d deps, key string, def int) (int, error) {
	v := d.getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: %q is not a whole number", key, v)
	}
	return n, nil
}

const keyCheckMeta = "key-check"

// loadBox reads TABS_SECRET_KEY_FILE and checks it against the database:
// a wrong key fails startup instead of every two-factor login.
func loadBox(path string, st *store.Store) (*auth.SecretBox, error) {
	if path == "" {
		return nil, errors.New("TABS_SECRET_KEY_FILE is required (create one with `tabs genkey`)")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("TABS_SECRET_KEY_FILE: %w", err)
	}
	key, err := auth.ParseKey(string(raw))
	if err != nil {
		return nil, fmt.Errorf("TABS_SECRET_KEY_FILE: %w", err)
	}
	box, err := auth.NewSecretBox(key)
	if err != nil {
		return nil, err
	}
	if err := checkKey(box, st); err != nil {
		return nil, err
	}
	return box, nil
}

func checkKey(box *auth.SecretBox, st *store.Store) error {
	sentinel, err := st.Meta(keyCheckMeta)
	if err != nil {
		return err
	}
	if sentinel == nil {
		sealed, err := box.Seal(0, keyCheckMeta)
		if err != nil {
			return err
		}
		return st.SetMeta(keyCheckMeta, []byte(sealed))
	}
	if _, err := box.Open(0, string(sentinel)); err != nil {
		return errors.New("TABS_SECRET_KEY_FILE is not the key this database was created with")
	}
	return nil
}

func run(d deps) error {
	log := d.log
	listen := d.env("TABS_LISTEN", ":8080")
	cfgPath := d.env("TABS_CONFIG", "/config/tabs.yaml")
	iconsDir := d.env("TABS_ICONS_DIR", "/config/icons")

	set, err := loadSettings(d)
	if err != nil {
		return err
	}
	proxies := d.getenv("TABS_TRUSTED_PROXIES")
	if proxies == "" {
		return errors.New("TABS_TRUSTED_PROXIES is required")
	}
	trusted, err := web.ParseTrustedProxies(proxies)
	if err != nil {
		return fmt.Errorf("TABS_TRUSTED_PROXIES: %w", err)
	}
	if len(trusted) == 0 {
		return errors.New("TABS_TRUSTED_PROXIES has no entries")
	}
	idle, err := duration(d, "TABS_SESSION_IDLE", 7*24*time.Hour)
	if err != nil {
		return err
	}
	maxAge, err := duration(d, "TABS_SESSION_MAX", 30*24*time.Hour)
	if err != nil {
		return err
	}
	banAfter, err := integer(d, "TABS_BAN_AFTER", 10)
	if err != nil {
		return err
	}
	banWindow, err := duration(d, "TABS_BAN_WINDOW", 15*time.Minute)
	if err != nil {
		return err
	}
	banFor, err := duration(d, "TABS_BAN_DURATION", time.Hour)
	if err != nil {
		return err
	}
	lockAfter, err := integer(d, "TABS_LOCK_AFTER", 0)
	if err != nil {
		return err
	}

	cfg, err := tabs.Load(cfgPath)
	if err != nil {
		return err
	}

	// os.Root confines all icon opens to iconsDir, including via symlinks.
	root, err := os.OpenRoot(iconsDir)
	if err != nil {
		return fmt.Errorf("icons dir: %w", err)
	}
	defer root.Close()

	st, err := store.Open(set.dbPath)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()
	box, err := loadBox(d.getenv("TABS_SECRET_KEY_FILE"), st)
	if err != nil {
		return err
	}

	opts := web.Options{
		AuthURL: set.authURL, PublicURL: set.publicURL, Trusted: trusted, Insecure: set.insecure,
		SessionIdle: idle, SessionMax: maxAge, Box: box,
		Banner: auth.NewBanner(banAfter, banWindow, banFor), LockAfter: lockAfter,
	}
	if set.insecure {
		log.Warn("TABS_INSECURE_COOKIES is set: cookies work over plain HTTP. Never use this outside local development.")
	}

	// With no users yet, write a one-time setup link next to the database
	// rather than into the logs, so only someone with the volume can claim
	// the first admin.
	tokenFile := filepath.Join(filepath.Dir(set.dbPath), "setup-token")
	n, err := st.UserCount()
	if err != nil {
		return err
	}
	if n == 0 {
		tok, err := auth.NewToken()
		if err != nil {
			return err
		}
		link := set.authURL.String() + "/_tabs/setup?token=" + tok
		if err := os.WriteFile(tokenFile, []byte(link+"\n"), 0o600); err != nil {
			return fmt.Errorf("writing setup token: %w", err)
		}
		opts.SetupToken = tok
		opts.OnSetupDone = func() {
			if err := os.Remove(tokenFile); err != nil {
				log.Error("removing setup token file", "err", err)
			}
		}
		log.Warn("no users yet: open the setup link in " + tokenFile + " to create the first admin")
	} else if err := os.Remove(tokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Error("removing stale setup token file", "err", err)
	}

	app, err := web.New(cfg, st, opts, root.FS(), log)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Info("listening", "addr", ln.Addr().String(), "tabs", len(cfg.Tabs), "auth", set.authURL.String(), "portal", set.publicURL.String())
	if d.onListen != nil {
		d.onListen(ln.Addr())
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	prune := time.NewTicker(5 * time.Minute)
	defer prune.Stop()

	for {
		select {
		case err := <-errc:
			return err
		case <-prune.C:
			if err := st.Prune(time.Now(), idle); err != nil {
				log.Error("prune", "err", err)
			}
			app.Prune()
		case sig := <-d.sigs:
			if sig == syscall.SIGHUP {
				next, err := tabs.Load(cfgPath)
				if err == nil {
					err = app.SetConfig(next)
				}
				if err != nil {
					log.Error("reload failed; keeping previous config", "err", err)
				} else {
					log.Info("config reloaded", "tabs", len(next.Tabs))
				}
				if d.onReload != nil {
					d.onReload(err)
				}
				continue
			}
			log.Info("shutting down", "signal", sig.String())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(ctx)
		}
	}
}

// recoverCmd prints a one-hour password link for a user, unlocking the
// account and optionally clearing two-factor login. It opens the database
// directly, so the server must be stopped.
func recoverCmd(d deps, args []string) error {
	var name string
	resetTOTP := false
	for _, a := range args {
		switch {
		case a == "--reset-totp":
			resetTOTP = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag %q", a)
		case name == "":
			name = a
		default:
			return errors.New("usage: tabs recover <username> [--reset-totp]")
		}
	}
	if name == "" {
		return errors.New("usage: tabs recover <username> [--reset-totp]")
	}
	set, err := loadSettings(d)
	if err != nil {
		return err
	}
	st, err := store.Open(set.dbPath)
	if err != nil {
		return fmt.Errorf("database (is the server still running?): %w", err)
	}
	defer st.Close()
	u, err := st.UserByName(name)
	if err != nil {
		return fmt.Errorf("user %q: %w", name, err)
	}
	if u.Disabled {
		return fmt.Errorf("user %q is disabled", name)
	}
	if _, err := st.UpdateUser(u.ID, func(x *store.User) error {
		x.Locked = false
		if resetTOTP {
			x.TOTPSecret, x.TOTPLastStep, x.RecoveryHashes = "", 0, nil
		}
		return nil
	}); err != nil {
		return err
	}
	tok, err := auth.NewToken()
	if err != nil {
		return err
	}
	if err := st.CreateReset(store.Reset{Hash: auth.HashToken(tok), UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		return err
	}
	fmt.Fprintf(d.stdout, "Password link for %s (valid for one hour, works once):\n%s/_tabs/reset/%s\n", u.Username, set.authURL, tok)
	if resetTOTP {
		fmt.Fprintln(d.stdout, "Two-factor login was cleared.")
	}
	return nil
}

// rekeyCmd re-encrypts every TOTP secret from TABS_SECRET_KEY_FILE to a new
// key file in one transaction. The server must be stopped; afterwards point
// TABS_SECRET_KEY_FILE at the new file.
func rekeyCmd(d deps, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tabs rekey <new-key-file>")
	}
	set, err := loadSettings(d)
	if err != nil {
		return err
	}
	st, err := store.Open(set.dbPath)
	if err != nil {
		return fmt.Errorf("database (is the server still running?): %w", err)
	}
	defer st.Close()
	oldBox, err := loadBox(d.getenv("TABS_SECRET_KEY_FILE"), st)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	key, err := auth.ParseKey(string(raw))
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	newBox, err := auth.NewSecretBox(key)
	if err != nil {
		return err
	}
	sentinel, err := newBox.Seal(0, keyCheckMeta)
	if err != nil {
		return err
	}
	n, err := st.RewriteTOTPSecrets(func(id uint64, sealed string) (string, error) {
		plain, err := oldBox.Open(id, sealed)
		if err != nil {
			return "", err
		}
		return newBox.Seal(id, plain)
	}, keyCheckMeta, []byte(sentinel))
	if err != nil {
		return err
	}
	fmt.Fprintf(d.stdout, "Re-encrypted %d secrets. Now set TABS_SECRET_KEY_FILE to %s.\n", n, args[0])
	return nil
}

// healthcheck probes the local listener. It only ever dials loopback.
func healthcheck(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/_tabs/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %s", resp.Status)
	}
	return nil
}
