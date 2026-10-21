// Command tabs serves a sidebar of apps, each loaded in an iframe and filtered
// by the viewer's forward-auth groups.
//
// Usage:
//
//	tabs              run the server
//	tabs healthcheck  GET /_tabs/healthz on the local listener; exit 0 or 1
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/computerswereamistake/tabs/internal/tabs"
	"github.com/computerswereamistake/tabs/internal/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	listen := env("TABS_LISTEN", ":8080")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			if err := healthcheck(listen); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
			os.Exit(2)
		}
	}

	if err := run(log, listen); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, listen string) error {
	cfgPath := env("TABS_CONFIG", "/config/tabs.yaml")
	iconsDir := env("TABS_ICONS_DIR", "/config/icons")

	proxies := os.Getenv("TABS_TRUSTED_PROXIES")
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

	app := web.New(cfg, trusted, root.FS(), log)
	srv := &http.Server{
		Addr:              listen,
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", listen, "tabs", len(cfg.Tabs))
		errc <- srv.ListenAndServe()
	}()

	for {
		select {
		case err := <-errc:
			return err
		case sig := <-sigs:
			if sig == syscall.SIGHUP {
				next, err := tabs.Load(cfgPath)
				if err != nil {
					log.Error("reload failed; keeping previous config", "err", err)
					continue
				}
				app.SetConfig(next)
				log.Info("config reloaded", "tabs", len(next.Tabs))
				continue
			}
			log.Info("shutting down", "signal", sig.String())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(ctx)
		}
	}
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
