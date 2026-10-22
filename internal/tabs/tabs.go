// Package tabs holds the domain model: which apps exist, who is looking, and
// which apps they may see. It has no HTTP dependencies.
package tabs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Tab is one app in the sidebar.
type Tab struct {
	Slug   string   `yaml:"slug"`   // URL-safe unique id, used as the #hash
	Name   string   `yaml:"name"`   // display name
	URL    string   `yaml:"url"`    // iframe src: a "/path/" or an absolute https:// URL
	Icon   string   `yaml:"icon"`   // file name under the icons dir; optional
	Groups []string `yaml:"groups"` // empty = any logged-in viewer
}

// Viewer is who is looking: a logged-in user's name and groups.
type Viewer struct {
	User   string
	Name   string
	Groups []string
}

// Config is the parsed YAML file.
type Config struct {
	Title string `yaml:"title"`
	Tabs  []Tab  `yaml:"tabs"` // order = sidebar order

	// LogoutURL is no longer used: tabs handles logout itself. It is still
	// parsed so an old config gets a clear error instead of "unknown field".
	LogoutURL string `yaml:"logoutURL"`
}

// CanSee reports whether v may see t. Group matching is exact and
// case-sensitive.
func (v Viewer) CanSee(t Tab) bool {
	if len(t.Groups) == 0 {
		return true
	}
	for _, g := range t.Groups {
		if slices.Contains(v.Groups, g) {
			return true
		}
	}
	return false
}

// VisibleTo returns the tabs v may see, in config order.
func (c Config) VisibleTo(v Viewer) []Tab {
	var out []Tab
	for _, t := range c.Tabs {
		if v.CanSee(t) {
			out = append(out, t)
		}
	}
	return out
}

var slugRE = regexp.MustCompile(`^[a-z0-9-]+$`)

// groupRE matches group names as tabs stores them.
var groupRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// Validate checks the config is safe and coherent.
func (c Config) Validate() error {
	if len(c.Tabs) == 0 {
		return errors.New("at least one tab is required")
	}
	if c.LogoutURL != "" {
		return errors.New("logoutURL is no longer used (tabs handles logout itself); remove it")
	}
	seen := make(map[string]bool, len(c.Tabs))
	for i, t := range c.Tabs {
		if !slugRE.MatchString(t.Slug) {
			return fmt.Errorf("tabs[%d]: slug %q must match %s", i, t.Slug, slugRE)
		}
		if seen[t.Slug] {
			return fmt.Errorf("tabs[%d]: duplicate slug %q", i, t.Slug)
		}
		seen[t.Slug] = true
		if strings.TrimSpace(t.Name) == "" {
			return fmt.Errorf("tab %q: name is required", t.Slug)
		}
		if err := checkURL(t.URL); err != nil {
			return fmt.Errorf("tab %q: url: %w", t.Slug, err)
		}
		if isOwnPath(t.URL) {
			return fmt.Errorf("tab %q: url %q points at this app, which cannot be framed", t.Slug, t.URL)
		}
		for _, g := range t.Groups {
			if !groupRE.MatchString(g) {
				return fmt.Errorf("tab %q: group %q must match %s", t.Slug, g, groupRE)
			}
		}
		if t.Icon != "" {
			if strings.Contains(t.Icon, "/") || strings.Contains(t.Icon, `\`) || strings.Contains(t.Icon, "..") {
				return fmt.Errorf("tab %q: icon %q must be a plain file name", t.Slug, t.Icon)
			}
			if _, ok := IconContentType(t.Icon); !ok {
				return fmt.Errorf("tab %q: icon %q must be one of %s", t.Slug, t.Icon, strings.Join(slices.Sorted(maps.Keys(iconTypes)), " "))
			}
		}
	}
	return nil
}

// iconTypes is the allowlist of icon file extensions and their content types.
// Nothing else is served from the icons dir, so a stray HTML file there can
// never be served on the app's origin.
var iconTypes = map[string]string{
	".svg":  "image/svg+xml",
	".png":  "image/png",
	".webp": "image/webp",
	".ico":  "image/x-icon",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
}

// IconContentType returns the content type for an allowed icon file name.
func IconContentType(name string) (string, bool) {
	ct, ok := iconTypes[strings.ToLower(path.Ext(name))]
	return ct, ok
}

// hostRE limits absolute-URL hosts to plain hostnames, so nothing unusual
// (wildcards, commas, semicolons) reaches the CSP frame-src directive.
var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// isOwnPath reports whether a same-origin URL points at this app's own
// routes ("/" or "/_tabs/..."), which refuse to be framed.
func isOwnPath(s string) bool {
	if !strings.HasPrefix(s, "/") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	p := path.Clean(u.Path)
	return p == "/" || p == "/_tabs" || strings.HasPrefix(p, "/_tabs/")
}

// checkURL accepts a same-origin path ("/x/") or an absolute https URL.
func checkURL(s string) error {
	if strings.HasPrefix(s, "/") {
		// "//host" and "/\host" are treated by browsers as another origin.
		if strings.HasPrefix(s, "//") || strings.HasPrefix(s, `/\`) {
			return fmt.Errorf("%q is not a same-origin path", s)
		}
		if _, err := url.Parse(s); err != nil {
			return err
		}
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("%q must be a path starting with / or an absolute https:// URL", s)
	}
	if !hostRE.MatchString(u.Hostname()) {
		return fmt.Errorf("%q: host %q must be a plain hostname", s, u.Hostname())
	}
	return nil
}

// Tab returns the tab with the given slug.
func (c Config) Tab(slug string) (Tab, bool) {
	for _, t := range c.Tabs {
		if t.Slug == slug {
			return t, true
		}
	}
	return Tab{}, false
}

// Host returns the host[:port] a tab is served from, lower-cased, or "" for
// a same-origin tab (served from the portal host).
func (t Tab) Host() string {
	if strings.HasPrefix(t.URL, "/") {
		return ""
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return CanonicalHost(u.Host)
}

// CanonicalHost lower-cases a host[:port], drops a trailing dot and the
// default https port, so hosts compare equal however they were written.
// Anything that isn't a plain host[:port] gives "".
func CanonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	host, port := h, ""
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h, "]") {
		host, port = h[:i], h[i+1:]
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strings.Trim(port, "0123456789") != "" {
			return ""
		}
	}
	host = strings.TrimSuffix(host, ".")
	if !hostRE.MatchString(host) {
		return ""
	}
	if port == "" || port == "443" {
		return host
	}
	return host + ":" + port
}

// FrameOrigins returns the distinct origins of absolute tab URLs, in config
// order, for use in a CSP frame-src directive. Relative URLs are skipped.
func (c Config) FrameOrigins() []string {
	var out []string
	for _, t := range c.Tabs {
		u, err := url.Parse(t.URL)
		if err != nil || !u.IsAbs() || u.Host == "" {
			continue
		}
		o := u.Scheme + "://" + u.Host
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

// Parse decodes and validates a YAML config. Unknown keys are rejected.
func Parse(r io.Reader) (Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, errors.New("config is empty")
		}
		return Config{}, err
	}
	if c.Title == "" {
		c.Title = "Tabs"
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Load reads and parses the config file at path.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is the operator's TABS_CONFIG, not request input
	if err != nil {
		return Config{}, err
	}
	c, err := Parse(bytes.NewReader(b))
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}
