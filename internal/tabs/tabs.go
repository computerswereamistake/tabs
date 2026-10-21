// Package tabs holds the domain model: which apps exist, who is looking, and
// which apps they may see. It has no HTTP dependencies.
package tabs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Tab is one app in the sidebar.
type Tab struct {
	Slug   string   `yaml:"slug"`   // URL-safe unique id, used as the #hash
	Name   string   `yaml:"name"`   // display name
	URL    string   `yaml:"url"`    // iframe src: a "/path/" or an absolute https:// URL
	Icon   string   `yaml:"icon"`   // file name under the icons dir; optional
	Groups []string `yaml:"groups"` // empty = any authenticated viewer
}

// Viewer is who is looking, built only from forward-auth headers.
type Viewer struct {
	User   string
	Name   string
	Groups []string
}

// Config is the parsed YAML file.
type Config struct {
	Title     string `yaml:"title"`
	LogoutURL string `yaml:"logoutURL"`
	Tabs      []Tab  `yaml:"tabs"` // order = sidebar order
}

// ErrNoUser is returned by NewViewer when the user header is missing or empty.
var ErrNoUser = errors.New("missing remote user")

// NewViewer builds a Viewer from the raw Remote-User, Remote-Name and
// Remote-Groups header values. Groups are comma-separated; entries are
// trimmed and empties dropped. Name falls back to User.
func NewViewer(user, name, groups string) (Viewer, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return Viewer{}, ErrNoUser
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = user
	}
	var gs []string
	for g := range strings.SplitSeq(groups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			gs = append(gs, g)
		}
	}
	return Viewer{User: user, Name: name, Groups: gs}, nil
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

// Validate checks the config is safe and coherent.
func (c Config) Validate() error {
	if len(c.Tabs) == 0 {
		return errors.New("at least one tab is required")
	}
	if c.LogoutURL != "" {
		if err := checkURL(c.LogoutURL); err != nil {
			return fmt.Errorf("logoutURL: %w", err)
		}
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
		if strings.Contains(t.Icon, "/") || strings.Contains(t.Icon, `\`) || strings.Contains(t.Icon, "..") {
			return fmt.Errorf("tab %q: icon %q must be a plain file name", t.Slug, t.Icon)
		}
	}
	return nil
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
	return nil
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
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	c, err := Parse(bytes.NewReader(b))
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}
