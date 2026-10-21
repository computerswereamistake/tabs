package tabs

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func slugs(ts []Tab) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Slug)
	}
	return out
}

func TestCanSee(t *testing.T) {
	tests := []struct {
		name   string
		viewer []string
		tab    []string
		want   bool
	}{
		{"empty tab groups, no viewer groups", nil, nil, true},
		{"empty tab groups, viewer has groups", []string{"users"}, nil, true},
		{"overlap", []string{"users", "admins"}, []string{"admins"}, true},
		{"no overlap", []string{"users"}, []string{"admins"}, false},
		{"viewer has no groups", nil, []string{"users"}, false},
		{"case sensitive", []string{"Users"}, []string{"users"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Viewer{User: "u", Groups: tt.viewer}
			if got := v.CanSee(Tab{Groups: tt.tab}); got != tt.want {
				t.Errorf("CanSee = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVisibleTo(t *testing.T) {
	c := Config{Tabs: []Tab{
		{Slug: "a", Groups: []string{"admins"}},
		{Slug: "b"},
		{Slug: "c", Groups: []string{"users"}},
		{Slug: "d", Groups: []string{"users", "admins"}},
	}}
	tests := []struct {
		name   string
		groups []string
		want   []string
	}{
		{"no groups", nil, []string{"b"}},
		{"users", []string{"users"}, []string{"b", "c", "d"}},
		{"admins", []string{"admins"}, []string{"a", "b", "d"}},
		{"both keeps order", []string{"users", "admins"}, []string{"a", "b", "c", "d"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slugs(c.VisibleTo(Viewer{User: "u", Groups: tt.groups}))
			if !slices.Equal(got, tt.want) {
				t.Errorf("VisibleTo = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewViewer(t *testing.T) {
	tests := []struct {
		name               string
		user, dname, group string
		want               Viewer
		err                error
	}{
		{"groups with spaces", "bob", "Bob", "users, admins", Viewer{"bob", "Bob", []string{"users", "admins"}}, nil},
		{"trailing commas", "bob", "", "users,,admins,", Viewer{"bob", "bob", []string{"users", "admins"}}, nil},
		{"empty groups", "bob", "Bob", "", Viewer{"bob", "Bob", nil}, nil},
		{"only commas", "bob", "Bob", " , ,", Viewer{"bob", "Bob", nil}, nil},
		{"missing user", "", "Bob", "users", Viewer{}, ErrNoUser},
		{"blank user", "  ", "Bob", "users", Viewer{}, ErrNoUser},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewViewer(tt.user, tt.dname, tt.group)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if got.User != tt.want.User || got.Name != tt.want.Name || !slices.Equal(got.Groups, tt.want.Groups) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func validConfig() Config {
	return Config{
		Title:     "Media",
		LogoutURL: "https://auth.example.com/logout",
		Tabs: []Tab{
			{Slug: "app-one", Name: "App One", URL: "/one/", Icon: "one.svg"},
			{Slug: "two", Name: "Two", URL: "https://two.example.com/", Icon: "two.png", Groups: []string{"users"}},
		},
	}
}

func TestValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no tabs", func(c *Config) { c.Tabs = nil }},
		{"duplicate slug", func(c *Config) { c.Tabs[1].Slug = c.Tabs[0].Slug }},
		{"uppercase slug", func(c *Config) { c.Tabs[0].Slug = "App" }},
		{"slug with slash", func(c *Config) { c.Tabs[0].Slug = "a/b" }},
		{"empty slug", func(c *Config) { c.Tabs[0].Slug = "" }},
		{"empty name", func(c *Config) { c.Tabs[0].Name = " " }},
		{"empty url", func(c *Config) { c.Tabs[0].URL = "" }},
		{"relative url", func(c *Config) { c.Tabs[0].URL = "one/" }},
		{"http url", func(c *Config) { c.Tabs[0].URL = "http://one.example.com/" }},
		{"javascript url", func(c *Config) { c.Tabs[0].URL = "javascript:alert(1)" }},
		{"protocol-relative url", func(c *Config) { c.Tabs[0].URL = "//evil.example.com/" }},
		{"backslash url", func(c *Config) { c.Tabs[0].URL = `/\evil.example.com/` }},
		{"url with userinfo", func(c *Config) { c.Tabs[1].URL = "https://u:p@two.example.com/" }},
		{"icon with slash", func(c *Config) { c.Tabs[0].Icon = "sub/one.svg" }},
		{"icon with dotdot", func(c *Config) { c.Tabs[0].Icon = "..one.svg" }},
		{"icon with backslash", func(c *Config) { c.Tabs[0].Icon = `a\b.svg` }},
		{"bad logout url", func(c *Config) { c.LogoutURL = "javascript:alert(1)" }},
		{"wildcard host", func(c *Config) { c.Tabs[1].URL = "https://*.example.com/" }},
		{"comma in host", func(c *Config) { c.Tabs[1].URL = "https://two.example.com,evil/" }},
		{"semicolon in host", func(c *Config) { c.Tabs[1].URL = "https://two.example.com;img-src/" }},
		{"url is app root", func(c *Config) { c.Tabs[0].URL = "/" }},
		{"url is app route", func(c *Config) { c.Tabs[0].URL = "/_tabs/healthz" }},
		{"url is app route, unclean", func(c *Config) { c.Tabs[0].URL = "/x/../_tabs/" }},
		{"url is app route, encoded", func(c *Config) { c.Tabs[0].URL = "/%5ftabs/static/app.js" }},
		{"icon not an image", func(c *Config) { c.Tabs[0].Icon = "page.html" }},
		{"icon without extension", func(c *Config) { c.Tabs[0].Icon = "one" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Error("Validate accepted a bad config")
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no icon", func(c *Config) { c.Tabs[0].Icon = "" }},
		{"uppercase icon extension", func(c *Config) { c.Tabs[0].Icon = "ONE.PNG" }},
		{"host with port", func(c *Config) { c.Tabs[1].URL = "https://two.example.com:8443/x/" }},
		{"path starting with _tabs-like name", func(c *Config) { c.Tabs[0].URL = "/_tabsish/" }},
		{"logout on same origin", func(c *Config) { c.LogoutURL = "/logout" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)
			if err := c.Validate(); err != nil {
				t.Errorf("Validate rejected a good config: %v", err)
			}
		})
	}
}

func TestFrameOrigins(t *testing.T) {
	c := Config{Tabs: []Tab{
		{URL: "/one/"},
		{URL: "https://a.example.com/x/"},
		{URL: "https://b.example.com:8443/"},
		{URL: "https://a.example.com/y/"},
		{URL: "/two/"},
	}}
	want := []string{"https://a.example.com", "https://b.example.com:8443"}
	if got := c.FrameOrigins(); !slices.Equal(got, want) {
		t.Errorf("FrameOrigins = %v, want %v", got, want)
	}
	if got := (Config{Tabs: []Tab{{URL: "/only/"}}}).FrameOrigins(); len(got) != 0 {
		t.Errorf("relative-only FrameOrigins = %v, want empty", got)
	}
}

func TestLoadExample(t *testing.T) {
	if _, err := Load("../../tabs.example.yaml"); err != nil {
		t.Fatalf("example config: %v", err)
	}
}

func TestParse(t *testing.T) {
	good := `
title: Media
logoutURL: https://auth.example.com/logout
tabs:
  - slug: one
    name: One
    url: /one/
    icon: one.svg
    groups: [users]
`
	c, err := Parse(strings.NewReader(good))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Title != "Media" || len(c.Tabs) != 1 || c.Tabs[0].Groups[0] != "users" {
		t.Errorf("unexpected config %+v", c)
	}

	bad := map[string]string{
		"unknown top-level key": good + "extra: 1\n",
		"unknown tab key":       strings.Replace(good, "icon: one.svg", "icon: one.svg\n    colour: red", 1),
		"empty":                 "",
		"invalid":               "tabs: []\n",
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(in)); err == nil {
				t.Error("Parse accepted bad input")
			}
		})
	}
}
