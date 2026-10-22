package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/computerswereamistake/tabs/internal/auth"
	"github.com/computerswereamistake/tabs/internal/store"
)

const (
	resetLinkTTL     = 72 * time.Hour
	maxInviteHours   = 30 * 24
	maxInviteUses    = 100
	defaultInviteTTL = 7 * 24
)

type adminUsersData struct {
	Users  []store.User
	Groups []store.Group
	Link   string // a just-created reset link, shown once
	For    string
}

type adminUserData struct {
	User     store.User
	Groups   []store.Group
	Sessions int
	Link     string
	Self     bool
}

type groupRow struct {
	store.Group
	Members int
	Tabs    []string
}

type adminGroupsData struct {
	Groups  []groupRow
	Missing []string // used by tabs but not defined
}

type inviteRow struct {
	store.Invite
	Short string // first characters of the hash, to tell rows apart
}

type adminInvitesData struct {
	Invites      []inviteRow
	Groups       []store.Group
	Link         string
	DefaultHours int
	MaxHours     int
}

type adminBansData struct {
	Bans   []auth.Ban
	Locked []store.User
}

// adminCtx is one admin-page request.
type adminCtx struct {
	w      http.ResponseWriter
	r      *http.Request
	a      *authed
	st     *state
	target store.User // the user on /admin/users/{id}
	self   bool       // target is the admin making the request
}

// adminPage is one admin page: its template, how to load its data (fresh
// for every render, given the last action's result), and its forms.
type adminPage struct {
	template string
	heading  func(c *adminCtx) string
	load     func(s *Server, c *adminCtx, res result) (any, error)
	actions  map[string]func(s *Server, c *adminCtx) result
}

func fixedHeading(h string) func(*adminCtx) string { return func(*adminCtx) string { return h } }

var (
	adminUsersPage = adminPage{
		template: "admin_users",
		heading:  fixedHeading("Users"),
		load:     (*Server).loadAdminUsers,
		actions:  map[string]func(*Server, *adminCtx) result{"create": (*Server).adminCreateUser},
	}
	adminUserPage = adminPage{
		template: "admin_user",
		heading:  func(c *adminCtx) string { return "User " + c.target.Username },
		load:     (*Server).loadAdminUser,
		actions: map[string]func(*Server, *adminCtx) result{
			"save":       (*Server).adminSaveUser,
			"unlock":     (*Server).adminUnlockUser,
			"reset-totp": (*Server).adminResetTOTP,
			"reset-link": (*Server).adminResetLink,
			"revoke":     (*Server).adminRevokeSessions,
			"delete":     (*Server).adminDeleteUser,
		},
	}
	adminGroupsPage = adminPage{
		template: "admin_groups",
		heading:  fixedHeading("Groups"),
		load:     (*Server).loadAdminGroups,
		actions: map[string]func(*Server, *adminCtx) result{
			"create": groupAction("create"),
			"update": groupAction("update"),
			"delete": groupAction("delete"),
		},
	}
	adminInvitesPage = adminPage{
		template: "admin_invites",
		heading:  fixedHeading("Invites"),
		load:     (*Server).loadAdminInvites,
		actions: map[string]func(*Server, *adminCtx) result{
			"create": (*Server).adminCreateInvite,
			"revoke": (*Server).adminRevokeInvite,
		},
	}
	adminBansPage = adminPage{
		template: "admin_bans",
		heading:  fixedHeading("Bans and locks"),
		load:     (*Server).loadAdminBans,
		actions:  map[string]func(*Server, *adminCtx) result{"unban": (*Server).adminUnban},
	}
)

func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request, st *state) {
	a := s.requireFull(w, r)
	if a == nil {
		return
	}
	if !a.user.Admin {
		s.message(w, r, http.StatusForbidden, "Admins only", "You need to be an admin to see this page.")
		return
	}
	if !allow(w, r, "GET", "HEAD", "POST") {
		return
	}
	if r.Method == http.MethodPost && !s.checkPost(w, r, a) {
		return
	}
	c := &adminCtx{w: w, r: r, a: a, st: st}
	p := strings.TrimPrefix(r.URL.Path, pathAdmin)
	switch {
	case p == "" || p == "/":
		http.Redirect(w, r, pathAdmin+"/users", http.StatusSeeOther)
	case p == "/users":
		s.runAdmin(c, adminUsersPage)
	case strings.HasPrefix(p, "/users/"):
		id, err := strconv.ParseUint(strings.TrimPrefix(p, "/users/"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		c.target, err = s.store.UserByID(id)
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		c.self = c.target.ID == a.user.ID
		s.runAdmin(c, adminUserPage)
	case p == "/groups":
		s.runAdmin(c, adminGroupsPage)
	case p == "/invites":
		s.runAdmin(c, adminInvitesPage)
	case p == "/bans":
		s.runAdmin(c, adminBansPage)
	default:
		http.NotFound(w, r)
	}
}

// runAdmin runs the posted action, if any, then renders the page.
func (s *Server) runAdmin(c *adminCtx, pg adminPage) {
	var res result
	if c.r.Method == http.MethodPost {
		act, ok := pg.actions[c.r.PostFormValue("action")]
		if !ok {
			res = refuse(http.StatusBadRequest, "Unknown action.")
		} else if res = act(s, c); res.written {
			return
		}
	}
	data, err := pg.load(s, c, res)
	if err != nil {
		s.fail(c.w, c.r, err)
		return
	}
	s.showForm(c.w, c.r, c.a, pg.template, pg.heading(c), res, data)
}

// formGroups reads the checked group boxes.
func formGroups(r *http.Request) []string {
	var out []string
	for _, g := range r.PostForm["groups"] {
		if g != "" && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

func (s *Server) newResetLink(userID uint64) (string, error) {
	tok, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	err = s.store.CreateReset(store.Reset{Hash: auth.HashToken(tok), UserID: userID, ExpiresAt: s.opts.Now().Add(resetLinkTTL)})
	return s.authOrigin + pathReset + "/" + tok, err
}

// --- users ---

func (s *Server) loadAdminUsers(c *adminCtx, res result) (any, error) {
	d := adminUsersData{Link: res.link, For: res.linkFor}
	var err error
	if d.Users, err = s.store.Users(); err == nil {
		d.Groups, err = s.store.Groups()
	}
	return d, err
}

func (s *Server) adminCreateUser(c *adminCtx) result {
	r := c.r
	name, err := store.NormalizeUsername(r.PostFormValue("username"))
	var display, email string
	if err == nil {
		display, err = store.CleanName(r.PostFormValue("name"))
	}
	if err == nil {
		email, err = store.CleanEmail(r.PostFormValue("email"))
	}
	u := store.User{Username: name, Name: display, Email: email, Groups: formGroups(r), Admin: r.PostFormValue("admin") == "on"}
	temp := r.PostFormValue("password")
	if err == nil && temp != "" {
		if err = auth.CheckPassword(temp, name); err == nil {
			u.PasswordHash, err = auth.HashPassword(temp)
			u.MustChangePassword = true
		}
	}
	if err == nil {
		err = s.store.CreateUser(&u)
	}
	if err != nil {
		return refuse(http.StatusBadRequest, userError(err))
	}
	s.audit(r, "admin-user-created", "by", c.a.user.Username, "user", u.Username, "admin", u.Admin)
	if temp != "" {
		return done(fmt.Sprintf("Created %s with a temporary password; they must change it at first login.", u.Username))
	}
	link, err := s.newResetLink(u.ID)
	if err != nil {
		return s.failResult(c.w, r, err)
	}
	return result{link: link, linkFor: u.Username}
}

func (s *Server) loadAdminUser(c *adminCtx, res result) (any, error) {
	d := adminUserData{User: c.target, Link: res.link, Self: c.self}
	var err error
	if d.Groups, err = s.store.Groups(); err == nil {
		var ss []store.Session
		ss, err = s.store.UserSessions(c.target.ID)
		d.Sessions = len(ss)
	}
	return d, err
}

// updateTarget applies fn to the page's user. If admins changed something
// about themselves that ended their own session, it reissues one, and
// sends them to their account page if they are no longer a full admin.
func (s *Server) updateTarget(c *adminCtx, event string, fn func(u *store.User) error) (result, bool) {
	before := c.target
	u, err := s.store.UpdateUser(c.target.ID, fn)
	if err != nil {
		return refuse(http.StatusBadRequest, userError(err)), false
	}
	c.target = u
	s.audit(c.r, event, "by", c.a.user.Username, "user", u.Username)
	if c.self && u.AuthEpoch != before.AuthEpoch {
		na, ok := s.reissue(c.w, c.r, u)
		if !ok {
			return handled, false
		}
		c.a = na
		if c.a.state != effFull || !u.Admin {
			http.Redirect(c.w, c.r, pathAccount, http.StatusSeeOther)
			return handled, false
		}
	}
	return result{}, true
}

func (s *Server) adminSaveUser(c *adminCtx) result {
	name, err := store.CleanName(c.r.PostFormValue("name"))
	var email string
	if err == nil {
		email, err = store.CleanEmail(c.r.PostFormValue("email"))
	}
	if err != nil {
		return refuse(http.StatusBadRequest, userError(err))
	}
	groups := formGroups(c.r)
	admin := c.r.PostFormValue("admin") == "on"
	disabled := c.r.PostFormValue("disabled") == "on"
	if c.self && disabled {
		return refuse(http.StatusBadRequest, "You can't disable your own account.")
	}
	if res, ok := s.updateTarget(c, "admin-user-updated", func(u *store.User) error {
		u.Name, u.Email, u.Groups, u.Admin, u.Disabled = name, email, groups, admin, disabled
		return nil
	}); !ok {
		return res
	}
	return done("Saved.")
}

func (s *Server) adminUnlockUser(c *adminCtx) result {
	if res, ok := s.updateTarget(c, "admin-user-unlocked", func(u *store.User) error { u.Locked = false; return nil }); !ok {
		return res
	}
	s.lockMu.Lock()
	delete(s.failures, c.target.ID)
	s.lockMu.Unlock()
	return done("Unlocked.")
}

func (s *Server) adminResetTOTP(c *adminCtx) result {
	if res, ok := s.updateTarget(c, "admin-totp-reset", func(u *store.User) error {
		u.TOTPSecret, u.TOTPLastStep, u.RecoveryHashes = "", 0, nil
		return nil
	}); !ok {
		return res
	}
	return done("Two-factor login cleared; their sessions have ended.")
}

func (s *Server) adminResetLink(c *adminCtx) result {
	link, err := s.newResetLink(c.target.ID)
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	s.audit(c.r, "admin-reset-link", "by", c.a.user.Username, "user", c.target.Username)
	return result{link: link}
}

func (s *Server) adminRevokeSessions(c *adminCtx) result {
	if err := s.store.DeleteUserSessions(c.target.ID, c.a.sess.ID); err != nil {
		return s.failResult(c.w, c.r, err)
	}
	s.audit(c.r, "admin-sessions-revoked", "by", c.a.user.Username, "user", c.target.Username)
	return done("Their sessions have ended.")
}

func (s *Server) adminDeleteUser(c *adminCtx) result {
	if c.self {
		return refuse(http.StatusBadRequest, "You can't delete your own account.")
	}
	if c.r.PostFormValue("confirm") != c.target.Username {
		return refuse(http.StatusBadRequest, "Type the username to confirm.")
	}
	if err := s.store.DeleteUser(c.target.ID); err != nil {
		return refuse(http.StatusBadRequest, userError(err))
	}
	s.audit(c.r, "admin-user-deleted", "by", c.a.user.Username, "user", c.target.Username)
	http.Redirect(c.w, c.r, pathAdmin+"/users", http.StatusSeeOther)
	return handled
}

// --- groups ---

func (s *Server) loadAdminGroups(c *adminCtx, _ result) (any, error) {
	groups, err := s.store.Groups()
	if err != nil {
		return nil, err
	}
	users, err := s.store.Users()
	if err != nil {
		return nil, err
	}
	d := adminGroupsData{}
	defined := map[string]bool{}
	for _, g := range groups {
		row := groupRow{Group: g}
		defined[g.Name] = true
		for _, u := range users {
			if slices.Contains(u.Groups, g.Name) {
				row.Members++
			}
		}
		for _, t := range c.st.cfg.Tabs {
			if slices.Contains(t.Groups, g.Name) {
				row.Tabs = append(row.Tabs, t.Name)
			}
		}
		d.Groups = append(d.Groups, row)
	}
	for _, t := range c.st.cfg.Tabs {
		for _, g := range t.Groups {
			if !defined[g] && !slices.Contains(d.Missing, g) {
				d.Missing = append(d.Missing, g)
			}
		}
	}
	return d, nil
}

// groupAction handles the create, update and delete forms, which share
// their fields.
func groupAction(op string) func(*Server, *adminCtx) result {
	return func(s *Server, c *adminCtx) result {
		name := strings.TrimSpace(c.r.PostFormValue("name"))
		desc, err := store.CleanName(c.r.PostFormValue("description"))
		if err != nil {
			return refuse(http.StatusBadRequest, userError(err))
		}
		g := store.Group{Name: name, Description: desc, RequireTOTP: c.r.PostFormValue("requireTOTP") == "on"}
		switch op {
		case "create":
			err = s.store.CreateGroup(g)
		case "update":
			err = s.store.UpdateGroup(g)
		case "delete":
			err = s.store.DeleteGroup(name)
		}
		if err != nil {
			return refuse(http.StatusBadRequest, userError(err))
		}
		s.audit(c.r, "admin-group-"+op, "by", c.a.user.Username, "group", name, "requireTOTP", g.RequireTOTP)
		return done("Saved.")
	}
}

// --- invites ---

func (s *Server) loadAdminInvites(c *adminCtx, res result) (any, error) {
	invs, err := s.store.Invites()
	if err != nil {
		return nil, err
	}
	groups, err := s.store.Groups()
	if err != nil {
		return nil, err
	}
	d := adminInvitesData{Groups: groups, Link: res.link, DefaultHours: defaultInviteTTL, MaxHours: maxInviteHours}
	now := s.opts.Now()
	for _, inv := range invs {
		if inv.Usable(now) {
			d.Invites = append(d.Invites, inviteRow{Invite: inv, Short: inv.Hash[:8]})
		}
	}
	return d, nil
}

func (s *Server) adminCreateInvite(c *adminCtx) result {
	hours, err1 := strconv.Atoi(c.r.PostFormValue("hours"))
	uses, err2 := strconv.Atoi(c.r.PostFormValue("uses"))
	if err1 != nil || err2 != nil || hours < 1 || hours > maxInviteHours || uses < 1 || uses > maxInviteUses {
		return refuse(http.StatusBadRequest, fmt.Sprintf("Expiry must be 1-%d hours and uses 1-%d.", maxInviteHours, maxInviteUses))
	}
	note, err := store.CleanName(c.r.PostFormValue("note"))
	if err != nil {
		return refuse(http.StatusBadRequest, userError(err))
	}
	tok, err := auth.NewToken()
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	now := s.opts.Now()
	inv := store.Invite{
		Hash: auth.HashToken(tok), Groups: formGroups(c.r), Note: note, CreatedBy: c.a.user.Username,
		CreatedAt: now, ExpiresAt: now.Add(time.Duration(hours) * time.Hour), MaxUses: uses,
	}
	if err := s.store.CreateInvite(inv); err != nil {
		return refuse(http.StatusBadRequest, userError(err))
	}
	s.audit(c.r, "admin-invite-created", "by", c.a.user.Username, "groups", strings.Join(inv.Groups, ","), "uses", uses, "hours", hours)
	return result{link: s.authOrigin + pathInvite + "/" + url.PathEscape(tok)}
}

func (s *Server) adminRevokeInvite(c *adminCtx) result {
	short := c.r.PostFormValue("invite")
	invs, err := s.store.Invites()
	if err != nil {
		return s.failResult(c.w, c.r, err)
	}
	for _, inv := range invs {
		if len(short) == 8 && strings.HasPrefix(inv.Hash, short) {
			if err := s.store.DeleteInvite(inv.Hash); err != nil {
				return s.failResult(c.w, c.r, err)
			}
			s.audit(c.r, "admin-invite-revoked", "by", c.a.user.Username)
		}
	}
	return done("Invite revoked.")
}

// --- bans ---

func (s *Server) loadAdminBans(_ *adminCtx, _ result) (any, error) {
	users, err := s.store.Users()
	if err != nil {
		return nil, err
	}
	d := adminBansData{Bans: s.opts.Banner.Bans()}
	for _, u := range users {
		if u.Locked {
			d.Locked = append(d.Locked, u)
		}
	}
	return d, nil
}

func (s *Server) adminUnban(c *adminCtx) result {
	ip := c.r.PostFormValue("ip")
	s.opts.Banner.Unban(ip)
	s.ipLimit.Succeed(ip)
	s.audit(c.r, "admin-unban", "by", c.a.user.Username, "banned", ip)
	return done("Ban lifted.")
}
