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
	p := strings.TrimPrefix(r.URL.Path, pathAdmin)
	switch {
	case p == "" || p == "/":
		http.Redirect(w, r, pathAdmin+"/users", http.StatusSeeOther)
	case p == "/users":
		s.adminUsers(w, r, a)
	case strings.HasPrefix(p, "/users/"):
		id, err := strconv.ParseUint(strings.TrimPrefix(p, "/users/"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		s.adminUser(w, r, a, id)
	case p == "/groups":
		s.adminGroups(w, r, a, st)
	case p == "/invites":
		s.adminInvites(w, r, a)
	case p == "/bans":
		s.adminBans(w, r, a)
	default:
		http.NotFound(w, r)
	}
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

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request, a *authed) {
	show := func(status int, d adminUsersData, errMsg, notice string) {
		var err error
		if d.Users, err = s.store.Users(); err == nil {
			d.Groups, err = s.store.Groups()
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		p := s.newPage("Users", a, d)
		p.Error, p.Notice = errMsg, notice
		s.render(w, r, status, "admin_users", p)
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, adminUsersData{}, "", "")
		return
	}
	if r.PostFormValue("action") != "create" {
		show(http.StatusBadRequest, adminUsersData{}, "Unknown action.", "")
		return
	}
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
		show(http.StatusBadRequest, adminUsersData{}, userError(err), "")
		return
	}
	s.audit(r, "admin-user-created", "by", a.user.Username, "user", u.Username, "admin", u.Admin)
	if temp != "" {
		show(http.StatusOK, adminUsersData{}, "", fmt.Sprintf("Created %s with a temporary password; they must change it at first login.", u.Username))
		return
	}
	link, err := s.newResetLink(u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	show(http.StatusOK, adminUsersData{Link: link, For: u.Username}, "", "")
}

func (s *Server) adminUser(w http.ResponseWriter, r *http.Request, a *authed, id uint64) {
	target, err := s.store.UserByID(id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	self := target.ID == a.user.ID
	show := func(status int, link, errMsg, notice string) {
		d := adminUserData{User: target, Link: link, Self: self}
		var err error
		if d.Groups, err = s.store.Groups(); err == nil {
			var ss []store.Session
			ss, err = s.store.UserSessions(target.ID)
			d.Sessions = len(ss)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		p := s.newPage("User "+target.Username, a, d)
		p.Error, p.Notice = errMsg, notice
		s.render(w, r, status, "admin_user", p)
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, "", "", "")
		return
	}
	// update applies fn to the target, reissuing the admin's own session if
	// they changed something about themselves that ended it.
	update := func(event string, fn func(u *store.User) error) bool {
		before := target
		u, err := s.store.UpdateUser(target.ID, fn)
		if err != nil {
			show(http.StatusBadRequest, "", userError(err), "")
			return false
		}
		target = u
		s.audit(r, event, "by", a.user.Username, "user", u.Username)
		if self && u.AuthEpoch != before.AuthEpoch {
			na, ok := s.reissue(w, r, u)
			if !ok {
				return false
			}
			a = na
			if a.state != effFull || !u.Admin {
				http.Redirect(w, r, pathAccount, http.StatusSeeOther)
				return false
			}
		}
		return true
	}

	switch r.PostFormValue("action") {
	case "save":
		name, err := store.CleanName(r.PostFormValue("name"))
		var email string
		if err == nil {
			email, err = store.CleanEmail(r.PostFormValue("email"))
		}
		if err != nil {
			show(http.StatusBadRequest, "", userError(err), "")
			return
		}
		groups := formGroups(r)
		admin := r.PostFormValue("admin") == "on"
		disabled := r.PostFormValue("disabled") == "on"
		if self && disabled {
			show(http.StatusBadRequest, "", "You can't disable your own account.", "")
			return
		}
		if update("admin-user-updated", func(u *store.User) error {
			u.Name, u.Email, u.Groups, u.Admin, u.Disabled = name, email, groups, admin, disabled
			return nil
		}) {
			show(http.StatusOK, "", "", "Saved.")
		}
	case "unlock":
		if update("admin-user-unlocked", func(u *store.User) error { u.Locked = false; return nil }) {
			s.lockMu.Lock()
			delete(s.failures, target.ID)
			s.lockMu.Unlock()
			show(http.StatusOK, "", "", "Unlocked.")
		}
	case "reset-totp":
		if update("admin-totp-reset", func(u *store.User) error {
			u.TOTPSecret, u.TOTPLastStep, u.RecoveryHashes = "", 0, nil
			return nil
		}) {
			show(http.StatusOK, "", "", "Two-factor login cleared; their sessions have ended.")
		}
	case "reset-link":
		link, err := s.newResetLink(target.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "admin-reset-link", "by", a.user.Username, "user", target.Username)
		show(http.StatusOK, link, "", "")
	case "revoke":
		if err := s.store.DeleteUserSessions(target.ID, a.sess.ID); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r, "admin-sessions-revoked", "by", a.user.Username, "user", target.Username)
		show(http.StatusOK, "", "", "Their sessions have ended.")
	case "delete":
		if self {
			show(http.StatusBadRequest, "", "You can't delete your own account.", "")
			return
		}
		if r.PostFormValue("confirm") != target.Username {
			show(http.StatusBadRequest, "", "Type the username to confirm.", "")
			return
		}
		if err := s.store.DeleteUser(target.ID); err != nil {
			show(http.StatusBadRequest, "", userError(err), "")
			return
		}
		s.audit(r, "admin-user-deleted", "by", a.user.Username, "user", target.Username)
		http.Redirect(w, r, pathAdmin+"/users", http.StatusSeeOther)
	default:
		show(http.StatusBadRequest, "", "Unknown action.", "")
	}
}

func (s *Server) adminGroups(w http.ResponseWriter, r *http.Request, a *authed, st *state) {
	show := func(status int, errMsg, notice string) {
		groups, err := s.store.Groups()
		var users []store.User
		if err == nil {
			users, err = s.store.Users()
		}
		if err != nil {
			s.fail(w, r, err)
			return
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
			for _, t := range st.cfg.Tabs {
				if slices.Contains(t.Groups, g.Name) {
					row.Tabs = append(row.Tabs, t.Name)
				}
			}
			d.Groups = append(d.Groups, row)
		}
		for _, t := range st.cfg.Tabs {
			for _, g := range t.Groups {
				if !defined[g] && !slices.Contains(d.Missing, g) {
					d.Missing = append(d.Missing, g)
				}
			}
		}
		p := s.newPage("Groups", a, d)
		p.Error, p.Notice = errMsg, notice
		s.render(w, r, status, "admin_groups", p)
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, "", "")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	desc, err := store.CleanName(r.PostFormValue("description"))
	if err != nil {
		show(http.StatusBadRequest, userError(err), "")
		return
	}
	g := store.Group{Name: name, Description: desc, RequireTOTP: r.PostFormValue("requireTOTP") == "on"}
	switch r.PostFormValue("action") {
	case "create":
		err = s.store.CreateGroup(g)
	case "update":
		err = s.store.UpdateGroup(g)
	case "delete":
		err = s.store.DeleteGroup(name)
	default:
		show(http.StatusBadRequest, "Unknown action.", "")
		return
	}
	if err != nil {
		show(http.StatusBadRequest, userError(err), "")
		return
	}
	s.audit(r, "admin-group-"+r.PostFormValue("action"), "by", a.user.Username, "group", name, "requireTOTP", g.RequireTOTP)
	show(http.StatusOK, "", "Saved.")
}

func (s *Server) adminInvites(w http.ResponseWriter, r *http.Request, a *authed) {
	show := func(status int, link, errMsg, notice string) {
		invs, err := s.store.Invites()
		var groups []store.Group
		if err == nil {
			groups, err = s.store.Groups()
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d := adminInvitesData{Groups: groups, Link: link, DefaultHours: defaultInviteTTL, MaxHours: maxInviteHours}
		now := s.opts.Now()
		for _, inv := range invs {
			if inv.Usable(now) {
				d.Invites = append(d.Invites, inviteRow{Invite: inv, Short: inv.Hash[:8]})
			}
		}
		p := s.newPage("Invites", a, d)
		p.Error, p.Notice = errMsg, notice
		s.render(w, r, status, "admin_invites", p)
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, "", "", "")
		return
	}
	switch r.PostFormValue("action") {
	case "create":
		hours, err1 := strconv.Atoi(r.PostFormValue("hours"))
		uses, err2 := strconv.Atoi(r.PostFormValue("uses"))
		if err1 != nil || err2 != nil || hours < 1 || hours > maxInviteHours || uses < 1 || uses > maxInviteUses {
			show(http.StatusBadRequest, "", fmt.Sprintf("Expiry must be 1-%d hours and uses 1-%d.", maxInviteHours, maxInviteUses), "")
			return
		}
		note, err := store.CleanName(r.PostFormValue("note"))
		if err != nil {
			show(http.StatusBadRequest, "", userError(err), "")
			return
		}
		tok, err := auth.NewToken()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		now := s.opts.Now()
		inv := store.Invite{
			Hash: auth.HashToken(tok), Groups: formGroups(r), Note: note, CreatedBy: a.user.Username,
			CreatedAt: now, ExpiresAt: now.Add(time.Duration(hours) * time.Hour), MaxUses: uses,
		}
		if err := s.store.CreateInvite(inv); err != nil {
			show(http.StatusBadRequest, "", userError(err), "")
			return
		}
		s.audit(r, "admin-invite-created", "by", a.user.Username, "groups", strings.Join(inv.Groups, ","), "uses", uses, "hours", hours)
		show(http.StatusOK, s.authOrigin+pathInvite+"/"+url.PathEscape(tok), "", "")
	case "revoke":
		short := r.PostFormValue("invite")
		invs, err := s.store.Invites()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, inv := range invs {
			if len(short) == 8 && strings.HasPrefix(inv.Hash, short) {
				if err := s.store.DeleteInvite(inv.Hash); err != nil {
					s.fail(w, r, err)
					return
				}
				s.audit(r, "admin-invite-revoked", "by", a.user.Username)
			}
		}
		show(http.StatusOK, "", "", "Invite revoked.")
	default:
		show(http.StatusBadRequest, "", "Unknown action.", "")
	}
}

func (s *Server) adminBans(w http.ResponseWriter, r *http.Request, a *authed) {
	show := func(status int, notice string) {
		users, err := s.store.Users()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d := adminBansData{Bans: s.opts.Banner.Bans()}
		for _, u := range users {
			if u.Locked {
				d.Locked = append(d.Locked, u)
			}
		}
		p := s.newPage("Bans and locks", a, d)
		p.Notice = notice
		s.render(w, r, status, "admin_bans", p)
	}
	if r.Method != http.MethodPost {
		show(http.StatusOK, "")
		return
	}
	if r.PostFormValue("action") != "unban" {
		show(http.StatusBadRequest, "")
		return
	}
	ip := r.PostFormValue("ip")
	s.opts.Banner.Unban(ip)
	s.ipLimit.Succeed(ip)
	s.audit(r, "admin-unban", "by", a.user.Username, "banned", ip)
	show(http.StatusOK, "Ban lifted.")
}
