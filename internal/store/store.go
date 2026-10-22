// Package store persists users, groups, invites, password resets and
// sessions in a single bbolt file. Records are JSON. Tokens (sessions,
// invites, resets) are keyed by their hash only, so the file holds nothing
// that works as a cookie or link. It has no HTTP dependencies.
package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

var (
	bUsers         = []byte("users")         // id (8-byte BE) -> User
	bUsernames     = []byte("usernames")     // lower(username) -> id
	bGroups        = []byte("groups")        // name -> Group
	bInvites       = []byte("invites")       // hash -> Invite
	bResets        = []byte("resets")        // hash -> Reset
	bSessions      = []byte("sessions")      // id -> Session
	bSessionTokens = []byte("sessionTokens") // token hash -> session id
	bCodes         = []byte("codes")         // hash -> Code (handoff, one-time)
	bGates         = []byte("gates")         // hash -> Gate (per-host app cookie)
	bMeta          = []byte("meta")          // key -> raw value
)

// Errors returned by the store.
var (
	ErrNotFound      = errors.New("not found")
	ErrUsernameTaken = errors.New("username is taken")
	ErrEmailTaken    = errors.New("that email address belongs to another account")
	ErrGroupExists   = errors.New("group already exists")
	ErrLastAdmin     = errors.New("that would leave no enabled admin")
	ErrInviteUsed    = errors.New("invite is expired or used up")
	ErrInvalid       = errors.New("invalid")
	ErrTooMany       = errors.New("too many pending requests")
)

// NameRE is the charset for usernames and group names. Group names match tab
// slugs so tab `groups:` in the YAML can refer to them exactly.
var (
	UsernameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	GroupNameRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

// User is an account.
type User struct {
	ID                 uint64    `json:"id"`
	Username           string    `json:"username"` // lower-case, immutable
	Name               string    `json:"name"`
	Email              string    `json:"email,omitempty"`
	PasswordHash       string    `json:"passwordHash"`
	Admin              bool      `json:"admin"`
	Disabled           bool      `json:"disabled"`
	Locked             bool      `json:"locked,omitempty"` // too many failed logins; an admin unlocks
	Groups             []string  `json:"groups"`
	TOTPSecret         string    `json:"totpSecret,omitempty"` // encrypted by the caller
	TOTPLastStep       int64     `json:"totpLastStep,omitempty"`
	RecoveryHashes     []string  `json:"recoveryHashes,omitempty"`
	MustChangePassword bool      `json:"mustChangePassword,omitempty"`
	CreatedAt          time.Time `json:"createdAt"`
	// AuthEpoch increases whenever credentials or privileges change. Sessions
	// remember the epoch they were made at and stop working once it moves.
	AuthEpoch uint64 `json:"authEpoch"`
}

// HasTOTP reports whether the user has enrolled an authenticator.
func (u User) HasTOTP() bool { return u.TOTPSecret != "" }

// Group is a named set of users. Tabs list group names to restrict who can
// see and reach them.
type Group struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	RequireTOTP bool   `json:"requireTOTP,omitempty"`
}

// Invite lets someone create their own account, landing in Groups.
type Invite struct {
	Hash      string    `json:"hash"`
	Groups    []string  `json:"groups"`
	Note      string    `json:"note,omitempty"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	MaxUses   int       `json:"maxUses"`
	Uses      int       `json:"uses"`
}

// Usable reports whether the invite can still be redeemed at now.
func (i Invite) Usable(now time.Time) bool {
	return now.Before(i.ExpiresAt) && i.Uses < i.MaxUses
}

// Reset is a one-time password reset link for a user.
type Reset struct {
	Hash      string    `json:"hash"`
	UserID    uint64    `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SessionState is how far a session got through login. Further limits
// (must change password, must enrol TOTP) are worked out from the live user
// record on every request, not stored here.
type SessionState string

// Stored session states.
const (
	StateFull        SessionState = "full"
	StateTOTPPending SessionState = "totp-pending" // password ok, needs a code
)

// Session is a logged-in browser.
type Session struct {
	ID        string       `json:"id"`   // stable; gates and codes point here
	Hash      string       `json:"hash"` // hash of the current cookie token
	UserID    uint64       `json:"userId"`
	State     SessionState `json:"state"`
	CSRF      string       `json:"csrf"`
	AuthEpoch uint64       `json:"authEpoch"`
	CreatedAt time.Time    `json:"createdAt"`
	LastSeen  time.Time    `json:"lastSeen"`
	ExpiresAt time.Time    `json:"expiresAt"` // absolute limit
	UserAgent string       `json:"userAgent,omitempty"`
	Attempts  int          `json:"attempts,omitempty"` // failed TOTP tries while pending
	// PendingTOTP is a sealed secret shown during enrolment, kept until the
	// user confirms it with a code.
	PendingTOTP string `json:"pendingTotp,omitempty"`
}

// Code is a one-time handoff code: the auth host issues it, and the
// callback on Host swaps it for a gate cookie. State must match the state
// cookie set on Host when the flow started.
type Code struct {
	Hash      string    `json:"hash"`
	SessionID string    `json:"sessionId"`
	Host      string    `json:"host"`
	StateID   string    `json:"stateId"`         // names the flow's state cookie
	State     string    `json:"state"`           // hash of the state cookie value
	Rd        string    `json:"rd"`              // validated path to land on
	Retry     bool      `json:"retry,omitempty"` // already restarted once
	ExpiresAt time.Time `json:"expiresAt"`
}

// Gate authenticates a browser on one portal or app host. It is only as
// good as the session it hangs off.
type Gate struct {
	Hash      string    `json:"hash"`
	SessionID string    `json:"sessionId"`
	Host      string    `json:"host"`
	CSRF      string    `json:"csrf"` // for the portal's logout form
	CreatedAt time.Time `json:"createdAt"`
}

// Store is the database handle.
type Store struct {
	db *bolt.DB
}

// Open opens (creating if needed) the database at path. It fails fast if
// another process holds the file.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		if errors.Is(err, berrors.ErrTimeout) {
			return nil, fmt.Errorf("%s is in use by another process", path)
		}
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bUsers, bUsernames, bGroups, bInvites, bResets, bSessions, bSessionTokens, bCodes, bGates, bMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func idKey(id uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, id)
	return k
}

func get[T any](b *bolt.Bucket, key []byte) (T, error) {
	var v T
	raw := b.Get(key)
	if raw == nil {
		return v, ErrNotFound
	}
	err := json.Unmarshal(raw, &v)
	return v, err
}

func put(b *bolt.Bucket, key []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, raw)
}

func all[T any](b *bolt.Bucket) ([]T, error) {
	var out []T
	err := b.ForEach(func(_, raw []byte) error {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
	return out, err
}

// CleanName trims a display name and checks it is printable and short.
func CleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 100 {
		return "", fmt.Errorf("%w: name must be at most 100 characters", ErrInvalid)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: name has control characters", ErrInvalid)
		}
	}
	return name, nil
}

// emailRE is deliberately plain: one @, no spaces, commas or control
// characters, since the value is passed on in a Remote-Email header.
var emailRE = regexp.MustCompile(`^[^@\s,;<>"\x00-\x1f\x7f]+@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// CleanEmail trims and checks an optional email address.
func CleanEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", nil
	}
	if len(email) > 254 || !emailRE.MatchString(email) {
		return "", fmt.Errorf("%w: email address is not valid", ErrInvalid)
	}
	return email, nil
}

// NormalizeUsername lower-cases and validates a username.
func NormalizeUsername(u string) (string, error) {
	u = strings.ToLower(strings.TrimSpace(u))
	if !UsernameRE.MatchString(u) {
		return "", fmt.Errorf("%w: username must be 1-64 of a-z 0-9 . _ - and start with a letter or digit", ErrInvalid)
	}
	return u, nil
}

// --- users ---

// UserCount returns how many accounts exist.
func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bUsers).Stats().KeyN
		return nil
	})
	return n, err
}

// CreateUser stores a new user and assigns its ID. Username must already be
// normalized; groups must exist.
func (s *Store) CreateUser(u *User) error {
	return s.db.Update(func(tx *bolt.Tx) error { return createUserTx(tx, u) })
}

func createUserTx(tx *bolt.Tx, u *User) error {
	if _, err := NormalizeUsername(u.Username); err != nil || u.Username != strings.ToLower(u.Username) {
		return fmt.Errorf("%w: username", ErrInvalid)
	}
	names := tx.Bucket(bUsernames)
	if names.Get([]byte(u.Username)) != nil {
		return ErrUsernameTaken
	}
	if err := checkGroupsTx(tx, u.Groups); err != nil {
		return err
	}
	if err := checkEmailTx(tx, 0, u.Email); err != nil {
		return err
	}
	users := tx.Bucket(bUsers)
	id, err := users.NextSequence()
	if err != nil {
		return err
	}
	u.ID = id
	u.AuthEpoch = 1
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	if err := names.Put([]byte(u.Username), idKey(id)); err != nil {
		return err
	}
	return put(users, idKey(id), u)
}

// CreateFirstAdmin creates u as an admin only if there are no users yet, so
// two racing setup requests can't both succeed.
func (s *Store) CreateFirstAdmin(u *User) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bUsers).Stats().KeyN > 0 {
			return fmt.Errorf("%w: setup is already complete", ErrInvalid)
		}
		u.Admin = true
		return createUserTx(tx, u)
	})
}

// UserByID returns a user.
func (s *Store) UserByID(id uint64) (User, error) {
	var u User
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		u, err = get[User](tx.Bucket(bUsers), idKey(id))
		return err
	})
	return u, err
}

// UserByName returns a user by (case-insensitive) username.
func (s *Store) UserByName(name string) (User, error) {
	var u User
	err := s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bUsernames).Get([]byte(strings.ToLower(name)))
		if id == nil {
			return ErrNotFound
		}
		var err error
		u, err = get[User](tx.Bucket(bUsers), id)
		return err
	})
	return u, err
}

// Users returns all users ordered by username.
func (s *Store) Users() ([]User, error) {
	var out []User
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = all[User](tx.Bucket(bUsers))
		return err
	})
	slices.SortFunc(out, func(a, b User) int { return strings.Compare(a.Username, b.Username) })
	return out, err
}

// UpdateUser loads user id, applies fn, re-checks invariants and saves. If
// fn changes credentials or privileges it must call bump on the user, which
// invalidates every existing session. Errors from fn abort the update.
func (s *Store) UpdateUser(id uint64, fn func(u *User) error) (User, error) {
	var out User
	err := s.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bUsers)
		u, err := get[User](users, idKey(id))
		if err != nil {
			return err
		}
		before := u
		if err := fn(&u); err != nil {
			return err
		}
		u.ID, u.Username, u.CreatedAt = before.ID, before.Username, before.CreatedAt
		if err := checkGroupsTx(tx, u.Groups); err != nil {
			return err
		}
		if u.Email != before.Email {
			if err := checkEmailTx(tx, u.ID, u.Email); err != nil {
				return err
			}
		}
		// Anything that changes how the account proves itself, or whether it
		// is an admin or enabled, ends existing sessions. Group changes don't
		// need to: every request reads the live user. Using up a recovery
		// code isn't a change either; issuing new ones is.
		u.AuthEpoch = before.AuthEpoch
		if u.PasswordHash != before.PasswordHash || u.Admin != before.Admin || u.Disabled != before.Disabled ||
			u.TOTPSecret != before.TOTPSecret || !isSubset(u.RecoveryHashes, before.RecoveryHashes) {
			u.AuthEpoch++
		}
		if (before.Admin && !before.Disabled) && (!u.Admin || u.Disabled) {
			if err := ensureOtherAdminTx(tx, u.ID); err != nil {
				return err
			}
		}
		if u.AuthEpoch != before.AuthEpoch {
			if err := deleteSessionsTx(tx, func(x Session) bool { return x.UserID == u.ID }); err != nil {
				return err
			}
		}
		out = u
		return put(users, idKey(id), u)
	})
	return out, err
}

func isSubset(sub, of []string) bool {
	for _, x := range sub {
		if !slices.Contains(of, x) {
			return false
		}
	}
	return true
}

// ensureOtherAdminTx fails unless some enabled admin other than id exists.
func ensureOtherAdminTx(tx *bolt.Tx, id uint64) error {
	users, err := all[User](tx.Bucket(bUsers))
	if err != nil {
		return err
	}
	for _, o := range users {
		if o.ID != id && o.Admin && !o.Disabled {
			return nil
		}
	}
	return ErrLastAdmin
}

// DeleteUser removes a user, their sessions and their reset links.
func (s *Store) DeleteUser(id uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bUsers)
		u, err := get[User](users, idKey(id))
		if err != nil {
			return err
		}
		if u.Admin && !u.Disabled {
			if err := ensureOtherAdminTx(tx, id); err != nil {
				return err
			}
		}
		if err := tx.Bucket(bUsernames).Delete([]byte(u.Username)); err != nil {
			return err
		}
		if err := users.Delete(idKey(id)); err != nil {
			return err
		}
		if err := deleteSessionsTx(tx, func(x Session) bool { return x.UserID == id }); err != nil {
			return err
		}
		return deleteWhereTx(tx, bResets, func(r Reset) bool { return r.UserID == id })
	})
}

func deleteWhereTx[T any](tx *bolt.Tx, bucket []byte, match func(T) bool) error {
	b := tx.Bucket(bucket)
	var keys [][]byte
	err := b.ForEach(func(k, raw []byte) error {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil || match(v) {
			keys = append(keys, slices.Clone(k))
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// checkEmailTx fails if another user (not id) already has email. Emails
// are passed to apps as Remote-Email, so two accounts mustn't share one.
func checkEmailTx(tx *bolt.Tx, id uint64, email string) error {
	if email == "" {
		return nil
	}
	users, err := all[User](tx.Bucket(bUsers))
	if err != nil {
		return err
	}
	for _, o := range users {
		if o.ID != id && strings.EqualFold(o.Email, email) {
			return ErrEmailTaken
		}
	}
	return nil
}

// --- groups ---

func checkGroupsTx(tx *bolt.Tx, groups []string) error {
	b := tx.Bucket(bGroups)
	for i, g := range groups {
		if b.Get([]byte(g)) == nil {
			return fmt.Errorf("%w: group %q does not exist", ErrInvalid, g)
		}
		if slices.Contains(groups[:i], g) {
			return fmt.Errorf("%w: group %q listed twice", ErrInvalid, g)
		}
	}
	return nil
}

// CreateGroup adds a group.
func (s *Store) CreateGroup(g Group) error {
	if !GroupNameRE.MatchString(g.Name) {
		return fmt.Errorf("%w: group name must be 1-64 of a-z 0-9 -", ErrInvalid)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bGroups)
		if b.Get([]byte(g.Name)) != nil {
			return ErrGroupExists
		}
		return put(b, []byte(g.Name), g)
	})
}

// UpdateGroup changes a group's description or TOTP requirement.
func (s *Store) UpdateGroup(g Group) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bGroups)
		if b.Get([]byte(g.Name)) == nil {
			return ErrNotFound
		}
		return put(b, []byte(g.Name), g)
	})
}

// Groups returns all groups ordered by name.
func (s *Store) Groups() ([]Group, error) {
	var out []Group
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = all[Group](tx.Bucket(bGroups))
		return err
	})
	return out, err // bbolt iterates keys in order
}

// DeleteGroup removes a group and takes it off every user and invite, so
// recreating the name later doesn't quietly grant anything.
func (s *Store) DeleteGroup(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		gb := tx.Bucket(bGroups)
		if gb.Get([]byte(name)) == nil {
			return ErrNotFound
		}
		if err := gb.Delete([]byte(name)); err != nil {
			return err
		}
		users := tx.Bucket(bUsers)
		us, err := all[User](users)
		if err != nil {
			return err
		}
		for _, u := range us {
			if i := slices.Index(u.Groups, name); i >= 0 {
				u.Groups = slices.Delete(u.Groups, i, i+1)
				if err := put(users, idKey(u.ID), u); err != nil {
					return err
				}
			}
		}
		ib := tx.Bucket(bInvites)
		invs, err := all[Invite](ib)
		if err != nil {
			return err
		}
		for _, inv := range invs {
			if i := slices.Index(inv.Groups, name); i >= 0 {
				inv.Groups = slices.Delete(inv.Groups, i, i+1)
				if err := put(ib, []byte(inv.Hash), inv); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// --- invites ---

// CreateInvite stores an invite. Hash is the hash of the link token.
func (s *Store) CreateInvite(inv Invite) error {
	if inv.Hash == "" || inv.MaxUses < 1 || inv.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := checkGroupsTx(tx, inv.Groups); err != nil {
			return err
		}
		return put(tx.Bucket(bInvites), []byte(inv.Hash), inv)
	})
}

// Invite returns an invite by token hash.
func (s *Store) Invite(hash string) (Invite, error) {
	var inv Invite
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		inv, err = get[Invite](tx.Bucket(bInvites), []byte(hash))
		return err
	})
	return inv, err
}

// Invites returns all invites, newest first.
func (s *Store) Invites() ([]Invite, error) {
	var out []Invite
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = all[Invite](tx.Bucket(bInvites))
		return err
	})
	slices.SortFunc(out, func(a, b Invite) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, err
}

// DeleteInvite revokes an invite.
func (s *Store) DeleteInvite(hash string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bInvites)
		if b.Get([]byte(hash)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(hash))
	})
}

// RedeemInvite checks the invite and creates u in one transaction, so an
// invite can never be used more than MaxUses times. u gets the invite's
// groups (that still exist); invites never grant admin.
func (s *Store) RedeemInvite(hash string, now time.Time, u *User) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		ib := tx.Bucket(bInvites)
		inv, err := get[Invite](ib, []byte(hash))
		if err != nil {
			return ErrInviteUsed
		}
		if !inv.Usable(now) {
			return ErrInviteUsed
		}
		u.Admin = false
		u.Groups = slices.Clone(inv.Groups)
		if err := createUserTx(tx, u); err != nil {
			return err
		}
		inv.Uses++
		if inv.Uses >= inv.MaxUses {
			return ib.Delete([]byte(hash))
		}
		return put(ib, []byte(hash), inv)
	})
}

// --- resets ---

// CreateReset stores a reset link, replacing any earlier one for the user.
func (s *Store) CreateReset(r Reset) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bUsers).Get(idKey(r.UserID)) == nil {
			return ErrNotFound
		}
		if err := deleteWhereTx(tx, bResets, func(o Reset) bool { return o.UserID == r.UserID }); err != nil {
			return err
		}
		return put(tx.Bucket(bResets), []byte(r.Hash), r)
	})
}

// Reset returns a usable reset link.
func (s *Store) Reset(hash string, now time.Time) (Reset, error) {
	var r Reset
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		r, err = get[Reset](tx.Bucket(bResets), []byte(hash))
		if err == nil && !now.Before(r.ExpiresAt) {
			err = ErrNotFound
		}
		return err
	})
	return r, err
}

// RedeemReset sets the user's password hash from a reset link, in one
// transaction. It clears MustChangePassword, ends the user's sessions and
// voids every reset link they have. TOTP is untouched, so the next login
// still needs a code. A disabled user can't be reset back in.
func (s *Store) RedeemReset(hash string, now time.Time, passwordHash string) (User, error) {
	var out User
	err := s.db.Update(func(tx *bolt.Tx) error {
		rb := tx.Bucket(bResets)
		r, err := get[Reset](rb, []byte(hash))
		if err != nil || !now.Before(r.ExpiresAt) {
			return ErrNotFound
		}
		if err := rb.Delete([]byte(hash)); err != nil {
			return err
		}
		users := tx.Bucket(bUsers)
		u, err := get[User](users, idKey(r.UserID))
		if err != nil {
			return err
		}
		if u.Disabled {
			return fmt.Errorf("%w: account is disabled", ErrInvalid)
		}
		u.PasswordHash = passwordHash
		u.MustChangePassword = false
		u.AuthEpoch++
		if err := deleteSessionsTx(tx, func(x Session) bool { return x.UserID == u.ID }); err != nil {
			return err
		}
		if err := deleteWhereTx(tx, bResets, func(x Reset) bool { return x.UserID == u.ID }); err != nil {
			return err
		}
		out = u
		return put(users, idKey(u.ID), u)
	})
	return out, err
}

// --- sessions ---

// CreateSession stores a new session. ID and Hash must be set.
func (s *Store) CreateSession(sess Session) error {
	if sess.ID == "" || sess.Hash == "" {
		return ErrInvalid
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bSessionTokens).Put([]byte(sess.Hash), []byte(sess.ID)); err != nil {
			return err
		}
		return put(tx.Bucket(bSessions), []byte(sess.ID), sess)
	})
}

// liveSessionTx loads session id and its user, checking the session hasn't
// expired (absolute or idle), the user still exists and is enabled, and the
// user's credentials haven't changed since the session was made.
func liveSessionTx(tx *bolt.Tx, id []byte, now time.Time, idle time.Duration) (Session, User, error) {
	sess, err := get[Session](tx.Bucket(bSessions), id)
	if err != nil {
		return Session{}, User{}, ErrNotFound
	}
	if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeen) > idle {
		return Session{}, User{}, ErrNotFound
	}
	u, err := get[User](tx.Bucket(bUsers), idKey(sess.UserID))
	if err != nil || u.Disabled || u.AuthEpoch != sess.AuthEpoch {
		return Session{}, User{}, ErrNotFound
	}
	return sess, u, nil
}

// SessionByToken returns a live session and its user by token hash.
func (s *Store) SessionByToken(hash string, now time.Time, idle time.Duration) (Session, User, error) {
	var sess Session
	var u User
	err := s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bSessionTokens).Get([]byte(hash))
		if id == nil {
			return ErrNotFound
		}
		var err error
		sess, u, err = liveSessionTx(tx, id, now, idle)
		if err == nil && sess.Hash != hash {
			err = ErrNotFound // stale index entry
		}
		return err
	})
	return sess, u, err
}

// SessionByID returns a live session and its user by session ID.
func (s *Store) SessionByID(id string, now time.Time, idle time.Duration) (Session, User, error) {
	var sess Session
	var u User
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		sess, u, err = liveSessionTx(tx, []byte(id), now, idle)
		return err
	})
	return sess, u, err
}

// GateSession returns a gate, its live session and user.
func (s *Store) GateSession(gateHash string, now time.Time, idle time.Duration) (Gate, Session, User, error) {
	var g Gate
	var sess Session
	var u User
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		g, err = get[Gate](tx.Bucket(bGates), []byte(gateHash))
		if err != nil {
			return err
		}
		sess, u, err = liveSessionTx(tx, []byte(g.SessionID), now, idle)
		return err
	})
	return g, sess, u, err
}

// TouchSession records activity, at most once per interval so busy apps
// polling through forward-auth don't write on every request.
func (s *Store) TouchSession(sess Session, now time.Time, interval time.Duration) error {
	if now.Sub(sess.LastSeen) < interval {
		return nil
	}
	return s.UpdateSession(sess.ID, func(cur *Session) bool {
		cur.LastSeen = now
		return true
	})
}

// UpdateSession applies fn to a stored session and saves it, or deletes the
// session (and its gates) if fn returns false. fn must not change ID or
// Hash; use RotateSession for that.
func (s *Store) UpdateSession(id string, fn func(*Session) (keep bool)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bSessions)
		sess, err := get[Session](b, []byte(id))
		if err != nil {
			return err
		}
		hash := sess.Hash
		if !fn(&sess) {
			return deleteSessionsTx(tx, func(x Session) bool { return x.ID == id })
		}
		sess.ID, sess.Hash = id, hash
		return put(b, []byte(id), sess)
	})
}

// RotateSession gives session id a new token hash and applies fn, in one
// transaction. The old token stops working. Gates and codes, which point at
// the ID, are unaffected.
func (s *Store) RotateSession(id, newHash string, fn func(*Session)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bSessions)
		sess, err := get[Session](b, []byte(id))
		if err != nil {
			return err
		}
		tokens := tx.Bucket(bSessionTokens)
		if err := tokens.Delete([]byte(sess.Hash)); err != nil {
			return err
		}
		if fn != nil {
			fn(&sess)
		}
		sess.ID, sess.Hash = id, newHash
		if err := tokens.Put([]byte(newHash), []byte(id)); err != nil {
			return err
		}
		return put(b, []byte(id), sess)
	})
}

// DeleteSession removes one session and its gates.
func (s *Store) DeleteSession(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return deleteSessionsTx(tx, func(x Session) bool { return x.ID == id })
	})
}

// UserSessions returns a user's sessions, newest first.
func (s *Store) UserSessions(userID uint64) ([]Session, error) {
	var out []Session
	err := s.db.View(func(tx *bolt.Tx) error {
		ss, err := all[Session](tx.Bucket(bSessions))
		for _, x := range ss {
			if x.UserID == userID {
				out = append(out, x)
			}
		}
		return err
	})
	slices.SortFunc(out, func(a, b Session) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, err
}

// DeleteUserSessions removes all of a user's sessions (and their gates)
// except the one with ID keep ("" for none).
func (s *Store) DeleteUserSessions(userID uint64, keep string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return deleteSessionsTx(tx, func(x Session) bool { return x.UserID == userID && x.ID != keep })
	})
}

// deleteSessionsTx deletes matching sessions with their token index entries,
// gates and pending codes.
func deleteSessionsTx(tx *bolt.Tx, match func(Session) bool) error {
	var ids []string
	tokens := tx.Bucket(bSessionTokens)
	err := deleteWhereTx(tx, bSessions, func(x Session) bool {
		if !match(x) {
			return false
		}
		ids = append(ids, x.ID)
		_ = tokens.Delete([]byte(x.Hash))
		return true
	})
	if err != nil || len(ids) == 0 {
		return err
	}
	if err := deleteWhereTx(tx, bGates, func(g Gate) bool { return slices.Contains(ids, g.SessionID) }); err != nil {
		return err
	}
	return deleteWhereTx(tx, bCodes, func(c Code) bool { return slices.Contains(ids, c.SessionID) })
}

// --- handoff codes and gates ---

// CreateCode stores a handoff code. At most maxPending live codes may exist
// per session, so a looping script can't grow the database.
func (s *Store) CreateCode(c Code, now time.Time, maxPending int) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bSessions).Get([]byte(c.SessionID)) == nil {
			return ErrNotFound
		}
		codes, err := all[Code](tx.Bucket(bCodes))
		if err != nil {
			return err
		}
		n := 0
		for _, o := range codes {
			if o.SessionID == c.SessionID && now.Before(o.ExpiresAt) {
				n++
			}
		}
		if n >= maxPending {
			return ErrTooMany
		}
		return put(tx.Bucket(bCodes), []byte(c.Hash), c)
	})
}

// ConsumeCode deletes and returns a live handoff code. A code works once.
func (s *Store) ConsumeCode(hash string, now time.Time) (Code, error) {
	var c Code
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bCodes)
		var err error
		c, err = get[Code](b, []byte(hash))
		if err != nil {
			return err
		}
		if err := b.Delete([]byte(hash)); err != nil {
			return err
		}
		if !now.Before(c.ExpiresAt) {
			return ErrNotFound
		}
		return nil
	})
	return c, err
}

// CreateGate stores a gate for an existing session.
func (s *Store) CreateGate(g Gate) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bSessions).Get([]byte(g.SessionID)) == nil {
			return ErrNotFound
		}
		return put(tx.Bucket(bGates), []byte(g.Hash), g)
	})
}

// --- meta ---

// Meta returns a stored metadata value, or nil.
func (s *Store) Meta(key string) ([]byte, error) {
	var v []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v = slices.Clone(tx.Bucket(bMeta).Get([]byte(key)))
		return nil
	})
	return v, err
}

// SetMeta stores a metadata value.
func (s *Store) SetMeta(key string, v []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bMeta).Put([]byte(key), v)
	})
}

// RewriteTOTPSecrets replaces every user's TOTP secret with fn(id, old) and
// sets meta[metaKey] = metaVal, all in one transaction, for key rotation.
// Pending enrolments in sessions are dropped (they're under the old key).
// AuthEpoch is left alone: the secrets are the same, only their encryption
// changed.
func (s *Store) RewriteTOTPSecrets(fn func(id uint64, sealed string) (string, error), metaKey string, metaVal []byte) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bMeta).Put([]byte(metaKey), metaVal); err != nil {
			return err
		}
		sb := tx.Bucket(bSessions)
		ss, err := all[Session](sb)
		if err != nil {
			return err
		}
		for _, x := range ss {
			if x.PendingTOTP != "" {
				x.PendingTOTP = ""
				if err := put(sb, []byte(x.ID), x); err != nil {
					return err
				}
			}
		}
		users := tx.Bucket(bUsers)
		us, err := all[User](users)
		if err != nil {
			return err
		}
		for _, u := range us {
			if u.TOTPSecret == "" {
				continue
			}
			if u.TOTPSecret, err = fn(u.ID, u.TOTPSecret); err != nil {
				return fmt.Errorf("user %s: %w", u.Username, err)
			}
			if err := put(users, idKey(u.ID), u); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// Prune deletes expired sessions (with their gates), invites, resets and
// codes.
func (s *Store) Prune(now time.Time, idle time.Duration) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := deleteSessionsTx(tx, func(x Session) bool {
			return !now.Before(x.ExpiresAt) || now.Sub(x.LastSeen) > idle
		}); err != nil {
			return err
		}
		if err := deleteWhereTx(tx, bCodes, func(x Code) bool { return !now.Before(x.ExpiresAt) }); err != nil {
			return err
		}
		if err := deleteWhereTx(tx, bInvites, func(x Invite) bool { return !x.Usable(now) }); err != nil {
			return err
		}
		return deleteWhereTx(tx, bResets, func(x Reset) bool { return !now.Before(x.ExpiresAt) })
	})
}
