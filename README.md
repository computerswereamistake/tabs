# tabs

A minimal replacement for Organizr's tabbed UI: a sidebar of apps, each loaded
in an iframe, filtered by the viewer's groups. Tabs is also the login server
for those apps: it has its own users, groups, invite links and two-factor
login (TOTP), and a forward-auth endpoint so the reverse proxy lets each user
reach only the apps their groups allow.

Design goals: small attack surface. Stdlib Go plus a handful of small
libraries (YAML, bbolt, x/crypto, a QR encoder), one database file, no
outbound network, distroless image.

## How it fits together

Tabs answers for three kinds of host, all on one listener behind Caddy:

| Host | What it serves |
| --- | --- |
| **Auth host** (`TABS_AUTH_URL`, e.g. `auth.example.com`) | Login, two-factor, account, admin, setup, invite and password links |
| **Portal host** (`TABS_PUBLIC_URL`, e.g. `tabs.example.com`) | The sidebar, plus every same-origin app (`/app-one/`) |
| **App hosts** (hosts of absolute tab URLs) | Only the sign-in handoff; Caddy gates the rest |

The auth host holds the only cookie that can change anything, and no app is
ever served from it. That matters because a framed same-origin app shares the
portal's origin: a compromised one could script anything on that origin, so
login and admin live elsewhere.

The portal and each app host get their own **gate** cookie. A browser
without one is sent through a one-time handoff: the host sets a per-flow
state cookie, the auth host checks the login (asking for one if needed) and
redirects back with a 60-second code, and the host swaps that code for a gate
only if the browser still holds the matching state cookie. A code someone else
obtained is useless to you, so nobody can log you in as them.

For each app request, Caddy's `forward_auth` asks
`/_tabs/auth/verify?tab=<slug>`. Tabs checks the gate, its session and the
user's groups against that tab, and answers `200` with `Remote-User`,
`Remote-Name`, `Remote-Email` and `Remote-Groups`, `403`, or (for page loads
only) a redirect into the handoff. Each Caddy route names its tab: tabs never
works out the tab from the URL, because its idea of `..` or `%2f` could differ
from Caddy's.

## Users, groups and two-factor login

All of this is managed in the admin pages on the auth host. None of it is in
YAML.

- **First admin.** On first start with an empty database, tabs writes a
  one-time setup link to `setup-token` next to the database (not to the
  logs) and deletes it once the admin exists. The image has no shell, so read
  it from the volume, e.g.
  `docker run --rm -v tabs-data:/data busybox cat /data/setup-token`.
- **Users** have a lowercase username, display name, optional email
  (passed on as `Remote-Email`), groups and an admin flag. Users can set
  their own email and it isn't verified (tabs sends no mail), though no two
  accounts can share one, so apps should identify people by `Remote-User`,
  not `Remote-Email`. An admin can add
  someone with a temporary password (they must change it at first login) or
  get a one-time link for them to choose their own.
- **Invites** are links that let someone create their own account, landing in
  the invite's groups. Each has an expiry (up to 30 days) and a use count.
  Invites never make admins.
- **Groups** are what tab `groups:` in the YAML refer to (lowercase letters,
  digits, dashes). The groups page warns about tab groups that don't exist.
  Deleting a group removes it from users and open invites.
- **Two-factor login** is optional per user (account page: scan a QR code,
  confirm a code, save 10 one-time recovery codes). An admin can tick
  *Require two-factor* on a group: members without it must enrol before they
  can reach any app, effective on their next request. It can't be turned off
  while a group requires it. Codes can't be replayed.
- **Changing** a password, turning two-factor on or off, new recovery codes,
  or an admin changing someone's admin/disabled status ends all of that user's
  sessions (you stay logged in on the browser that made the change). Group
  changes apply on the next request without logging anyone out.
- **Failed logins** back off per username and address. Ten failures (password
  or code) from one address in 15 minutes ban it for an hour; the admin
  *Bans* page lists and lifts bans. A ban never locks an account, so nobody
  can lock you out from elsewhere. If you'd rather lock accounts too, set
  `TABS_LOCK_AFTER`; an admin then has to unlock them.
- **Locked out?** Stop the server and run
  `tabs recover <user> [--reset-totp]`; it prints a one-hour password link and
  unlocks the account.

## Configuration

Site-specific values (hostnames, app URLs, proxy subnet) live in the
environment and config file, never in this repo.

| Env var | Default | Purpose |
| --- | --- | --- |
| `TABS_AUTH_URL` | (required) | Auth host origin, e.g. `https://auth.example.com` |
| `TABS_PUBLIC_URL` | (required) | Portal origin, e.g. `https://tabs.example.com`; must be a different host |
| `TABS_TRUSTED_PROXIES` | (required) | Comma-separated IPs/CIDRs of the reverse proxy: the only callers verify answers, and whose `X-Forwarded-For` is believed (see [Trusted proxies](#trusted-proxies)) |
| `TABS_SECRET_KEY_FILE` | (required) | File holding the key that encrypts TOTP secrets; make one with `tabs genkey` |
| `TABS_DB` | `/data/tabs.db` | Database file; the directory must be writable |
| `TABS_CONFIG` | `/config/tabs.yaml` | Tabs config file |
| `TABS_ICONS_DIR` | `/config/icons` | Icon files |
| `TABS_LISTEN` | `:8080` | Listen address |
| `TABS_SESSION_IDLE` | `7d` | Log out after this long without activity (`7d`, `12h`, …) |
| `TABS_SESSION_MAX` | `30d` | Log out after this long regardless |
| `TABS_BAN_AFTER` | `10` | Failures from one address that ban it; `0` disables bans |
| `TABS_BAN_WINDOW` | `15m` | Window those failures are counted in |
| `TABS_BAN_DURATION` | `1h` | How long a ban lasts |
| `TABS_LOCK_AFTER` | `0` (off) | Consecutive failures that lock an account until an admin unlocks it |
| `TABS_INSECURE_COOKIES` | unset | `1` allows plain-HTTP origins for local development; refused unless both hosts are `localhost`/`*.localhost`/loopback |

The key file can end in a newline and holds 64 hex characters (or base64 of
32 bytes). Tabs refuses to start with a different key from the one the
database was created with. To rotate it, stop the server and run
`tabs rekey <new-key-file>`, then point `TABS_SECRET_KEY_FILE` at the new
file. Keep the key out of the database backups, or encrypting the secrets
gains nothing.

See [tabs.example.yaml](tabs.example.yaml). Each tab has:

- `slug`: unique, `^[a-z0-9-]+$`, used as the URL `#hash` and in Caddy's
  `verify?tab=`
- `name`: display name
- `url`: a same-origin path (`/app/`) or an absolute `https://` URL with a
  plain hostname. It may not point at this app (`/` or `/_tabs/...`) or the
  auth host.
- `icon` (optional): file name inside `TABS_ICONS_DIR`, one of `.svg .png
  .webp .ico .jpg .jpeg .gif`. Only those types are ever served from that dir.
- `groups` (optional): viewer must be in at least one; empty means any
  logged-in user.

Top-level `title` is optional. Unknown keys are rejected (`logoutURL` is gone:
tabs handles logout).

The config is read at startup (an invalid file fails startup) and re-read on
`SIGHUP` (an invalid file is logged and the old config kept):

```bash
docker kill --signal=HUP tabs
```

## Routes

| Host | Route | Response |
| --- | --- | --- |
| any | `GET /_tabs/healthz` | `200 ok`, no auth |
| any (trusted proxy only) | `GET /_tabs/auth/verify?tab=<slug>` | forward-auth answer; 404 to anyone else |
| portal | `GET /` | The sidebar, or the handoff |
| portal | `GET /_tabs/session` | `204` while the gate is good, else 401; the page's session check |
| portal | `POST /_tabs/logout` | Ends the session everywhere |
| portal | `GET /_tabs/static/*`, `/_tabs/icons/*` | Embedded CSS/JS; icons, no listings |
| portal, app hosts | `GET /_tabs/auth/start`, `/_tabs/auth/callback` | The handoff |
| auth | `/_tabs/login`, `/login/totp`, `/account`, `/setup`, `/invite/…`, `/reset/…`, `/admin/…`, `/auth/handoff`, `/logged-out` | Forms; every POST needs a same-origin `Origin` and, once logged in, a CSRF token |
| anything else | | 404 |

Pages on the auth host load no script at all. Every response has a strict
CSP (`frame-ancestors 'none'`), `nosniff` and
`Cross-Origin-Resource-Policy: same-origin`. All cookies are `__Host-`
prefixed, `Secure`, `HttpOnly` and `SameSite=Lax`. Invite, reset and setup
tokens are moved from the URL into a short-lived cookie on first visit and
redacted from the request log.

## Deploying

### Trusted proxies

Every address in `TABS_TRUSTED_PROXIES` can call verify and set the client
address used for bans, so the range should contain nothing but the reverse
proxy:

- **Use a dedicated network.** Put tabs on its own small Docker network that
  only the proxy also joins, and trust the range its containers are given
  (see the Compose example). `0.0.0.0/0` and `::/0` are refused.
- **Never publish the tabs port** (`ports:` in Compose). Docker's userland
  proxy makes outside clients appear to come from the network's gateway
  address.

### Compose

Substitute your own image, paths and subnet:

```yaml
services:
  tabs:
    container_name: tabs
    image: ghcr.io/computerswereamistake/tabs:<tag>
    restart: unless-stopped
    networks: [tabs-auth]                 # no `ports:`; only the proxy reaches it
    environment:
      TABS_AUTH_URL: https://auth.example.com
      TABS_PUBLIC_URL: https://tabs.example.com
      TABS_TRUSTED_PROXIES: 10.99.0.8/29  # = tabs-auth ip_range below
      TABS_SECRET_KEY_FILE: /run/secrets/tabs_key
    secrets: [tabs_key]
    volumes:
      - /path/to/tabs-config:/config:ro   # tabs.yaml + icons/
      - tabs-data:/data                   # the database
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "/tabs", "healthcheck"]

  caddy:
    # ...existing config...
    networks: [front, tabs-auth]          # front for the apps, tabs-auth for tabs

secrets:
  tabs_key:
    file: /path/to/tabs.key               # `docker run --rm <image> genkey > tabs.key`

volumes:
  tabs-data:

networks:
  tabs-auth:
    internal: true                        # no outbound access for tabs
    ipam:
      config:
        - subnet: 10.99.0.0/28
          gateway: 10.99.0.1              # the Docker host's side of the bridge
          ip_range: 10.99.0.8/29          # containers get .8-.15, never the gateway
```

A new named volume takes the image's `/data` ownership (uid 65532). With a
bind mount instead, `chown 65532` the directory yourself. Back up the volume;
the setup link, once used, can't be regenerated except with `tabs recover`.

### Caddy

Each app route runs `forward_auth` with its own tab slug. Tabs' own routes
are **not** behind `forward_auth` (tabs authenticates them itself):

```caddyfile
(tabs_gate) {
	forward_auth tabs:8080 {
		uri /_tabs/auth/verify?tab={args[0]}
		header_up X-Forwarded-Host {hostport}
		copy_headers Remote-User Remote-Name Remote-Email Remote-Groups
	}
	# The app doesn't need the gate cookie; don't hand it over.
	request_header Cookie "(^|;\s*)__Host-tabs_gate=[^;]*" ""
}

auth.example.com {
	reverse_proxy tabs:8080
}

tabs.example.com {
	handle /app-one/* {
		import tabs_gate app-one
		reverse_proxy app-one:80
	}
	handle {
		reverse_proxy tabs:8080           # /, /_tabs/*
	}
}

other.example.com {                       # a tab with url: https://other.example.com/
	handle /_tabs/auth/* {
		reverse_proxy tabs:8080           # the handoff; not gated
	}
	handle {
		import tabs_gate other
		reverse_proxy other:80
	}
}
```

- `forward_auth` replaces any client-sent `Remote-*` headers named in
  `copy_headers`, and `header_up X-Forwarded-Host {hostport}` keeps the
  forwarded host to the one the browser used.
- **Apps on the portal host trust each other.** They share one gate cookie;
  if the `request_header` line is ever wrong, a portal app's backend could
  replay a user's gate against other portal apps. Put apps you don't trust on
  their own host.
- Don't give two tabs with different `groups` the same upstream: the gate
  is only as precise as Caddy's path matching.
- Framed apps that send `X-Frame-Options: DENY` or a restrictive
  `frame-ancestors` will not load. **Replace** those headers rather than
  removing them, or the app becomes frameable by any site:
  - same-origin apps: `Content-Security-Policy: frame-ancestors 'self'` (and
    drop `X-Frame-Options`)
  - apps on another host: `frame-ancestors https://<tabs host>`

  Caddy example for one route: `header /app/* { -X-Frame-Options
  Content-Security-Policy "frame-ancestors 'self'" }`. If the app sends its
  own CSP, merge rather than overwrite.

### Migrating from Authelia

Authelia's users don't carry over. Create the groups your tabs use, invite
your users (or add them), remove Authelia's `forward_auth` from the tabs and
app routes, and use the snippet above. Remove `logoutURL` from `tabs.yaml`.

### Known behaviour

- **Expired sessions.** A framed app can't show the login page (it refuses
  to be framed), so the page checks `/_tabs/session` when you return to the
  browser tab, switch tabs, click or type inside a same-origin app, or an
  app navigates inside its frame (at most every 15 seconds). If two checks a
  second apart both say the session has expired, it reloads, so you go
  through login, and afterwards reopens the tab you were on. If the browser
  blocks storage, or the check still fails straight after such a reload, it
  shows a "Log in again" banner instead of reloading.
- **The idle timeout won't fire while tabs is open.** Many dashboard-style
  apps poll their APIs every few seconds, even in hidden frames, and every
  poll through verify counts as activity. The session then lasts until
  `TABS_SESSION_MAX`, so set that to something you're comfortable with for an
  unattended, unlocked machine. Tabs itself never polls.
- **Apps on a different site.** Apps on sibling subdomains of the portal
  (`*.example.com`) work in frames. Apps on an unrelated domain need
  third-party cookies inside a frame, which Safari and Firefox block by
  default; the "open in new tab" button still works.
- **Enrolment needs only the password.** If a group starts requiring
  two-factor, a member who hasn't enrolled can enrol with just their
  password, so someone who stole it first could enrol their own app. Ask
  members to enrol before you require it.
- Bans and backoff are kept in memory, so a restart clears them.

### Operations

- The icons dir is opened once at startup. Editing or adding files in it
  takes effect immediately; replacing the directory itself needs a restart
  (`SIGHUP` only re-reads the YAML).
- The container runs as the distroless `nonroot` user (uid 65532), so the
  mounted config and icons must be readable by it and `/data` writable.
- `recover` and `rekey` open the database directly, which the running server
  holds locked: stop it first, e.g.
  `docker compose run --rm --no-deps tabs recover alice`.
- Audit events (logins, failures, bans, every admin action) are logged as
  `"msg":"auth"` lines with the actor and target, never secrets.

## Development

```bash
go test ./... && go vet ./... && golangci-lint run
```

`go test` also runs the browser-script tests in
[internal/web/testdata](internal/web/testdata/app.test.mjs) through Node's
built-in test runner (no npm packages). Without Node installed they are
skipped locally; in CI a missing Node fails the build. To run them alone:

```bash
node --test internal/web/testdata/app.test.mjs
```

## CI and releases

[GitHub Actions](.github/workflows/ci.yml) runs on pushes to `main`, pull
requests and `v*` tags: gofmt, `go mod tidy`, `go vet`, golangci-lint
([config](.golangci.yml)), `go test -race` (including the JS tests),
govulncheck and gosec, then builds the image for
`linux/amd64` and `linux/arm64`. Only releases push the image.

Releases are automatic. On each push to `main`, CI derives the next version
from the [Conventional Commit](https://www.conventionalcommits.org/) messages
since the last `vX.Y.Z` tag, publishes the image, then pushes the tag:

| Commit message                                | Bump  |
| --------------------------------------------- | ----- |
| `feat!: …`, any `type!:`, `BREAKING CHANGE:`  | major |
| `feat: …`                                     | minor |
| `fix: …`, `perf: …`                           | patch |
| anything else (`chore`, `ci`, `docs`, …)      | none  |

The first release, with no tag yet, is `v0.1.0`. With squash merges, the PR
title is the commit message that counts. A hand-pushed `v*` tag still
publishes too.

A release publishes `ghcr.io/computerswereamistake/tabs:0.1.0` (plus `0.1` and
a `sha-…` tag). New GHCR packages start private; make it public, or give the
deploy host a read token, in the package settings. Actions are pinned to
commit SHAs and base images to digests; Dependabot proposes updates weekly.

To run locally over plain HTTP, use two `*.localhost` names (browsers
resolve them to loopback) behind a local Caddy with the snippet above, with
`auto_https off` and `http://` site addresses:

```bash
go run ./cmd/tabs genkey > /tmp/tabs.key
TABS_CONFIG=tabs.example.yaml TABS_ICONS_DIR=. TABS_DB=/tmp/tabs.db TABS_SECRET_KEY_FILE=/tmp/tabs.key TABS_TRUSTED_PROXIES=127.0.0.1 TABS_LISTEN=127.0.0.1:8090 TABS_AUTH_URL=http://auth.localhost:8080 TABS_PUBLIC_URL=http://tabs.localhost:8080 TABS_INSECURE_COOKIES=1 go run ./cmd/tabs
```

Then open the link in `/tmp/setup-token`.
