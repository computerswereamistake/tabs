# tabs

A minimal replacement for Organizr's tabbed UI: a sidebar of apps, each loaded
in an iframe, filtered by the viewer's groups.

`tabs` does **no authentication**. It expects to sit behind a reverse proxy
doing forward-auth (e.g. Caddy + Authelia), which sets `Remote-User`,
`Remote-Name`, `Remote-Email` and `Remote-Groups`. Those headers are only
believed when the request comes from an address in `TABS_TRUSTED_PROXIES`.

> **Tabs is not an access-control layer.** Group filtering only decides which
> tabs appear in the sidebar; a viewer who cannot see a tab can still type its
> URL. Enforce who may reach each app in the reverse proxy and auth server
> (e.g. Authelia `access_control` rules per path or host), and treat `groups`
> here as a convenience that should mirror those rules.

Design goals: small attack surface. Stdlib Go plus one YAML library, no
database, no writes, no outbound network, distroless image.

## Configuration

All site-specific values (hostnames, app URLs, logout URL, proxy subnet) live
in the config file and environment, never in this repo.

| Env var | Default | Purpose |
| --- | --- | --- |
| `TABS_CONFIG` | `/config/tabs.yaml` | Config file path |
| `TABS_ICONS_DIR` | `/config/icons` | Icon files |
| `TABS_LISTEN` | `:8080` | Listen address |
| `TABS_TRUSTED_PROXIES` | (required) | Comma-separated IPs/CIDRs allowed to send identity headers (see [Trusted proxies](#trusted-proxies)) |

See [tabs.example.yaml](tabs.example.yaml). Each tab has:

- `slug`: unique, `^[a-z0-9-]+$`, used as the URL `#hash`
- `name`: display name
- `url`: a same-origin path (`/app/`) or an absolute `https://` URL with a
  plain hostname. It may not point at this app (`/` or `/_tabs/...`).
- `icon` (optional): file name inside `TABS_ICONS_DIR`, one of `.svg .png
  .webp .ico .jpg .jpeg .gif`. Only those types are ever served from that dir.
- `groups` (optional): viewer must be in at least one; empty means any
  authenticated viewer. Matching is exact and case-sensitive.

Top-level `title` and `logoutURL` are optional. Unknown keys are rejected.

The config is read at startup (an invalid file fails startup) and re-read on
`SIGHUP` (an invalid file is logged and the old config kept):

```bash
docker kill --signal=HUP tabs
```

## Routes

| Route | Response |
| --- | --- |
| `GET /` | The page; 401 without a trusted `Remote-User` |
| `GET /_tabs/static/*` | Embedded CSS/JS |
| `GET /_tabs/icons/*` | Icons from `TABS_ICONS_DIR`; no listings |
| `GET /_tabs/session` | `204` while forward-auth identifies the viewer, else 401; the page's session check |
| `GET /_tabs/healthz` | `200 ok`, no auth |
| anything else | 404; methods other than GET/HEAD get 405 |

Every response carries a strict CSP; `frame-src` is `'self'` plus the origins
of any absolute tab URLs.

## Deploying

### Trusted proxies

Every address in `TABS_TRUSTED_PROXIES` can claim to be any user, so the
range should contain nothing but the reverse proxy:

- **Use a dedicated network.** Put tabs on its own small Docker network that
  only the proxy also joins, and trust the range its containers are given
  (see the Compose example). The proxy keeps a dynamic IP. Trusting a shared
  network's subnet instead trusts every container on it, including the apps
  you frame. `0.0.0.0/0` and `::/0` are refused.
- **Never publish the tabs port** (`ports:` in Compose). Docker's userland
  proxy makes outside clients appear to come from the network's gateway
  address, so a published port inside a trusted range lets anyone forge
  identity headers.
- The proxy must remove client-supplied `Remote-*` headers before forward-auth
  sets them. A request with any identity header repeated gets 401, in case a
  proxy appends rather than replaces.

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
      TABS_TRUSTED_PROXIES: 10.99.0.8/29  # = tabs-auth ip_range below
    volumes:
      - /path/to/tabs-config:/config:ro   # tabs.yaml + icons/
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "/tabs", "healthcheck"]

  caddy:
    # ...existing config...
    networks: [front, tabs-auth]          # front for the apps, tabs-auth for tabs

networks:
  tabs-auth:
    internal: true                        # no outbound access for tabs
    ipam:
      config:
        - subnet: 10.99.0.0/28
          gateway: 10.99.0.1              # the Docker host's side of the bridge
          ip_range: 10.99.0.8/29          # containers get .8-.15, never the gateway
```

Containers still get dynamic addresses, but always from `ip_range`, so
trusting that range trusts only Caddy and tabs. The gateway address belongs to
the Docker host, and any process on the host connects to the network from it,
which is why it sits outside the trusted range. Pick a subnet that doesn't
clash with your other networks.

### Reverse proxy

- Route `/` and `/_tabs/*` to `tabs:8080` after `forward_auth`. In
  particular `/_tabs/session` must go through `forward_auth` under the same
  Authelia rule as `/` (same policy, e.g. not two-factor for one and
  one-factor for the other), or the page will think the session has expired
  and show a "Log in again" banner.
- Framed apps that send `X-Frame-Options: DENY` or a restrictive
  `frame-ancestors` will not load. **Replace** those headers rather than
  removing them, or the app becomes frameable by any site:
  - same-origin apps: `Content-Security-Policy: frame-ancestors 'self'` (and
    drop `X-Frame-Options`)
  - apps on another host: `frame-ancestors https://<tabs host>`

  Caddy example for one route: `header /app/* { -X-Frame-Options
  Content-Security-Policy "frame-ancestors 'self'" }`. If the app sends its
  own CSP, merge rather than overwrite.

### Known behaviour

- **Expired sessions.** A framed app can't show the login page (it refuses
  to be framed), so the page checks `/_tabs/session` when you return to the
  browser tab, switch tabs, click or type inside a same-origin app, or an
  app navigates inside its frame (at most every 15 seconds). If two checks a
  second apart both say the session has expired, it reloads, so the proxy
  sends you to login, and afterwards reopens the tab you were on. If the
  browser blocks storage, or the check still fails straight after such a
  reload, it shows a "Log in again" banner instead of reloading. For apps on
  another host, only the tab-level moments apply.
- **Authelia's inactivity timeout won't fire while tabs is open.** Many
  dashboard-style apps poll their APIs every few seconds, even in hidden frames, and
  every poll through `forward_auth` counts as activity. The session then
  lasts until Authelia's absolute `expiration`, so set that to something
  you're comfortable with for an unattended, unlocked machine. Tabs itself
  never polls, so it adds nothing to this.
- Framed same-origin apps share an origin with tabs, so a script-injection
  bug in one of them can reach the tabs page. Keep the apps patched; serving
  tabs on its own host is the stronger isolation if you need it.

### Operations

- The icons dir is opened once at startup. Editing or adding files in it
  takes effect immediately; replacing the directory itself needs a restart
  (`SIGHUP` only re-reads the YAML).
- The container runs as the distroless `nonroot` user (uid 65532), so the
  mounted config and icons must be readable by it.

## Development

```bash
go test ./... && go vet ./...
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
requests and `v*` tags: gofmt, `go mod tidy`, `go vet`, `go test -race`
(including the JS tests), govulncheck and gosec, then builds the image for
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

```bash
TABS_CONFIG=tabs.example.yaml TABS_ICONS_DIR=. TABS_TRUSTED_PROXIES=127.0.0.1 TABS_LISTEN=127.0.0.1:8080 go run ./cmd/tabs
```

Locally, send the identity headers yourself, e.g. with a browser extension or
`curl -H 'Remote-User: me' -H 'Remote-Groups: users' http://127.0.0.1:8080/`.
