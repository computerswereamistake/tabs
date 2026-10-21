# tabs

A minimal replacement for Organizr's tabbed UI: a sidebar of apps, each loaded
in an iframe, filtered by the viewer's groups.

`tabs` does **no authentication**. It expects to sit behind a reverse proxy
doing forward-auth (e.g. Caddy + Authelia), which sets `Remote-User`,
`Remote-Name`, `Remote-Email` and `Remote-Groups`. Those headers are only
believed when the request comes from an address in `TABS_TRUSTED_PROXIES`.

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
| `TABS_TRUSTED_PROXIES` | (required) | Comma-separated CIDRs/IPs allowed to send identity headers |

See [tabs.example.yaml](tabs.example.yaml). Each tab has:

- `slug`: unique, `^[a-z0-9-]+$`, used as the URL `#hash`
- `name`: display name
- `url`: a same-origin path (`/app/`) or an absolute `https://` URL
- `icon` (optional): file name inside `TABS_ICONS_DIR`
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
| `GET /_tabs/healthz` | `200 ok`, no auth |
| anything else | 404; methods other than GET/HEAD get 405 |

Every response carries a strict CSP; `frame-src` is `'self'` plus the origins
of any absolute tab URLs.

## Deploying

Compose example (substitute your own image, network and subnet):

```yaml
tabs:
  container_name: tabs
  image: ghcr.io/computerswereamistake/tabs:<tag>
  restart: unless-stopped
  networks: [front]
  environment:
    TABS_TRUSTED_PROXIES: 172.16.0.0/12   # your proxy network's subnet: docker network inspect <network>
  volumes:
    - /path/to/tabs-config:/config:ro     # tabs.yaml + icons/
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  healthcheck:
    test: ["CMD", "/tabs", "healthcheck"]
```

Reverse proxy notes:

- Route `/` (and `/_tabs/*`) to `tabs:8080` after `forward_auth`, and make sure
  the proxy strips client-supplied `Remote-*` headers.
- Framed apps must not send `X-Frame-Options: DENY` or a restrictive
  `frame-ancestors`; override those headers in the proxy for that route if
  needed.

## Development

```bash
go test ./... && go vet ./...
```

```bash
TABS_CONFIG=tabs.example.yaml TABS_ICONS_DIR=. TABS_TRUSTED_PROXIES=127.0.0.1 TABS_LISTEN=127.0.0.1:8080 go run ./cmd/tabs
```

Locally, send the identity headers yourself, e.g. with a browser extension or
`curl -H 'Remote-User: me' -H 'Remote-Groups: users' http://127.0.0.1:8080/`.
