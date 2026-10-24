# dot-auth

Open-source authentication for Godot games and dedicated servers, wired to the website-city backbone. A client signs in to the backbone with the device flow; a publisher-run issuer turns that into a short-lived ticket for ONE server; the server verifies it offline. Plus LAN accounts, self-service local profiles, guests, pluggable providers, server self-reporting to the backbone, and site groups mapped to server admin flags.

Read the family [CLAUDE.md](../../CLAUDE.md) and [docs/backbone.md](../../docs/backbone.md) first; this file is only what is specific to authentication. The reasoning is in [docs/](docs/README.md).

**The distributable is `addons/dot_auth/`. It requires dot-core** (API level in `dot_auth_api.gd`), linked locally (`ln -s ../../dot-core/addons/dot_core addons/dot_core`, gitignored; [development setup](../../docs/development-setup.md)). dot-auth and dot-server never import each other. [strategies](docs/strategies.md#coupling-with-dot-server)

## Read before

| Read | Before |
| --- | --- |
| [docs/README.md](docs/README.md) | the index |
| [docs/tickets.md](docs/tickets.md) | `DotAuthTicket`, `DotAuthIssuer`, `DotAuthSessionReporter`, `single_session`, the issuer's listener |
| [docs/strategies.md](docs/strategies.md) | `DotAuthServer`, the strategies, `allow_guests`, local profiles, `DotAuthProvider`, what is deliberately not here |
| [docs/backbone.md](docs/backbone.md) | `DotAuthClient`, `DotBackboneClient`, any backbone endpoint, `backbone_url` |
| [docs/security.md](docs/security.md) | `DotJwt`, hashing, the token store, admin mapping, display names |
| [docs/history.md](docs/history.md) | the bugs, and how each looked |

## Layout

| Path | What |
| --- | --- |
| `addons/dot_auth/dot_auth_config.gd` | strategies and endpoints; `validate()` enforces the invariants |
| `addons/dot_auth/dot_auth_identity.gd` | who a player is; `uid` is namespaced `provider:id` |
| `addons/dot_auth/util/` | `DotJwt` (compact JWS, algorithm pinned by the verifier), `DotPkce` |
| `addons/dot_auth/client/` | `DotAuthClient` (device flow, rotating refresh, tickets, `post_app` / `get_app`), `DotAuthTokenStore` (read the caveat), `DotAuthWebHandoff` |
| `addons/dot_auth/local/` | `DotLocalProfiles`, `DotLocalProfileProvider`, `DotLocalProfileClient` (the client's secrets, keyed by server) |
| `addons/dot_auth/server/` | `DotAuthTicket` (read the class doc), `DotAuthIssuer` (minting and the session table), `DotAuthSessionReporter`, `DotAuthProvider`, `DotAuthServer` (registers as `dot_auth_server`) |
| `addons/dot_auth/backbone/` | `DotBackboneClient`: server self-reporting; `post_integration` / `get_integration` are the seams other addons use |
| `addons/dot_auth/bridge/` | `DotAuthAdminSource`: site groups to server permission flags, duck-typed for dot-server |
| `addons/dot_auth/dot_auth_api.gd` | the API level (`LEVEL`, `OLDEST`); the bump rule is on `DotAddonApi` |
| `examples/auth_demo.tscn` | the suite, offline (binds `127.0.0.1:18787` for the issuer's listener; skips those checks with a line if the port is taken) |
| `examples/cfg_selftest.tscn` | `auth.yml` from `cfg/addons/dot_auth/`, `cfg/server/addons/dot_auth/` over it, the flat `cfg/auth.yml` shim (WARN once, removed 2026-12-31); secrets stay file-only |
| `examples/session_reporter_selftest.tscn` | a stopping `DotServer` frees its players' seats on its report; needs dot-server linked (`ln -s ../../dot-server/addons/dot_server addons/dot_server`, gitignored); binds `127.0.0.1:18795`-`18799` |
| `examples/issuer.tscn` | the issuer as a daemon; never exits, so no smoke test covers it |

## Running and testing

- The family's two steps ([game-dev/CLAUDE.md](../../CLAUDE.md#validating-anything)), then `godot --headless --path . res://examples/auth_demo.tscn` and `timeout 120 godot --headless --path . res://examples/session_reporter_selftest.tscn`. Each exits non-zero on any failure. auth_demo covers everything but the device flow itself, which needs a live backbone and a person clicking Approve.
- **Add a case to the demo for any change to the ticket, JWT or admin-mapping paths**: a bug there is a vulnerability rather than a crash.
- Changing the issuer's listener: drive it with a socket that writes headers and body separately; one `curl` passes either way. [tickets](docs/tickets.md#running-the-issuer)

## Rules that bite

**Tickets and sessions**

- A server never receives a player's backbone token on a public server: `TICKET` is for public servers, `INTROSPECT` for first-party only, and even then the client sends a single-use join token minted for the announced audience, never `valid_access_token()`. A client sends only the credential asked for. [strategies](docs/strategies.md#introspect-never-hands-a-server-the-access-token) [tickets](docs/tickets.md#the-central-design-problem-and-the-answer)
- A ticket is audience-scoped, minutes long, single-use and RS256. `validate()` refuses `TICKET` without `server_id` and replay memory not longer than the ticket's life. A client asks for one by the address it dialled, never the announced id; an adopting server verifies nothing until it holds an id and a key from its own backbone. [tickets](docs/tickets.md#the-backbones-own-issuer-by-dialled-address) [tickets](docs/tickets.md#the-central-design-problem-and-the-answer)
- `single_session` lives on the issuer; rosters are absolute; an unconfirmed session is never ended by a roster; `session_lease_sec >= ticket_ttl_sec`; server keys are per server. [tickets](docs/tickets.md#one-seat-per-account)
- `DotAuthServer` builds the `DotAuthSessionReporter` when `session_report_url` is set and follows the registry's `dot_server`; the roster is every signed-on session, not only those in play. [tickets](docs/tickets.md#who-builds-the-reporter-and-which-stops-it-reports)
- The goodbye is synchronous (`report_offline_now()`, bounded): `shutdown()` and `quit()` report; SIGINT/SIGTERM/kill do not and fall to the lease. [tickets](docs/tickets.md#who-builds-the-reporter-and-which-stops-it-reports)
- The issuer's listener goes behind a reverse proxy; requests are buffered across polls and bounded in total, not per read. [tickets](docs/tickets.md#running-the-issuer)

**Accounts**

- A local profile's identity is a server-issued secret: never a name, a machine id or a password. The secret travels on `profile_created`, never on the identity (identities are relayed to every player). Sign-in and sign-up are separate credentials. [strategies](docs/strategies.md#local-profiles-accounts-with-no-cloud)
- A local profile id is a player key (22 base64url characters); nothing downstream branches on account kind. [strategies](docs/strategies.md#the-id-is-a-player-key-unchanged)
- A new auth method is a `DotAuthProvider`: `_handles()` cheap and structural, a claimed credential owns its outcome, uids namespaced with `:`. [strategies](docs/strategies.md#adding-an-authentication-method)

**Security**

- `DotJwt` pins RS256 at the call site; never dispatch on the token's `alg`. [security](docs/security.md)
- MACs compare in constant time; unknown user and wrong password (and the like) answer identically, timing included. [security](docs/security.md)
- Only guests choose their name; guests never get admin flags; `role_flags` is empty by default. [security](docs/security.md)
- `hash_password` is for LAN files only; web token-store encryption is obfuscation. [security](docs/security.md#two-things-that-are-weaker-than-they-look)

**Backbone**

- Device-flow poll outcomes are 202 envelopes; honour `slow_down`; `token_reuse` means every device was signed out. [backbone](docs/backbone.md#contracts-this-code-depends-on)
- Integration requests carry `ts` in seconds and a `nonce`, stamped only in `_stamp()`. Roster reports are absolute; `report_roster` is off by default. [backbone](docs/backbone.md#contracts-this-code-depends-on)
- `backbone_url` is a security property: check any default against what website-city serves; a web client gets it from a shipped JSON file, never the query string. [backbone](docs/backbone.md#the-backbone-url-is-a-security-property)

## Where a game plugs in

| To change | Where |
| --- | --- |
| How a server authenticates | `DotAuthConfig.strategy`, `allow_guests`, `allow_local_profiles` |
| A new sign-in method | `DotAuthProvider` subclass, `auth_server.add_provider(...)` |
| One seat per account | `DotAuthConfig.single_session` on the issuer; `session_report_url` / `_key` on the server (the auth server builds the reporter); `create_session_reporter = false` plus your own `roster_provider` for a host without dot-server |
| Which site groups are admins | `DotAuthAdminSource` and `role_flags` |
| Where the backbone is | `backbone_url` via env, argv or JSON (web: a shipped JSON file) |
| What a server reports to the site | `DotBackboneClient.report_stats` / `report_users`, `report_roster` |
| Anything a player reports about themselves | `DotAuthClient.post_app` / `get_app` |
| Embedding the issuer in another service | `listen_port = 0`, `issue_for_token()` |

Deliberately not here: the OAuth authorization-code flow, platform SSO, Ed25519, token binding to a connection. [strategies](docs/strategies.md#deliberately-not-here)
