# dot-auth

Open-source authentication for Godot games and dedicated servers, wired to the
website-city backbone at `~/stack/website-city`.

**The distributable is `addons/dot_auth/`.** It requires
[dot-core](../dot-core), a separate repository.

```bash
# Local development setup — the symlink is gitignored on purpose.
ln -s ../../dot-core/addons/dot_core addons/dot_core
```

## The central design problem, and the answer

A player has an account on the backbone. A **community-run** game server needs to
know who they are. The obvious implementation — the client sends its backbone
access token, the server calls `/api/app/v1/me` — hands every server operator a
live credential for the player's entire site account.

That is unacceptable for a game with third-party servers, and it is exactly why
Platforms issue auth session tickets rather than sharing session cookies.

So dot-auth has three participants:

```
  client ──(device-code + PKCE)──> backbone            "who am I"
  client ──(access token)────────> DotAuthIssuer       first-party, publisher-run
  client <──(signed ticket)─────── DotAuthIssuer       scoped to ONE server, minutes
  client ──(ticket)──────────────> game server         verified OFFLINE, no round trip
```

`DotAuthIssuer` is the piece the publisher runs. It is the **only** component that
needs the private key or backbone credentials. Server operators get a public key
and nothing else.

Four properties make a ticket safe. Dropping any one breaks it:

| Property | Where | Why |
| --- | --- | --- |
| Audience-scoped (`aud` = server id) | `DotAuthTicket.verify` | A ticket captured on server A is refused by B, so a malicious operator cannot replay their players' tickets elsewhere. |
| Short-lived (minutes) | `ticket_ttl_sec` | It only has to survive "asked for it" → "connected". |
| Single-use (`jti` remembered) | `DotAuthServer._spent_tickets` | A ticket captured in flight cannot be used twice inside its window. |
| Asymmetrically signed (RS256) | `DotJwt` | With HS256 every verifying server could *forge* a ticket for any player. |

`DotAuthConfig.validate()` refuses `TICKET` without a `server_id`, and refuses
`ticket_replay_memory_sec <= ticket_ttl_sec` — otherwise a ticket outlives the
record of having been spent and is replayable in the gap.

## One seat per account

`DotAuthConfig.single_session` makes the issuer refuse a ticket for one server
while the player is on another. It is off by default.

**It lives on the issuer because the issuer is the only participant that sees
every server.** A game server knows its own roster and nothing about anybody
else's, and having servers compare notes would mean operators trusting each
other — the thing the ticket design exists to avoid. So the issuer keeps a table
of `uid -> server`, and `issue_for_identity()` consults it before minting.

A ticket says where a player is *going*; it does not say they arrived or when
they left. Three things end a session, and the option is only as good as they
are:

| Ends it | How | Who |
| --- | --- | --- |
| **The server's roster** | `POST /session {serverId, users}` with the server's key. Absolute, like the backbone's: absent means gone, an empty list means empty. `DotAuthSessionReporter` sends one on a timer and an empty one on the way down. | Authoritative. The only one that can hold a player for a whole match and free them the moment they leave. |
| **The player** | `POST /session/release` with their access token; `DotAuthClient.release_session()`. Ends only the session behind that token. | The polite fast path on disconnect. A player still on a server is put back by its next report. |
| **The lease** | `session_lease_sec` (300) without word from a server. | What a non-reporting server's players get: held for the lease after their ticket, then let go, playing or not. |

Rules that were each the answer to a bug the demo would otherwise have found:

- **A ticket for the server a player is already on is always granted.** A
  crashed client has to be able to reconnect. And it must not demote a
  *confirmed* session to unconfirmed, or the next roster to omit them for a
  moment could not end it.
- **A roster does not end an unconfirmed session.** The server is telling the
  truth — the player has not arrived yet — but acting on it would let a player
  collect tickets for two servers in the seconds between the first being minted
  and the first roster naming them. An unconfirmed session lapses on its own.
- **A roster moves a player the table had elsewhere.** The report is the truth
  about where they are. Refusing to believe it holds them on a server they left.
- **`session_lease_sec >= ticket_ttl_sec`**, enforced by `validate()`. A lease
  shorter than the ticket lets a player hold a live ticket for one server after
  the issuer has forgotten the session, and get a second one for another.
- **Server keys are per server, in a file, and at least 16 characters.** A
  report can only speak for the server whose key it carries: a key for
  `eu-west-1` reporting `us-east-2`'s roster is refused as unauthenticated.
  Unknown server and wrong key answer identically, in constant time, so a
  caller learns neither which servers report nor how much of a key was right.
  Without a key anyone could report any player as being anywhere, which would
  lock them out of everywhere else on the strength of a POST.
- **The refusal names the server.** "You are already connected to eu-west-1"
  is the player's own whereabouts and is what they need to act on.
  `DotAuthClient._issuer_refusal()` is what carries that message through
  `DotHttp`'s generic "Not allowed." — the issuer's `{error, code}` body is
  kept as the error's detail, the same way `_envelope_code()` recovers the
  backbone's.

The demo runs the roster path **over a real socket** through the issuer's own
listener, because the endpoint is the one part of this a direct call cannot
reach. The game side is not wired: dot-server does not yet create a
`DotAuthSessionReporter` the way dot-2d-hungry's module creates a
`DotBackboneClient`. The host gives it the same roster, as uids, through
`roster_provider`, and calls `report_offline()` before it stops.

## The four strategies

`DotAuthConfig.strategy` decides how `DotAuthServer.authenticate()` behaves, so
one server binary covers every deployment:

| Strategy | Use | Cost |
| --- | --- | --- |
| `TICKET` | **Public servers.** | Needs a publisher-run issuer. No per-join network call. |
| `INTROSPECT` | First-party servers only. | Operator holds a live account credential; a backbone round trip per join. Warns loudly at startup. |
| `LOCAL` | LAN, development. | Accounts in a JSON file. Password hashing is salted SHA-256 × 4096 — see the caveat below. |
| `ANONYMOUS` | Open servers. | Nobody is authenticated; bans cannot mean anything. Warns. |

`allow_guests` layers a guest fallback onto any strategy, and warns, because a
banned player can always return as a different guest.

## Local profiles: accounts with no cloud

`allow_local_profiles` is a fifth option that is deliberately **not** a strategy.
It is a `DotAuthProvider`, so it composes: a server can take backbone tickets
*and* let a visitor with no site account make one that lives here, and a player
without an account is not turned away from a game whose other players have one.

**Different from `LOCAL`.** That strategy is an operator-maintained file of
usernames and passwords, for a server with a known cast. This is self-service: a
visitor names themselves and is the same player next week.

### The identity is a credential the server ISSUES

This is the whole design, and it is the part to defend. On first join the server
mints an id and a 32-byte secret, stores only a salted hash, and hands the secret
to the client once; the client keeps it **per server** and presents it next time.
A session cookie, essentially.

Every alternative was worse, and each is written down in `DotLocalProfiles`
because each is the one somebody will propose again:

- **A name.** An offline mode hashes the name into the uuid, and the
  well-known consequence is that anyone who types your name is you.
- **A machine id.** `device_hint()` exists and is *not* the identity.
  `OS.get_unique_id()` returns **nothing at all on web and iOS**, and a browser
  is a first-class target for this family — so anything requiring it simply does
  not work there. It is also just a string the client sends, so it is exactly as
  forgeable as a name while looking authoritative, and it is stable across
  *accounts* as well as installs, so two people sharing a machine are one player.
  It is stored on creation and compared on verify **only to log** that a profile
  moved machine. Enforcing it would lock players out for replacing a computer.
- **A password.** Puts a login form in front of somebody who wanted to play, and
  lands a password store on a game server.

### Three things that are load-bearing

**The secret travels on `profile_created`, never on the identity.** An identity
is *relayed* — dot-server sends one to every player in the match so they can draw
each other's names — so a secret on it would be broadcast to the lobby. The
signal fires synchronously inside `authenticate()`, so the peer being admitted is
unambiguous. The demo asserts the secret does not appear in `identity.to_dict()`.

**An unknown id and a wrong secret answer identically.** Distinguishing them
hands an attacker the list of ids that exist, which is what they would need
before guessing anything else.

**Sign-in and sign-up are separate credentials.** `local_profile` versus
`local_profile_new`. Folding them into "create it if the id is unknown" turns
every mistyped or lost credential into a brand new profile, so a player whose
secret was lost silently becomes a stranger with their own name taken.

### The id is a player key, unchanged

22 base64url characters — the same shape `DotUserScope` derives and
`DotAvatarKey.is_usable` accepts. So a local profile files a profile and an
avatar through exactly the same store interfaces a backbone-backed player does,
and **nothing downstream branches on which kind of account it is**: point
dot-user and dot-user-avatar at their `local` backends and the whole platform
works with no backbone at all.

The demo restates the key-shape check as `DotAvatarKeyShape` rather than calling
dot-user-avatar's, because that agreement between two addons that never import
each other is the thing being tested.

## Adding an authentication method

The four strategies do not cover a store or console platform, a chat service, a
publisher's own account service, a LAN token or a QA bypass — and a game needing one should not fork this.
Subclass `DotAuthProvider` and register it:

```gdscript
auth_server.add_provider(PlatformProvider.new())
```

Providers are consulted **before** the configured strategy, in priority order. Three
rules the implementation enforces so they compose safely:

- **`_handles()` must be cheap and structural** — "does this dictionary contain my
  field". A provider doing network work there runs it for logins meant for somebody
  else.
- **A provider that claims a credential owns the outcome.** If it authenticates and
  then refuses, the built-in strategy does *not* get a second go — otherwise a
  refused login walks in through another door.
- **Namespace your uids.** `uid` is what bans and admin entries key on. Two
  platforms' account ids are both digits; unprefixed, a ban on one applies to
  whoever holds the other. `DotAuthProvider.authenticate` warns when a uid has no `:` in it.

Rate limiting runs before providers, so a custom provider cannot be used to make this
server hammer an external service.

## Backbone contracts this code depends on

Verified against the real source, not guessed. If these drift, dot-auth breaks
here:

| Endpoint | Contract source | Used by |
| --- | --- | --- |
| `POST /api/app/v1/auth/device` | `~/types/app-api/contract.ts` `DeviceStartRequest` | `DotAuthClient.start_device_login` |
| `POST /api/app/v1/auth/token` | `DeviceTokenRequest`, `TokenResponse` | `DotAuthClient._poll_for_token` |
| `POST /api/app/v1/auth/refresh` | `RefreshRequest` | `DotAuthClient.refresh` |
| `POST /api/app/v1/auth/revoke` | — | `DotAuthClient.sign_out` |
| `GET /api/app/v1/me` | `SessionUserSchema` | issuer + `INTROSPECT` |
| `POST /api/content/server/integration/stats` | `~/types/integration/server.ts` `IngestServerStatsInput` | `DotBackboneClient.report_stats` |
| `POST /api/content/server/integration/users` | `IngestServerUsersInput` | `DotBackboneClient.report_users` |
| `GET /api/integration/v1/user/lookup` | `IngestUserLookupInput` | `DotBackboneClient.lookup_user` |

Details that are easy to get wrong and are already handled:

- **Poll outcomes are 202 with an error envelope**, not HTTP failures.
  `authorization_pending`, `slow_down`, `access_denied`, `expired_token` are read
  from the JSON `code`, which `DotHttp` preserves as the error's detail.
  `_envelope_code()` recovers it without a second request.
- **`slow_down` must be honoured** over the configured interval. Polling faster
  than told burns the grant.
- **`token_reuse` on refresh is not a generic error.** The backbone has signed
  every device out. `DotAuthClient` clears the store and emits
  `session_revoked` so the UI can show a security notice.
- **`ClientInfoSchema.platform` has no `web` member.** A browser build reports
  `unknown` via `DotPlatform.backbone_platform()` rather than failing validation.
- **Integration requests need `ts` (Unix *seconds*) and `nonce`.** Milliseconds
  are refused loudly by the backbone's skew window. `DotBackboneClient._stamp()`
  is the only place this is done.
- **Roster reports are absolute, not incremental.** An empty list closes every
  session. A server that does not know its roster must not call the endpoint.
  When the list is truncated at 512, `setCount` is forced off — otherwise it
  would report a count lower than the truth every tick.
- **`SERVER_STATS` and `SERVER_USERS` are separate scopes** on purpose: a player
  list is personal data about third parties. `report_roster` is off by default.

## The endpoint that does not exist yet

The ticket flow needs the client to exchange a backbone token for a scoped
ticket. `DotAuthIssuer` implements that **as a standalone service** using only
existing backbone endpoints (`/api/app/v1/me`), so nothing needs adding to
website-city to deploy this today.

If it later becomes worth folding into the backbone, the natural shape is
`POST /api/app/v1/auth/ticket` taking `{serverId}` with a bearer access token and
returning `{ticket, expiresIn}` — the same contract `DotAuthIssuer` serves. That
would remove a hop and let the backbone rate-limit centrally. Not required.

## Security decisions worth not undoing

- **`DotJwt` pins the algorithm at the call site.** `verify_rs256` requires
  `alg == "RS256"` and refuses anything else. Reading `alg` from the token and
  dispatching on it is the classic JWT vulnerability: you get handed
  `{"alg":"none"}`, or an HS256 token signed with the RSA *public* key as the HMAC
  secret. `examples/auth_demo.tscn` tests exactly that attack.
- **Every MAC comparison is constant-time** (`DotHash.constant_time_equal`).
  Early-return comparison leaks how many leading bytes were right, turning
  forgery into 32 rounds of 256 tries.
- **Unknown username and wrong password are indistinguishable** — same code, same
  message, and the hash runs either way so the timing matches too.
- **An authenticated player cannot override their display name**; only guests may
  name themselves. `_apply_requested_name()` enforces it, and the demo tests that
  "Ada" cannot connect as "Administrator".
- **Guests never get admin flags.** `DotAuthAdminSource.lookup()` refuses them
  outright — a guest uid is a random per-device string, so granting anything would
  grant it to anyone who asks.
- **`role_flags` is empty by default.** A site moderator is *not* automatically an
  admin on every community server running this addon. Shipping that default would
  hand anyone with a site role control of every server.
- **Secrets are refused from environment and argv** (`sensitive_keys()`): both are
  readable by other processes and end up in `ps` output and pasted bug reports.

### Two things that are weaker than they look

**`DotAuthServer.hash_password` is salted SHA-256 with 4096 rounds.** That is not
adequate for a public account system — passwords deserve argon2 or bcrypt, and
Godot ships neither. It exists so a LAN server does not keep plaintext in a JSON
file. Anything with real users belongs on the backbone, which does it properly.

**`DotAuthTokenStore` encryption is obfuscation on web.** The key derives from a
per-install salt stored next to the ciphertext plus a device-stable string. Against
another user on the machine, that works. Against the machine's owner, or anything
running as the same user, it does not. On web everything is in one origin, so
devtools recovers both halves. It still raises the cost of the common cases (synced
backups, shared PCs, files in support bundles) and makes tampering detectable.

## Validating changes

```bash
godot --headless --path . --import
find . -name '*.gd' -not -path './.godot/*' | while read f; do
    godot --headless --path . --check-only --script "res://${f#./}"
done

# 124 checks, all offline. Exits non-zero on any failure.
godot --headless --path . res://examples/auth_demo.tscn
```

Offline includes the session half: it binds `127.0.0.1:18787` for the issuer's
listener and points the issuer's backbone at a dead local port, so nothing in the
suite can reach the real site. If the port is taken, the socket checks are
skipped with a line saying so rather than failed.

The demo covers everything except the device flow itself, which needs a live
backbone and a human clicking Approve. **Add a case to it for any change to the
ticket, JWT or admin-mapping paths** — those are the ones where a bug is a
vulnerability rather than a crash.

## Running the issuer

```bash
godot --headless --path . res://examples/issuer.tscn -- \
    --auth-backbone-url https://themodcommunity.com
```

with `private_key_file` pointing at the key. The built-in listener speaks enough
HTTP/1.1 for one JSON POST and has no TLS, keep-alive or chunked encoding — **put
it behind a reverse proxy**, which is where TLS, real request limits and access
logs belong. It binds `127.0.0.1` by default and warns if you bind wider.

What it does implement, because a request does not arrive in one read:

- **The request is buffered across polls** and dispatched only once the headers
  and a full `Content-Length` body are present. Parsing whatever one poll saw
  treats a TCP segment boundary as the end of the request — a body arriving in a
  second segment was answered `400 Expected a JSON body`, which localhost testing
  never shows because a small request is coalesced into one segment.
- **`Expect: 100-continue` gets its interim response.** curl sends it for any body
  over ~1 KB and waits before writing, so without this the body only arrives once
  the client times out waiting.
- **`max_request_bytes` bounds the accumulated request**, and an announced
  `Content-Length` over it is refused before the body is read. A per-read check
  bounds nothing: a sender trickling bytes never trips one.
- **`request_timeout_sec` (10s) bounds the whole request** and
  **`max_connections` (64) bounds the poll list.** Idle sockets are dropped and
  the 65th caller gets a 503. Every held connection is polled every frame.

The issuer also serves `POST /session` (a server's roster, bearer = its key from
`session_keys_file`) and `POST /session/release` (bearer = the player's access
token). See "One seat per account".

`examples/issuer.tscn` is a daemon, not a self-test — it never exits, so it is the
one component the smoke tests do not cover. Drive it with a socket that writes
headers and body separately when changing this; a single `curl` will pass either
way.

Leave `listen_port` at 0 and call `issue_for_token()` directly to embed the issuer
in an existing service instead.

## File map

```
addons/dot_auth/
  dot_auth_config.gd            Strategies + endpoints. validate() enforces the invariants.
  dot_auth_identity.gd          Who a player is. uid is namespaced "provider:id".
  util/
    dot_jwt.gd                  Compact JWS. Algorithm pinned by the verifier.
    dot_pkce.gd                 S256 verifier/challenge. Hashes the ASCII of the verifier.
  client/
    dot_auth_client.gd          Device flow, rotating refresh, ticket requests,
                                and post_app / get_app for anything a PLAYER
                                reports about themselves.
    dot_auth_token_store.gd     Encrypted credential persistence. Read the caveat.
  local/
    dot_local_profiles.gd         Server-issued accounts that never leave this server.
    dot_local_profile_provider.gd Signs them in. A provider, so it composes with any strategy.
    dot_local_profile_client.gd   The client's secrets, keyed by server.
  server/
    dot_auth_ticket.gd          Ticket format. Read the class doc.
    dot_auth_issuer.gd          Publisher-run minting service, and the session table.
    dot_auth_session_reporter.gd  A server telling the issuer who is on it.
    dot_auth_server.gd          The four strategies. Registers as "dot_auth_server".
  backbone/
    dot_backbone_client.gd      Server self-reporting via the integration API.
                                post_integration / get_integration are the generic
                                seams other addons reach the backbone through.
  bridge/
    dot_auth_admin_source.gd    Site groups -> server permission flags. Duck-typed.
```

## Coupling

dot-auth and dot-server do not import each other; either works alone.

- `DotAuthServer` registers itself in `DotRegistry` as `dot_auth_server`.
- `DotAuthAdminSource` satisfies dot-server's admin-source contract
  (`lookup(identity) -> DotResult{flags, immunity, source}` plus
  `source_name()`) by duck typing.

Keep it that way. A hard dependency in either direction makes both harder to adopt.

## Things deliberately not here

- **OAuth authorization-code flow.** The device flow covers desktop, mobile,
  console and browser with one implementation and never asks a player to type
  credentials into a game client. A browser build could use a redirect flow for a
  smoother experience.
- **Platform SSO.** The backbone has a platform provider already; linking it would
  mean a platform id in `identity.claims` and a `DotCloudSourceHttp`-style provider
  abstraction here.
- **Ed25519.** Godot's `Crypto` has no EdDSA. The backbone's own API JWTs use it,
  which is one more reason the issuer indirection exists.
- **Token binding to a connection.** A ticket proves identity at join time. Binding
  it to the transport session would need transport cooperation.
