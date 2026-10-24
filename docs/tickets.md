# Tickets, the issuer, and one seat per account

## The central design problem, and the answer

A player has an account on the backbone. A **community-run** game server needs to know who they are. The obvious implementation (the client sends its backbone access token, the server calls `/api/app/v1/me`) hands every server operator a live credential for the player's entire site account.

That is unacceptable for a game with third-party servers, and it is exactly why platforms issue auth session tickets rather than sharing session cookies. So dot-auth has three participants:

```
  client ──(device-code + PKCE)──> backbone            "who am I"
  client ──(access token)────────> DotAuthIssuer       first-party, publisher-run
  client <──(signed ticket)─────── DotAuthIssuer       scoped to ONE server, minutes
  client ──(ticket)──────────────> game server         verified OFFLINE, no round trip
```

`DotAuthIssuer` is the piece the publisher runs. It is the **only** component that needs the private key or backbone credentials. Server operators get a public key and nothing else. A client sends only the credential the server's strategy asks for; one that volunteered its access token to a ticket server would defeat the point.

Four properties make a ticket safe. Dropping any one breaks it:

| Property | Where | Why |
| --- | --- | --- |
| Audience-scoped (`aud` = server id) | `DotAuthTicket.verify` | A ticket captured on server A is refused by B, so a malicious operator cannot replay their players' tickets elsewhere. |
| Short-lived (minutes) | `ticket_ttl_sec` | It only has to survive "asked for it" → "connected". |
| Single-use (`jti` remembered) | `DotAuthServer._spent_tickets` | A ticket captured in flight cannot be used twice inside its window. |
| Asymmetrically signed (RS256) | `DotJwt` | With HS256 every verifying server could *forge* a ticket for any player. |

`DotAuthConfig.validate()` refuses `TICKET` without a `server_id` (unless `adopt_ticket_trust`, below), and refuses `ticket_replay_memory_sec <= ticket_ttl_sec`: otherwise a ticket outlives the record of having been spent and is replayable in the gap.

### The backbone's own issuer, by dialled address

website-city now issues tickets itself: `POST /api/app/v1/auth/ticket` with a bearer access token and `{address}`, the `host:port` the client **dialled**, answers `{ticket, expiresIn, serverId}`; `GET /api/app/v1/auth/ticket-keys` publishes the public keys by `kid`. The client calls `DotAuthClient.request_ticket_for_address()` (dot-server's client link does, with the address passed to `connect_to_server`). It never asks by the `server_id` a server announced: a hostile server announcing a victim's id would be handed a ticket valid on the victim. `DotAuthIssuer` and `request_ticket(issuer, server_id)` remain for a publisher running its own; `ticket_issuer_url` names that issuer, empty means the backbone's.

A server needs neither an id nor a key file. With `adopt_ticket_trust` it starts in `TICKET` and refuses signed-in joins (`CODE_STATE`) until it has both: the id from `integration/v1/me` once a `backbone` client is handed over, the keys from its own `backbone_url`'s `ticket-keys` over verified HTTPS (plain HTTP only to loopback), kept in `ticket_trust_cache`. An explicit `server_id` or `ticket_public_key` wins. A ticket naming an unknown `kid` is refused and emits `ticket_key_wanted`, which refetches at most once a minute; the ring is also refetched every `refreshSec` the site names (900 s, clamped to 5 min to 6 h). A kid the site lists under `revoked` is dropped, refused, never adopted again, and remembered in the trust cache across restarts. A ticket is never verified without an audience, because `DotAuthTicket.verify` accepts any audience when given none. The threat model is website-city's `docs/api/connect-tickets.md`.

**Binding to the connection.** dot-server puts a random `ticket_nonce` in each connection's challenge; the client passes it to `request_ticket_for_address(address, issuer_url, nonce)`, the issuer signs it in as the `nonce` claim, and the host passes its own copy to `authenticate(credential, rate_key, connection_nonce)`. A ticket whose nonce differs is refused, so a ticket copied off plain UDP or `ws://` is useless on any other connection; the check runs before the ticket is spent, so a thief's attempt does not burn the player's ticket. The nonce never comes from the credential (`authenticate` strips `_connection_nonce`). Unbound tickets are accepted unless `require_ticket_binding` is set. A ticket with no `jti` is refused, and when `ticket_replay_max` spent ids are held new tickets are refused rather than old ids forgotten.

## One seat per account

`DotAuthConfig.single_session` makes the issuer refuse a ticket for one server while the player is on another. It is off by default.

**It lives on the issuer because the issuer is the only participant that sees every server.** A game server knows its own roster and nothing about anybody else's, and having servers compare notes would mean operators trusting each other, the thing the ticket design exists to avoid. So the issuer keeps a table of `uid -> server`, and `issue_for_identity()` consults it before minting.

A ticket says where a player is *going*; it does not say they arrived or when they left. Three things end a session:

| Ends it | How | Who |
| --- | --- | --- |
| **The server's roster** | `POST /session {serverId, users}` with the server's key. Absolute: absent means gone, an empty list means empty. `DotAuthSessionReporter` sends one on a timer and an empty one on the way down. | Authoritative. The only one that can hold a player for a whole match and free them the moment they leave. |
| **The player** | `POST /session/release` with their access token; `DotAuthClient.release_session()`. Ends only the session behind that token. | The polite fast path on disconnect. A player still on a server is put back by its next report. |
| **The lease** | `session_lease_sec` (300) without word from a server. | What a non-reporting server's players get: held for the lease after their ticket, then let go, playing or not. |

Rules that were each the answer to a bug:

- **A ticket for the server a player is already on is always granted**, so a crashed client can reconnect. And it must not demote a *confirmed* session to unconfirmed, or the next roster to omit them for a moment could not end it.
- **A roster does not end an unconfirmed session.** The player has not arrived yet, and acting on it would let a player collect tickets for two servers in the seconds between the first being minted and the first roster naming them. An unconfirmed session lapses on its own.
- **A roster moves a player the table had elsewhere.** The report is the truth about where they are.
- **`session_lease_sec >= ticket_ttl_sec`**, enforced by `validate()`. A shorter lease lets a player hold a live ticket for one server after the issuer has forgotten the session, and get a second for another.
- **Server keys are per server, in a file (`session_keys_file`), and at least 16 characters.** A report can only speak for the server whose key it carries. Unknown server and wrong key answer identically, in constant time. Without a key anyone could report any player as being anywhere, locking them out of everywhere else on the strength of a POST.
- **The refusal names the server.** "You are already connected to eu-west-1" is the player's own whereabouts and is what they need to act on. `DotAuthClient._issuer_refusal()` carries it through `DotHttp`'s generic "Not allowed." by keeping the issuer's `{error, code}` body as the error's detail.

### Who builds the reporter, and which stops it reports

**`DotAuthServer` builds the `DotAuthSessionReporter` itself** when `session_report_url` is set (off, and silent, without one; `create_session_reporter = false` for a host that builds its own). It finds the `dot_server` in `DotRegistry` (now, or when one registers) and calls `follow_server()`, which takes the roster from `sessions()`, every signed-on session rather than only those in play, because a player loading a map or reloading through a game change is still on this server and dropping them from a roster would end a confirmed seat mid-load. Guests are dropped by `normalise_roster`.

It lives on the auth server rather than in dot-game or dot-server because its lifetime is the server process's and its config is `DotAuthConfig`. dot-game's `DotGameModule` is per game: a game change unloads it with every player still connected, and arena, g2gfast, hungario and playground are not on it. Games never own authentication; the host's `dot_auth_server` is the same for every game it runs. dot-server never names dot-auth. The reasoning is also on `DotAuthServer.session_reporter`.

**The goodbye is synchronous.** `report_offline_now()` drives an `HTTPClient` on the calling thread for at most `offline_timeout_sec` (3 s), because both moments it is sent are the process ending: an `HTTPRequest` is freed with the tree before the issuer answers. `report_offline()` (asynchronous) remains for a host that keeps the process alive until it returns.

| A server that stops by | Reports? | Its players |
| --- | --- | --- |
| `DotServer.shutdown()` | yes, on the `SHUTTING_DOWN` state change, before the sessions are cleared | free at once |
| `SceneTree.quit()`: the console's `quit`, a scheduled restart, a host's exit | yes, from the reporter's `_exit_tree` (children leave first, so before DotServer's own shutdown). Checked against a separate fake issuer process | free at once |
| SIGINT (Ctrl+C, the panel egg's stop), SIGTERM (`kill`, `docker stop`) | **no**: headless Godot 4.7.2 runs no notification on either (measured again 2026-10-11) | held for `session_lease_sec` |
| SIGKILL, a crash, a lost network | no | held for `session_lease_sec` |
| An issuer that does not answer | tried, gives up after `offline_timeout_sec` with a warning | held for `session_lease_sec` |

So a deployment that wants seats freed on stop has to stop with `quit` on the console, not with a signal. The leaving-the-tree path cannot tell a quit from a host removing the auth server on purpose; either way nothing reports this server any more, and the issuer hears so.

`examples/session_reporter_selftest.tscn` proves the first two rows against real `DotServer`s and a fake issuer socket on a thread (a blocking send cannot be answered by an issuer polled on the same main thread), and keeps the control: with the reporter switched off the same stop leaves the seat held.

## Running the issuer

```bash
godot --headless --path . res://examples/issuer.tscn -- \
    --auth-backbone-url https://moddingcommunity.com
```

with `private_key_file` pointing at the key. Leave `listen_port` at 0 and call `issue_for_token()` directly to embed the issuer in an existing service instead. It also serves `POST /session` (bearer = the server's key) and `POST /session/release` (bearer = the player's access token).

The built-in listener speaks enough HTTP/1.1 for one JSON POST and has no TLS, keep-alive or chunked encoding: **put it behind a reverse proxy**, which is where TLS, real request limits and access logs belong. It binds `127.0.0.1` by default and warns if you bind wider. What it does implement, because a request does not arrive in one read:

- **The request is buffered across polls** and dispatched only once the headers and a full `Content-Length` body are present. Parsing whatever one poll saw treats a TCP segment boundary as the end of the request (a body in a second segment was answered `400 Expected a JSON body`), which localhost testing never shows because a small request is coalesced into one segment.
- **`Expect: 100-continue` gets its interim response.** curl sends it for any body over about 1 KB and waits before writing.
- **`max_request_bytes` bounds the accumulated request**, and an announced `Content-Length` over it is refused before the body is read. A per-read check bounds nothing: a sender trickling bytes never trips one.
- **`request_timeout_sec` (10 s) bounds the whole request** and **`max_connections` (64) bounds the poll list.** Idle sockets are dropped and the 65th caller gets a 503.

`examples/issuer.tscn` is a daemon, not a self-test: it never exits, so the smoke tests do not cover it. Drive it with a socket that writes headers and body separately when changing the listener; a single `curl` passes either way.
