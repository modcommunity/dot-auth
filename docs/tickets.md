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

`DotAuthConfig.validate()` refuses `TICKET` without a `server_id`, and refuses `ticket_replay_memory_sec <= ticket_ttl_sec`: otherwise a ticket outlives the record of having been spent and is replayable in the gap.

### The endpoint that does not exist

`DotAuthIssuer` is a standalone service using only existing backbone endpoints (`/api/app/v1/me`), so nothing needs adding to website-city to deploy it. If it is later folded into the backbone, the natural shape is `POST /api/app/v1/auth/ticket` taking `{serverId}` with a bearer access token and returning `{ticket, expiresIn}`, the same contract `DotAuthIssuer` serves. That would remove a hop and let the backbone rate-limit centrally. Not required.

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

**The game side is not wired yet.** Nothing in dot-server, dot-game or any game creates a `DotAuthSessionReporter` today (game-hungario and dot-server-deploy create a `DotBackboneClient`, which is a different report). A host gives the reporter its roster as uids through `roster_provider` and calls `report_offline()` before it stops. Not yet converted; reason unknown. Until it is, `single_session` relies on the release call and the lease.

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
