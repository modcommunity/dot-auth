# The backbone: contracts and the URL

The family's view of website-city is in [game-dev/docs/backbone.md](../../../docs/backbone.md); this is dot-auth's half.

## Contracts this code depends on

Verified against website-city's source. If these drift, dot-auth breaks here:

| Endpoint | Contract source | Used by |
| --- | --- | --- |
| `POST /api/app/v1/auth/device` | `~/types/app-api/contract.ts` `DeviceStartRequest` | `DotAuthClient.start_device_login` |
| `POST /api/app/v1/auth/token` | `DeviceTokenRequest`, `TokenResponse` | `DotAuthClient._poll_for_token` |
| `POST /api/app/v1/auth/refresh` | `RefreshRequest` | `DotAuthClient.refresh` |
| `POST /api/app/v1/auth/revoke` | none | `DotAuthClient.sign_out` |
| `GET /api/app/v1/me` | `SessionUserSchema` | issuer + `INTROSPECT` |
| `POST /api/content/server/integration/stats` | `~/types/integration/server.ts` `IngestServerStatsInput` | `DotBackboneClient.report_stats` |
| `POST /api/content/server/integration/users` | `IngestServerUsersInput` | `DotBackboneClient.report_users` |
| `GET /api/integration/v1/user/lookup` | `IngestUserLookupInput` | `DotBackboneClient.lookup_user` |

`DotAuthClient.post_app` / `get_app` are the seam for anything a PLAYER reports about themselves; `DotBackboneClient.post_integration` / `get_integration` are the seam other addons reach the backbone through as a server.

Details that are easy to get wrong and are already handled:

- **Poll outcomes are 202 with an error envelope**, not HTTP failures. `authorization_pending`, `slow_down`, `access_denied`, `expired_token` are read from the JSON `code`, which `DotHttp` preserves as the error's detail; `_envelope_code()` recovers it without a second request.
- **`slow_down` must be honoured** over the configured interval. Polling faster than told burns the grant.
- **`token_reuse` on refresh is not a generic error.** The backbone has signed every device out. `DotAuthClient` clears the store and emits `session_revoked` so the UI can show a security notice.
- **`ClientInfoSchema.platform` has no `web` member.** A browser build reports `unknown` via `DotPlatform.backbone_platform()` rather than failing validation.
- **Integration requests need `ts` (Unix *seconds*) and `nonce`.** Milliseconds are refused by the backbone's skew window. `DotBackboneClient._stamp()` is the only place this is done.
- **Roster reports are absolute, not incremental.** An empty list closes every session, so a server that does not know its roster must not call the endpoint. When the list is truncated at 512, `setCount` is forced off, or it would report a count lower than the truth every tick.
- **`SERVER_STATS` and `SERVER_USERS` are separate scopes** on purpose: a player list is personal data about third parties. `report_roster` is off by default.

## The backbone URL is a security property

`DotAuthConfig.backbone_url` defaults to `https://moddingcommunity.com`. A default endpoint decides where a device-code grant (the opening request of an authentication flow) is sent, so a wrong default that does not resolve fails loudly, and the same wrong default the day somebody registers the name fails *quietly*. Check any default URL against what website-city actually serves. See [history](history.md).

**Overriding it.** It is an ordinary `DotConfig` field: `DOT_AUTH_BACKBONE_URL`, `--auth-backbone-url` and a JSON file, layered by `DotAuthClient.start()`. A browser build has neither an environment nor an argv, so a web client is told through a JSON file shipped in its export; `dot-server-deploy/client/auth.json` is the worked example. It is deliberately **not** read from the page's query string: this URL decides where a single-use sign-in code is redeemed, and a link that could aim it at another host would be a credential-forwarding link.
