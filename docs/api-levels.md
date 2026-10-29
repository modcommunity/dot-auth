# API levels

What each level of `DotAuthApi` added. The bump rule is on `DotAddonApi`.

1. Everything before the file existed (an absent file reads as 1).
2. `DotAuthSessionReporter.report_offline_now()`, `follow_server()` and `offline_timeout_sec`; `DotAuthServer.session_reporter` and `create_session_reporter` (the auth server builds the reporter itself when `session_report_url` is set).
3. `DotAuthClient.SERVICE` (the client registers itself as `dot_auth_client`, the name `DotClientLink` looks up to attach a sign-in) and `DotAuthClient.account_key()`.
4. `DotAuthClient.redeem_handoff(code)`, the launcher's sign-in code on any platform.
5. `DotAuthClient.request_join_token(audience)` and `is_first_party(audience)`; `DotAuthConfig.first_party_audiences`, `join_audience` and `is_audience()`; `DotAuthServer.join_audience()`. INTROSPECT now carries a join token, never an access token.
6. `DotAuthConfig.apply_cfg_file` and `load_cfg` read `cfg/addons/dot_auth/auth.yml` and the operator's `cfg/server/addons/dot_auth/`, with the flat `cfg/auth.yml` as a shim until the end of 2026. Needs dot-core API level 16 (`DotAddonConfig.apply_file`). Secrets stay file-only.
7. Connect tickets by dialled address: `DotAuthClient.request_ticket_for_address()`; `DotAuthServer.adopt_ticket_trust()`, `ticket_trust_ready()` and `ticket_key_wanted` (key rotation by kid); `DotAuthConfig.adopt_ticket_trust`, `ticket_public_keys`, `ticket_issuer_url`.
8. Tickets bound to a connection: `authenticate(credential, rate_key, connection_nonce)`, `request_ticket_for_address(address, issuer_url, nonce)`, `DotAuthTicket.issue(..., nonce)`, `DotAuthConfig.require_ticket_binding` and `ticket_replay_max`; `revoke_ticket_keys()`. A ticket with no jti is refused; the site's revoked kids and refreshSec are honoured.
