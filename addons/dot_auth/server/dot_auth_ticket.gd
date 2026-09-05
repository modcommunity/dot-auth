class_name DotAuthTicket
extends RefCounted

## A short-lived, single-server credential proving who a connecting player is.
##
## [b]The problem it solves.[/b] A player has an account on the backbone. A
## community-run game server needs to know who they are. The obvious answer —
## send the server your account token and let it ask the backbone — hands every
## server operator a live credential for your whole site account. That is
## unacceptable for a game with third-party servers, and it is why platforms have auth
## session tickets rather than sharing session cookies.
##
## So: the client asks a [DotAuthIssuer] the publisher runs (first-party, already
## trusted with the token) for a ticket naming one server. The server verifies it
## offline against the issuer's public key. The server learns an identity and
## nothing it can reuse.
##
## Four properties make it work, and dropping any one of them breaks it:
##
## - [b]Audience-scoped.[/b] [code]aud[/code] is the server id. A ticket captured
##   on server A is refused by server B, so a malicious operator cannot replay
##   their players' tickets elsewhere.
## - [b]Short-lived.[/b] Minutes. It only has to survive "asked for it" to
##   "connected".
## - [b]Single-use.[/b] [code]jti[/code] is remembered until expiry, so capturing
##   one in flight does not let it be used twice.
## - [b]Asymmetrically signed.[/b] RS256, so a verifying server cannot mint. With
##   HS256 every server holding the verification key could forge a ticket for any
##   player.
##
## Encoded as a compact JWS — see [DotJwt].

const CHANNEL := "auth.ticket"


## Mints a ticket. Issuer side only; needs the private key.
static func issue(
	identity: DotAuthIdentity,
	server_id: String,
	private_key_pem: String,
	issuer_name: String,
	ttl_sec: int,
	key_id: String = "default"
) -> DotResult:
	if server_id.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID,
			"A ticket must name a server.",
			"an unscoped ticket is valid everywhere, which defeats the purpose"
		)

	if not identity.is_valid():
		return DotResult.fail(
			DotError.CODE_INVALID, "Cannot issue a ticket for an invalid identity."
		)

	var claims := DotJwt.base_claims(
		issuer_name, identity.uid, server_id, ttl_sec
	)

	# The identity travels inside the ticket so the server needs no lookup. It is
	# a snapshot: a name changed after issue is stale until the next ticket, which
	# is the correct trade for not making every join a backbone round trip.
	claims["name"] = identity.display_name
	claims["username"] = identity.username
	claims["provider"] = identity.provider
	claims["role"] = identity.role

	if identity.avatar_url != "":
		claims["avatar"] = identity.avatar_url
	if not identity.claims.is_empty():
		claims["claims"] = identity.claims

	return DotJwt.encode_rs256(claims, private_key_pem, key_id)


## Verifies a ticket and returns the [DotAuthIdentity] inside it.
##
## [param expected_server_id] must match the ticket's audience. Passing
## [code]""[/code] disables the check and is [b]never[/b] correct in production —
## it turns every ticket into a universal one.
static func verify(
	ticket: String,
	public_key_pem: String,
	expected_server_id: String,
	leeway_sec: int = 60
) -> DotResult:
	var verified := DotJwt.verify_rs256(ticket, public_key_pem, leeway_sec)
	if not verified.ok:
		return verified

	var claims: Dictionary = verified.value

	var audience := str(claims.get("aud", ""))
	if expected_server_id != "":
		if audience != expected_server_id:
			return DotResult.fail(
				DotError.CODE_FORBIDDEN,
				"This ticket was issued for a different server.",
				"ticket names '%s', this server is '%s'"
					% [audience, expected_server_id]
			)
	else:
		DotLog.warn(
			CHANNEL,
			"verifying a ticket without checking its audience — any ticket for "
			+ "any server will be accepted"
		)

	var subject := str(claims.get("sub", ""))
	if subject == "":
		return DotResult.fail(
			DotError.CODE_INVALID, "The ticket names no user."
		)

	var identity := DotAuthIdentity.new()
	identity.uid = subject
	identity.provider = str(claims.get("provider", "backbone"))
	# uid is namespaced "provider:id"; recovering the bare id keeps the two
	# consistent for anything matching on provider_id.
	identity.provider_id = subject.split(":", true, 1)[-1]
	identity.display_name = str(claims.get("name", ""))
	identity.username = str(claims.get("username", ""))
	identity.avatar_url = str(claims.get("avatar", ""))
	identity.role = str(claims.get("role", ""))
	identity.authenticated_at = int(claims.get("iat", 0))
	identity.expires_at = int(claims.get("exp", 0))

	if claims.get("claims") is Dictionary:
		identity.claims = claims["claims"]

	if identity.display_name == "":
		identity.display_name = identity.username if identity.username != "" else "Player"

	return DotResult.success({
		"identity": identity,
		"jti": str(claims.get("jti", "")),
		"exp": int(claims.get("exp", 0)),
	})


## Reads a ticket's audience without verifying it.
##
## For routing a ticket to the right server in a multi-instance process. Never for
## an authorisation decision.
static func peek_audience(ticket: String) -> String:
	var peeked := DotJwt.peek(ticket)
	if not peeked.ok:
		return ""
	var d: Dictionary = peeked.value
	return str((d["payload"] as Dictionary).get("aud", ""))
