class_name DotJwt
extends RefCounted

## Compact JWS encoding, signing and verification.
##
## Used for [DotAuthTicket] — the short-lived, server-scoped credential a client
## presents to a game server. A standard format rather than a bespoke one because
## the properties that make it safe are the ones people get wrong when inventing:
## the signature covers the exact encoded header and payload, the algorithm is
## pinned by the verifier rather than read from the token, and expiry is checked
## against a bounded clock skew.
##
## [b]Supported algorithms.[/b] [code]RS256[/code] (RSA-SHA256) and
## [code]HS256[/code] (HMAC-SHA256), because those are what Godot's [Crypto] and
## [HMACContext] can do. No EdDSA — the engine has none.
##
## [b]RS256 vs HS256.[/b] HS256 is symmetric: whoever can verify can also forge.
## That is fine when issuer and verifier are the same process, and disqualifying
## when a ticket issued centrally is verified by hundreds of community game
## servers — any one of them could then mint tickets for any player. Use RS256 for
## anything crossing a trust boundary; [DotAuthConfig] warns when you do not.

const CHANNEL := "auth.jwt"

const ALG_RS256 := "RS256"
const ALG_HS256 := "HS256"

## Seconds of clock skew tolerated on [code]exp[/code] and [code]nbf[/code].
##
## Machine clocks disagree, and a ticket refused because a server is 20 seconds
## fast is a player who cannot connect for no visible reason. Matches the
## backbone's own `INTEGRATION_CLOCK_SKEW_SEC` thinking.
const DEFAULT_LEEWAY_SEC := 60


# --- Encoding --------------------------------------------------------------

## Signs a payload with an RSA private key.
static func encode_rs256(
	payload: Dictionary,
	private_key_pem: String,
	key_id: String = ""
) -> DotResult:
	var header := {"alg": ALG_RS256, "typ": "JWT"}
	if key_id != "":
		header["kid"] = key_id

	var signing_input := _signing_input(header, payload)

	var key := CryptoKey.new()
	var err := key.load_from_string(private_key_pem, false)
	if err != OK:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"Could not read the signing key.",
			error_string(err)
		)

	var crypto := Crypto.new()
	var sig := crypto.sign(
		HashingContext.HASH_SHA256, _sha256(signing_input), key
	)

	if sig.is_empty():
		return DotResult.fail(
			DotError.CODE_INTERNAL,
			"Signing failed.",
			"the key may be a public key, or too small"
		)

	return DotResult.success(
		"%s.%s" % [signing_input, DotHash.base64url_encode(sig)]
	)


## Signs a payload with a shared secret.
##
## Only safe when issuer and verifier are the same trust domain — see the class
## documentation.
static func encode_hs256(payload: Dictionary, secret: String) -> DotResult:
	if secret.length() < 32:
		# A short HMAC secret is brute-forceable offline from a single token, and
		# a token is by design something the attacker holds.
		return DotResult.fail(
			DotError.CODE_INVALID,
			"The HS256 secret must be at least 32 characters.",
			"got %d" % secret.length()
		)

	var header := {"alg": ALG_HS256, "typ": "JWT"}
	var signing_input := _signing_input(header, payload)

	var mac := DotHash.hmac_sha256(
		secret.to_utf8_buffer(), signing_input.to_utf8_buffer()
	)

	return DotResult.success(
		"%s.%s" % [signing_input, DotHash.base64url_encode(mac)]
	)


# --- Decoding --------------------------------------------------------------

## Reads a token's claims [b]without verifying anything[/b].
##
## For logging and for reading [code]kid[/code] before choosing a key. Never
## branch on the result for an authorisation decision — an unverified token is a
## string an attacker wrote.
static func peek(token: String) -> DotResult:
	var parts := token.split(".")
	if parts.size() != 3:
		return DotResult.fail(
			DotError.CODE_PARSE, "Malformed token.", "expected 3 segments"
		)

	var header: Variant = JSON.parse_string(
		DotHash.base64url_decode_text(parts[0])
	)
	var payload: Variant = JSON.parse_string(
		DotHash.base64url_decode_text(parts[1])
	)

	if not (header is Dictionary) or not (payload is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE, "Token segments are not JSON objects."
		)

	return DotResult.success({"header": header, "payload": payload})


## Verifies a token against an RSA public key and checks its time claims.
##
## [param expected_algorithm] is pinned by the caller and the token's own
## [code]alg[/code] must match it. [b]This is the check that matters most.[/b]
## Trusting the token's algorithm header is the classic JWT vulnerability: a
## verifier that reads [code]alg[/code] and dispatches on it can be handed
## [code]{"alg":"none"}[/code], or an HS256 token signed with the RSA public key
## as the HMAC secret — which is public.
static func verify_rs256(
	token: String,
	public_key_pem: String,
	leeway_sec: int = DEFAULT_LEEWAY_SEC
) -> DotResult:
	var parts := token.split(".")
	if parts.size() != 3:
		return DotResult.fail(
			DotError.CODE_PARSE, "Malformed token.", "expected 3 segments"
		)

	var peeked := peek(token)
	if not peeked.ok:
		return peeked

	var d: Dictionary = peeked.value
	var header: Dictionary = d["header"]

	if str(header.get("alg", "")) != ALG_RS256:
		return DotResult.fail(
			DotError.CODE_INTEGRITY,
			"Unexpected token algorithm.",
			"expected %s, got '%s'" % [ALG_RS256, header.get("alg", "")]
		)

	var key := CryptoKey.new()
	var err := key.load_from_string(public_key_pem, true)
	if err != OK:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"Could not read the verification key.",
			error_string(err)
		)

	var signing_input := "%s.%s" % [parts[0], parts[1]]
	var sig := DotHash.base64url_decode(parts[2])

	if sig.is_empty():
		return DotResult.fail(
			DotError.CODE_INTEGRITY, "The token signature is not valid base64url."
		)

	var crypto := Crypto.new()
	if not crypto.verify(
		HashingContext.HASH_SHA256, _sha256(signing_input), sig, key
	):
		return DotResult.fail(
			DotError.CODE_INTEGRITY, "The token signature is invalid."
		)

	return _check_times(d["payload"], leeway_sec)


## Verifies a token against a shared secret and checks its time claims.
static func verify_hs256(
	token: String,
	secret: String,
	leeway_sec: int = DEFAULT_LEEWAY_SEC
) -> DotResult:
	var parts := token.split(".")
	if parts.size() != 3:
		return DotResult.fail(
			DotError.CODE_PARSE, "Malformed token.", "expected 3 segments"
		)

	var peeked := peek(token)
	if not peeked.ok:
		return peeked

	var d: Dictionary = peeked.value
	var header: Dictionary = d["header"]

	if str(header.get("alg", "")) != ALG_HS256:
		return DotResult.fail(
			DotError.CODE_INTEGRITY,
			"Unexpected token algorithm.",
			"expected %s, got '%s'" % [ALG_HS256, header.get("alg", "")]
		)

	var signing_input := "%s.%s" % [parts[0], parts[1]]
	var expected := DotHash.hmac_sha256(
		secret.to_utf8_buffer(), signing_input.to_utf8_buffer()
	)
	var actual := DotHash.base64url_decode(parts[2])

	# Constant time: a byte-by-byte comparison that returns early leaks how much
	# of a forged MAC was right, which reduces forgery to 32 rounds of 256 tries.
	if not DotHash.constant_time_equal(expected, actual):
		return DotResult.fail(
			DotError.CODE_INTEGRITY, "The token signature is invalid."
		)

	return _check_times(d["payload"], leeway_sec)


## Checks [code]exp[/code] and [code]nbf[/code] against the wall clock.
static func _check_times(payload: Dictionary, leeway_sec: int) -> DotResult:
	var now := int(Time.get_unix_time_from_system())

	if payload.has("exp"):
		var exp := int(payload["exp"])
		if now > exp + leeway_sec:
			return DotResult.fail(
				DotError.CODE_AUTH,
				"This login has expired.",
				"expired %d seconds ago" % (now - exp)
			)

	if payload.has("nbf"):
		var nbf := int(payload["nbf"])
		if now + leeway_sec < nbf:
			return DotResult.fail(
				DotError.CODE_AUTH,
				"This token is not valid yet.",
				"valid in %d seconds" % (nbf - now)
			)

	return DotResult.success(payload)


static func _signing_input(header: Dictionary, payload: Dictionary) -> String:
	return "%s.%s" % [
		DotHash.base64url_encode_text(JSON.stringify(header)),
		DotHash.base64url_encode_text(JSON.stringify(payload)),
	]


static func _sha256(text: String) -> PackedByteArray:
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update(text.to_utf8_buffer())
	return ctx.finish()


## Standard claims for a new token.
static func base_claims(
	issuer: String,
	subject: String,
	audience: String,
	ttl_sec: int
) -> Dictionary:
	var now := int(Time.get_unix_time_from_system())
	return {
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": now,
		"nbf": now,
		"exp": now + ttl_sec,
		# A per-token id, so a verifier can refuse replays within the token's
		# lifetime. Without it a captured ticket is reusable until it expires.
		"jti": DotHash.random_token(16),
	}
