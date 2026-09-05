class_name DotPkce
extends RefCounted

## PKCE verifier/challenge pairs, as the backbone's device flow requires.
##
## [b]What PKCE buys in a device flow.[/b] The device code travels to the
## backbone twice: once when the login starts, once on every poll. Without PKCE,
## anything that observed the first exchange — a proxy, a log, a shared machine —
## could poll with the same device code and claim the token when the user
## approves. With it, redemption also requires the verifier, which never leaves
## the client.
##
## S256 only. The spec also allows [code]plain[/code], where the challenge *is*
## the verifier, which provides no protection at all; the backbone's schema
## expects a 43–128 character challenge and we never offer the weaker option.

## The backbone's `DeviceStartRequest` requires 43–128 characters.
## 32 random bytes base64url-encode to exactly 43.
const VERIFIER_BYTES := 32


## Generates a verifier and its S256 challenge.
##
## Returns [code]{verifier, challenge, method}[/code]. Keep the verifier in
## memory only — it is a secret with a ten-minute life and writing it anywhere
## is strictly worse than regenerating it.
static func generate() -> Dictionary:
	var verifier := DotHash.random_token(VERIFIER_BYTES)
	return {
		"verifier": verifier,
		"challenge": challenge_for(verifier),
		"method": "S256",
	}


## The S256 challenge for a verifier: base64url(SHA-256(ASCII(verifier))).
##
## Hashed over the [b]ASCII of the verifier string[/b], not over the bytes it
## decodes to. Getting that wrong produces a challenge the server computes
## differently, and the failure appears at redemption as a generic invalid-grant
## with nothing to point at.
static func challenge_for(verifier: String) -> String:
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update(verifier.to_ascii_buffer())
	return DotHash.base64url_encode(ctx.finish())


## Checks a verifier against a challenge. For an issuer implementing the flow.
static func verify(verifier: String, challenge: String) -> bool:
	return DotHash.constant_time_equal(
		challenge_for(verifier).to_utf8_buffer(),
		challenge.to_utf8_buffer()
	)
