class_name DotPkce
extends RefCounted

## PKCE verifier/challenge pairs for the backbone's device flow; S256 only, never [code]plain[/code].

## The backbone's `DeviceStartRequest` requires 43–128 characters.
## 32 random bytes base64url-encode to exactly 43.
const VERIFIER_BYTES := 32


## Generates a verifier and its S256 challenge as [code]{verifier, challenge, method}[/code]; keep the verifier in memory only.
static func generate() -> Dictionary:
	var verifier := DotHash.random_token(VERIFIER_BYTES)
	return {
		"verifier": verifier,
		"challenge": challenge_for(verifier),
		"method": "S256",
	}


## The S256 challenge: base64url(SHA-256) over the ASCII of the verifier string, not the bytes it decodes to.
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
