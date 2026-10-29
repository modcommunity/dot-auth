class_name DotAuthWebHandoff
extends RefCounted

## The browser player's identity handoff: the site hands the game a single-use code, never a token.
##
## NOTHING HERE MAY USE [method DotWeb.eval]: under a `script-src 'self' 'wasm-unsafe-eval'` policy it fails silently and signs nobody in. Off-web every function answers "nothing to do"; games call [DotAuthClient.try_web_handoff]. Why: docs/rationale.md.

# No log channel: static reads of one page global. Whether a missing or pending block
# matters is the auth client's decision, and it is the one that logs how a player
# signed in. Nothing here can fail against anything but a page that did not publish.

## The global the embedding page parks the block on; never the query string, where a credential reaches history, referrers and logs.
const GLOBAL := "__TMC_AUTH__"


## Whether this build could have a handoff at all; false on every native build.
static func supported() -> bool:
	return DotWeb.available()


## The `auth` block the site published, or an empty Dictionary (native build, nothing sent, or a game not using TMC identity; none is an error).
##
## Read field by field: the shape is a published contract and a generic walker over a JavaScript object has no bounded depth.
static func read() -> Dictionary:
	if not supported():
		return {}

	var obj: Variant = DotWeb.get_global(GLOBAL)

	if obj == null:
		return {}

	# Read properties with `.name`, never `.get("name")`: a JavaScriptObject forwards the call to the page, which has no `get` method.

	# The page sets this while it is still waiting for the site to post. Reported
	# as a block with nothing in it but the marker, so a caller can tell "not yet"
	# from "never" without a second global to read.
	if bool(obj.pending):
		return {"pending": true}

	var mode: Variant = obj.mode

	# No mode means this is not a block we understand — an empty object the page
	# published because there was nobody to ask, most likely.
	if mode == null:
		return {}

	var guest: Variant = obj.guest
	var issuer: Variant = obj.issuerUrl

	var out := {
		"mode": str(mode),
		"guest": bool(guest) if guest != null else true,
		"signedIn": bool(obj.signedIn),
		"issuerUrl": str(issuer) if issuer != null else "",
	}

	var h: Variant = obj.handoff

	if h != null:
		var raw_code: Variant = h.code
		var raw_url: Variant = h.redeemUrl
		var raw_exp: Variant = h.expiresIn

		var code := str(raw_code) if raw_code != null else ""
		var url := str(raw_url) if raw_url != null else ""

		if code != "" and url != "":
			out["handoff"] = {
				"code": code,
				"redeemUrl": url,
				"expiresIn": int(raw_exp) if raw_exp != null else 60,
			}

	return out


## Whether the page is still waiting to be handed a block, the only way to tell "not arrived yet" from "nobody will send one".
static func pending(auth: Dictionary) -> bool:
	return bool(auth.get("pending", false))


## Whether the site said the person at the keyboard is signed in; distinct from having a code, since a game minting no identities also gets no code.
static func signed_in(auth: Dictionary) -> bool:
	return bool(auth.get("signedIn", false))


## Whether the game may seat somebody with no identity; advisory, the SERVER enforces it.
static func guests_allowed(auth: Dictionary) -> bool:
	# Absent means yes: a page that published no policy is a page that is not
	# asking us to turn anybody away.
	return bool(auth.get("guest", true))


## The single-use code block, or an empty Dictionary.
static func handoff(auth: Dictionary) -> Dictionary:
	var raw: Variant = auth.get("handoff")

	return raw as Dictionary if raw is Dictionary else {}


## Forgets the code once spent, so the credential lives only as long as it is needed.
##
## Clears the FIELDS, not the global: replacing `window.X` needs an eval, which the CSP refuses.
static func consume() -> void:
	if not supported():
		return

	var obj: Variant = DotWeb.get_global(GLOBAL)

	if obj == null:
		return

	obj.handoff = null
