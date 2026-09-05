class_name DotAuthWebHandoff
extends RefCounted

## The browser player's identity handoff: "the person who pressed Play is this
## member".
##
## [b]The problem this solves.[/b] A game embedded in a website meets a player
## who is already signed into that website, and has no way to know it. The device
## flow is the wrong answer there — asking somebody to read a code off the canvas
## and type it into the site they are already signed into is a worse experience
## than no accounts at all, and it is the one place the flow's usual justification
## (the password is only typed on the website) buys nothing, because they are
## already on the website.
##
## [b]What the site hands over.[/b] Not a token. A single-use CODE, valid for
## about a minute, bound to one member and one game, which is exchanged for a
## credential pair scoped to that game. The distinction matters because the code
## travels through a document the site does not control: the worst a scraped code
## does is what the page it was scraped from was about to do anyway.
##
## [b]How it arrives.[/b] The site's loader posts it to the frame
## ([code]{type: "tmc.auth", auth: {…}}[/code]); the embedding page parks it on
## [code]window.__TMC_AUTH__[/code]. Deliberately NOT the query string: a
## credential in a URL reaches history, the referrer of every request the game
## makes, and any log that records frame sources.
##
## [b]NOTHING HERE MAY USE [method DotWeb.eval].[/b] The page that hosts a game
## should send `script-src 'self' 'wasm-unsafe-eval'` — enough to compile
## WebAssembly, not enough to evaluate a string — and under that policy Godot's
## `JavaScriptBridge.eval` throws an `EvalError` the engine swallows, so every
## read comes back null and the game silently signs nobody in. This module reads
## the global as an OBJECT ([method DotWeb.get_global]), which is not an eval and
## needs no CSP grant. That constraint is why the page publishes a
## [code]pending[/code] marker instead of the game asking the page a question.
##
## Off-web every function here answers "nothing to do", so callers need no
## platform guard — see [DotAuthClient.try_web_handoff], which is what a game
## actually calls.

const CHANNEL := "auth"

## The global the embedding page parks the block on.
const GLOBAL := "__TMC_AUTH__"


## Whether this build could have a handoff at all.
##
## False on every native build. A desktop client signs in with the device flow
## and stores its own credentials; there is no page to be handed anything by.
static func supported() -> bool:
	return DotWeb.available()


## The `auth` block the site published, or an empty Dictionary.
##
## Empty is the ordinary answer three ways over: a native build, a page that sent
## nothing, and a site whose game is not configured to use TMC for identity. None
## of them is an error and none of them should be logged as one.
##
## Read field by field rather than walked generically: the block's shape is a
## published contract, a JavaScript object reached through the bridge is not a
## Dictionary, and a generic walker over somebody else's object is a recursion
## depth nobody has bounded.
static func read() -> Dictionary:
	if not supported():
		return {}

	var obj: Variant = DotWeb.get_global(GLOBAL)

	if obj == null:
		return {}

	# Properties are read with `.name`, never `.get("name")`. A JavaScriptObject
	# routes a method call straight through to the JS object, so `.get("mode")`
	# tries to invoke a `get` method the page never defined and fails with
	# "obj[method] is not a function" — an error that reads like the bridge is
	# broken when it is only being asked the wrong way.
	#
	# The names are all fixed by the contract, so nothing here needs a dynamic
	# lookup.

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


## Whether the page is still waiting to be handed a block.
##
## The one thing that distinguishes "it has not arrived yet" from "there is
## nobody to send one" — both read as an absent block, and only the first is
## worth waiting for. A top-level tab that waited would spend that time on every
## launch outside the player, which is most of them.
static func pending(auth: Dictionary) -> bool:
	return bool(auth.get("pending", false))


## Whether the site said the person at the keyboard is signed in.
##
## Distinct from "there is a code": a signed-in member of a game that mints no
## identities also arrives with no code, and a game that could not tell those
## apart would offer a sign-in prompt to somebody already signed in.
static func signed_in(auth: Dictionary) -> bool:
	return bool(auth.get("signedIn", false))


## Whether the game may seat somebody with no identity at all.
##
## Advisory and the SERVER enforces it — only a server can refuse a player — but
## a client that reads it can skip a sign-in prompt nobody has to satisfy.
static func guests_allowed(auth: Dictionary) -> bool:
	# Absent means yes: a page that published no policy is a page that is not
	# asking us to turn anybody away.
	return bool(auth.get("guest", true))


## The single-use code block, or an empty Dictionary.
static func handoff(auth: Dictionary) -> Dictionary:
	var raw: Variant = auth.get("handoff")

	return raw as Dictionary if raw is Dictionary else {}


## Forget the code once it has been spent.
##
## A handoff is single-use, so the copy sitting on the page is worthless the
## moment it is redeemed — and a second sign-in attempt that finds it would spend
## a round trip to be told so. Clearing it is also the difference between a
## credential that lives as long as the tab and one that lives as long as it is
## needed.
##
## Clears the FIELDS rather than the global, because replacing `window.X` needs
## either an eval or a handle on `window` itself, and the first is refused by the
## policy this file exists to live under.
static func consume() -> void:
	if not supported():
		return

	var obj: Variant = DotWeb.get_global(GLOBAL)

	if obj == null:
		return

	obj.handoff = null
