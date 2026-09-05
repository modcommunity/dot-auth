@tool
class_name DotAuthClient
extends Node

## Signs a player in against the website-city backbone and keeps them signed in.
##
## Implements the backbone's device-code grant (`/api/app/v1/auth/*`) exactly as
## `~/types/app-api/contract.ts` defines it: PKCE-protected start, polling with
## the server's own interval and `slow_down` backoff, and rotating refresh.
##
## [b]Why a device flow and not a password field.[/b] A game asking for account
## credentials trains players to type them into game clients, which is the thing
## every phishing attempt relies on. The device flow means the password is only
## ever entered on the website — and it is the only flow that works unchanged on a
## console, a TV, and a browser build that cannot open a popup.
##
## [codeblock]
## var auth := DotAuthClient.new()
## add_child(auth)
## auth.config = my_config
##
## auth.device_code_ready.connect(func(user_code, url, _expires):
##     code_label.text = user_code
##     OS.shell_open(url))
##
## var res := await auth.sign_in()
## if res.ok:
##     print("hello ", (res.value as DotAuthIdentity).display_name)
## [/codeblock]

const CHANNEL := "auth"

## Emitted once the backbone has issued a device code.
##
## [param verification_uri_complete] has the code pre-filled and is what to open;
## [param user_code] is for players who must type it on another device.
signal device_code_ready(
	user_code: String,
	verification_uri_complete: String,
	expires_in: int
)

## Emitted on each poll, so a UI can show that something is happening.
signal awaiting_approval(elapsed_sec: float)

signal signed_in(identity: DotAuthIdentity)
signal signed_out()

## The access token was rotated. Anything caching it should re-read.
signal token_refreshed()

## The backbone reported `token_reuse`: a retired refresh token came back, so it
## signed every device out. Show this as a security notice, not a generic error.
signal session_revoked(reason: String)

@export_group("Configuration")

@export var config: DotAuthConfig = null

@export var config_file: String = "user://dot_auth.json"

## Sign in automatically from stored credentials when the node enters the tree.
@export var auto_sign_in: bool = true

## Refresh the access token in the background before it expires.
@export var auto_refresh: bool = true

## Accept an identity handed over by an embedding website (browser builds).
##
## On by default: a game running inside the TMC player that ignored this would
## ask a signed-in member to sign in again, which is the failure the handoff
## exists to remove. Turn it off for a browser build that must not trust its
## embedder — a game distributed to sites you do not control, where "who is
## playing" should come from your own backend instead.
@export var web_handoff: bool = true

var store: DotAuthTokenStore = null

var _http: DotHttp = null
var _identity: DotAuthIdentity = null
var _refresh_timer: Timer = null
var _signing_in: bool = false
var _cancelled: bool = false
var _started: bool = false


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	var ok := start()
	if not ok.ok:
		DotLog.result(CHANNEL, "start", ok)
		return

	if auto_sign_in and store.has_credentials():
		var res := await restore_session()
		if not res.ok:
			DotLog.debug(
				CHANNEL,
				"could not restore the stored session",
				{"why": res.code()}
			)


## Prepares config, HTTP and the token store. Idempotent.
func start() -> DotResult:
	if _started:
		return DotResult.success(self)

	if config == null:
		config = DotAuthConfig.new()

	if config_file != "":
		var loaded := config.apply_json_file(config_file)
		if not loaded.ok:
			return loaded

	config.apply_env()
	config.apply_cli()

	_http = DotHttp.new()
	_http.name = "AuthHttp"
	_http.base_url = config.backbone_url
	_http.user_agent = "%s/%s (dot-auth)" % [
		config.client_name, config.client_version
	]
	_http.timeout_sec = 20.0
	# The device poll's own loop handles pending/slow_down, so HTTP-level retries
	# would stack two backoffs and make polling unpredictable.
	_http.max_retries = 1
	add_child(_http)

	store = DotAuthTokenStore.new(
		config.token_store_path, config.encrypt_token_store
	)
	store.load_tokens()
	_identity = store.identity()

	_refresh_timer = Timer.new()
	_refresh_timer.one_shot = true
	_refresh_timer.timeout.connect(_on_refresh_due)
	add_child(_refresh_timer)

	_started = true
	return DotResult.success(self)


# --- Sign in ---------------------------------------------------------------

## Signs the player in, reusing stored credentials when possible.
##
## Returns the [DotAuthIdentity]. Starts a device login only when there is nothing
## to restore, so a returning player never sees a code.
func sign_in() -> DotResult:
	if not _started:
		var s := start()
		if not s.ok:
			return s

	if _signing_in:
		return DotResult.fail(
			DotError.CODE_STATE, "A sign-in is already in progress."
		)

	# The page's handoff comes FIRST, ahead of anything stored.
	#
	# Not an optimisation — a correctness order. The site is authoritative about
	# who is at the keyboard right now, and a browser build's store is per
	# ORIGIN: two members using the same computer, or one member who signed out
	# of the site and back in as somebody else, would otherwise be seated as
	# whoever this frame's storage last held. A stored session is the right
	# fallback and the wrong first answer.
	if web_handoff and DotAuthWebHandoff.supported():
		var handed := await try_web_handoff()
		if handed.ok:
			return handed
		DotLog.debug(
			CHANNEL,
			"no usable handoff from the page",
			{"why": handed.code()}
		)

	if store.has_credentials():
		var restored := await restore_session()
		if restored.ok:
			return restored
		DotLog.info(
			CHANNEL,
			"stored credentials did not work; starting a new login",
			{"why": restored.code()}
		)

	return await start_device_login()


## Signs in from the code the embedding page handed us, without asking anybody
## anything.
##
## The browser player's whole point: a member who is already signed into the site
## is seated as themselves. See [DotAuthWebHandoff] for what the page publishes
## and why it is a code rather than a token.
##
## [b]Every "no" is an ordinary outcome, not a failure to report.[/b] A native
## build, a page that published nothing, a signed-out visitor, a game whose
## operator did not turn TMC identity on — all four return a failed [DotResult]
## that the caller is expected to fall through, which is why [method sign_in]
## logs it at debug and carries on to the device flow.
func try_web_handoff(wait_sec: float = 3.0) -> DotResult:
	if not DotAuthWebHandoff.supported():
		return DotResult.fail(
			DotError.CODE_UNSUPPORTED, "Not running in a browser."
		)

	if not _started:
		var s := start()
		if not s.ok:
			return s

	var auth := await _await_page_auth(wait_sec)
	var code_block := DotAuthWebHandoff.handoff(auth)

	if code_block.is_empty():
		return DotResult.fail(
			DotError.CODE_AUTH,
			"The page published no sign-in code."
			if DotAuthWebHandoff.signed_in(auth)
			else "Nobody is signed in on the page."
		)

	var redeem_url := str(code_block.get("redeemUrl", ""))

	# The page that handed us a code IS the backbone, so take its origin rather
	# than the configured one. Without this a game embedded on a staging or
	# self-hosted deployment redeems fine — the redeem URL is absolute — and then
	# sends every LATER call (refresh, /me, the avatar) to whatever
	# `backbone_url` was compiled with, which is the wrong site and a token it
	# will not recognise.
	var origin := _origin_of(redeem_url)

	if origin != "" and origin != config.backbone_url.trim_suffix("/"):
		DotLog.info(
			CHANNEL,
			"taking the backbone from the page",
			{"was": config.backbone_url, "now": origin}
		)
		config.backbone_url = origin

	var res := await _http.post_json(
		redeem_url,
		{
			"code": str(code_block.get("code", "")),
			"client": {
				"name": config.client_name,
				# The backbone's ClientInfoSchema has no "web" member, so a
				# browser build reports "unknown" rather than failing
				# validation — the same choice the device flow makes.
				"platform": DotPlatform.backbone_platform(),
				"version": config.client_version,
			},
		}
	)

	# Spent either way. A handoff is single-use, so a code that reached the
	# backbone is worthless whatever came back, and leaving it on the page only
	# buys a retry that is guaranteed to fail.
	DotAuthWebHandoff.consume()

	if not res.ok:
		return res.wrap("The page's sign-in code was not accepted.")

	var unwrapped := _unwrap(res.value)
	if not unwrapped.ok:
		return unwrapped

	var accepted := _accept_tokens(unwrapped.value)

	if accepted.ok:
		DotLog.info(CHANNEL, "signed in from the page's handoff")

	return accepted


## Waits briefly for the page to post its auth block.
##
## The block usually arrives while the engine's WASM is still downloading, so
## this normally returns on its first read. The wait exists for the other order:
## a loader that posts on frame load can lose the race against a cached export
## that boots immediately, and a game that gave up on the first frame would seat
## a signed-in member as a guest for no reason anybody could see.
## `https://host:port` from a URL, or `""` if it is not one.
static func _origin_of(url: String) -> String:
	var scheme_end := url.find("://")

	if scheme_end <= 0:
		return ""

	var rest := url.substr(scheme_end + 3)
	var slash := rest.find("/")

	if slash >= 0:
		rest = rest.substr(0, slash)

	return "" if rest == "" else url.substr(0, scheme_end + 3) + rest


func _await_page_auth(wait_sec: float) -> Dictionary:
	var deadline := Time.get_ticks_msec() + int(maxf(0.0, wait_sec) * 1000.0)

	while true:
		var auth := DotAuthWebHandoff.read()

		# An empty read is FINAL: the page publishes a `pending` marker while it
		# is still waiting to be handed a block, so "nothing there" means there
		# is nobody to hand one over — a top-level tab, or a page that predates
		# this. Waiting on it would cost every launch outside a player the full
		# timeout for an answer that will not change.
		if auth.is_empty():
			return {}

		if not DotAuthWebHandoff.pending(auth):
			return auth

		if Time.get_ticks_msec() >= deadline:
			return {}

		await get_tree().create_timer(0.1).timeout

	return {}


## Refreshes from the stored refresh token, without any user interaction.
func restore_session() -> DotResult:
	if not store.has_credentials():
		return DotResult.fail(
			DotError.CODE_AUTH, "There is nothing stored to sign in with."
		)

	if store.is_access_valid(config.refresh_margin_sec):
		var cached := store.identity()
		if cached != null:
			_identity = cached
			_schedule_refresh()
			signed_in.emit(_identity)
			return DotResult.success(_identity)

	return await refresh()


## Runs the full device-code login. Emits [signal device_code_ready] first.
func start_device_login() -> DotResult:
	if not _started:
		var s := start()
		if not s.ok:
			return s

	_signing_in = true
	_cancelled = false

	var pkce := DotPkce.generate()

	var start_res := await _http.post_json(
		config.device_endpoint(),
		{
			"client": {
				"name": config.client_name,
				# The backbone's ClientInfoSchema enum has no "web" member, so a
				# browser build reports "unknown" rather than failing validation.
				"platform": DotPlatform.backbone_platform(),
				"version": config.client_version,
			},
			"codeChallenge": pkce["challenge"],
		}
	)

	if not start_res.ok:
		_signing_in = false
		return start_res.wrap("Could not start the login.")

	var envelope: Dictionary = start_res.value
	var data := _unwrap(envelope)
	if not data.ok:
		_signing_in = false
		return data

	var d: Dictionary = data.value

	var device_code := str(d.get("deviceCode", ""))
	var user_code := str(d.get("userCode", ""))
	var uri := str(d.get("verificationUriComplete", d.get("verificationUri", "")))
	var expires_in := int(d.get("expiresIn", 600))
	var interval := float(d.get("interval", config.device_poll_interval_sec))

	if device_code == "" or user_code == "":
		_signing_in = false
		return DotResult.fail(
			DotError.CODE_PARSE,
			"The backbone did not return a device code.",
			JSON.stringify(d).substr(0, 200)
		)

	DotLog.info(
		CHANNEL, "device login started", {"code": user_code, "url": uri}
	)

	device_code_ready.emit(user_code, uri, expires_in)

	var result := await _poll_for_token(
		device_code, str(pkce["verifier"]), interval, expires_in
	)

	_signing_in = false
	return result


## Polls `/auth/token` until the user approves, denies, or it expires.
func _poll_for_token(
	device_code: String,
	verifier: String,
	interval: float,
	expires_in: int
) -> DotResult:
	var deadline := Time.get_ticks_msec() + int(
		minf(float(expires_in), config.device_timeout_sec) * 1000.0
	)
	var started := Time.get_ticks_msec()
	var wait := maxf(1.0, interval)

	while Time.get_ticks_msec() < deadline:
		if _cancelled:
			return DotResult.fail(
				DotError.CODE_CANCELLED, "The login was cancelled."
			)

		await get_tree().create_timer(wait).timeout

		if _cancelled:
			return DotResult.fail(
				DotError.CODE_CANCELLED, "The login was cancelled."
			)

		awaiting_approval.emit(
			float(Time.get_ticks_msec() - started) / 1000.0
		)

		var res := await _http.post_json(
			config.token_endpoint(),
			{"deviceCode": device_code, "codeVerifier": verifier}
		)

		# Pending and slow_down come back as 202 with an error envelope, so a
		# transport-level failure and "the user has not clicked yet" arrive
		# through different paths and must be told apart.
		var code := _envelope_code(res)

		match code:
			"authorization_pending":
				continue
			"slow_down":
				# Honour the instruction rather than the configured interval:
				# ignoring it is how a grant gets burned for polling abuse.
				wait = minf(wait * 1.5, 30.0)
				DotLog.debug(
					CHANNEL, "backbone asked us to slow down", {"wait": wait}
				)
				continue
			"access_denied":
				return DotResult.fail(
					DotError.CODE_FORBIDDEN,
					"This device was not approved."
				)
			"expired_token":
				return DotResult.fail(
					DotError.CODE_TIMEOUT,
					"The login attempt expired. Please try again."
				)

		if not res.ok:
			# Anything else that is retryable (a 500, a dropped connection) is
			# worth another poll — the grant is still live on the backbone.
			if res.is_retryable():
				continue
			return res.wrap("The login failed.")

		var unwrapped := _unwrap(res.value)
		if not unwrapped.ok:
			return unwrapped

		return _accept_tokens(unwrapped.value)

	return DotResult.fail(
		DotError.CODE_TIMEOUT, "The login attempt timed out."
	)


## Stops an in-progress device login.
func cancel_sign_in() -> void:
	if _signing_in:
		_cancelled = true
		DotLog.info(CHANNEL, "login cancelled")


# --- Tokens ----------------------------------------------------------------

## Rotates the credential pair.
##
## The backbone retires the old refresh token on every use, so a `token_reuse`
## response means a retired token came back — either a race, or theft. Either way
## every device has been signed out and the only correct response is to clear the
## store and tell the player.
func refresh() -> DotResult:
	if not store.has_credentials():
		return DotResult.fail(
			DotError.CODE_AUTH, "There is no refresh token."
		)

	var res := await _http.post_json(
		config.refresh_endpoint(), {"refreshToken": store.refresh_token()}
	)

	var code := _envelope_code(res)

	if code == "token_reuse":
		store.clear()
		_identity = null
		DotLog.warn(
			CHANNEL,
			"the backbone reported credential reuse and signed every device out"
		)
		session_revoked.emit(
			"This session was signed out because its credentials were used "
			+ "from somewhere else."
		)
		signed_out.emit()
		return DotResult.fail(
			DotError.CODE_AUTH,
			"You were signed out for security reasons. Please sign in again."
		)

	if code == "invalid_grant":
		store.clear()
		_identity = null
		signed_out.emit()
		return DotResult.fail(
			DotError.CODE_AUTH, "Please sign in again."
		)

	if not res.ok:
		# A network failure is not a sign-out. Keeping the stored token means a
		# player on a flaky connection is not made to log in again.
		return res.wrap("Could not refresh the session.")

	var unwrapped := _unwrap(res.value)
	if not unwrapped.ok:
		return unwrapped

	var accepted := _accept_tokens(unwrapped.value)
	if accepted.ok:
		token_refreshed.emit()
	return accepted


func _accept_tokens(d: Dictionary) -> DotResult:
	var access := str(d.get("accessToken", ""))
	var refresh_token := str(d.get("refreshToken", ""))
	var expires_in := int(d.get("expiresIn", 3600))

	if access == "" or refresh_token == "":
		return DotResult.fail(
			DotError.CODE_PARSE,
			"The backbone did not return a usable credential pair."
		)

	var identity_res := DotAuthIdentity.from_backbone_user(
		d.get("user", {}) if d.get("user") is Dictionary else {}
	)

	if not identity_res.ok:
		return identity_res

	_identity = identity_res.value

	var saved := store.set_tokens(access, refresh_token, expires_in, _identity)
	if not saved.ok:
		# Failing to persist is not failing to sign in: the player is
		# authenticated for this session and will simply have to log in again
		# next launch.
		DotLog.warn(
			CHANNEL,
			"signed in, but the credentials could not be saved",
			{"detail": saved.error.detail}
		)

	_schedule_refresh()

	DotLog.info(
		CHANNEL,
		"signed in",
		{"user": _identity.label(), "expires_in": expires_in}
	)

	signed_in.emit(_identity)
	return DotResult.success(_identity)


## A valid access token, refreshing first if it is close to expiring.
##
## What anything calling the backbone on the player's behalf should use, rather
## than reading the store directly and racing the refresh.
func valid_access_token() -> DotResult:
	if not store.has_credentials():
		return DotResult.fail(DotError.CODE_AUTH, "Not signed in.")

	if store.is_access_valid(config.refresh_margin_sec):
		return DotResult.success(store.access_token())

	var refreshed := await refresh()
	if not refreshed.ok:
		return refreshed

	return DotResult.success(store.access_token())


func _schedule_refresh() -> void:
	if not auto_refresh or _refresh_timer == null:
		return

	var seconds := store.expires_in()
	if seconds <= 0:
		return

	# Refresh early, but never sooner than 30 seconds from now — a short-lived
	# token plus a large margin would otherwise produce a refresh loop.
	var delay := maxf(30.0, float(seconds) - config.refresh_margin_sec)
	_refresh_timer.start(delay)

	DotLog.debug(CHANNEL, "refresh scheduled", {"in": int(delay)})


func _on_refresh_due() -> void:
	if not store.has_credentials():
		return
	var res := await refresh()
	if not res.ok and res.is_retryable():
		# Try again shortly rather than waiting for the next natural expiry,
		# which by then has already passed.
		_refresh_timer.start(60.0)


# --- Sign out --------------------------------------------------------------

## Signs out, telling the backbone to retire the whole token family.
##
## [param local_only] skips the network call. Correct when the player is offline
## — a sign-out that fails because there is no connection would be a sign-out
## that does not happen.
func sign_out(local_only: bool = false) -> DotResult:
	if not local_only and store.has_credentials():
		var res := await _http.post_json(
			config.revoke_endpoint(), {"refreshToken": store.refresh_token()}
		)
		if not res.ok:
			DotLog.warn(
				CHANNEL,
				"could not revoke the session on the backbone; clearing it locally",
				{"why": res.code()}
			)

	store.clear()
	_identity = null

	if _refresh_timer != null:
		_refresh_timer.stop()

	DotLog.info(CHANNEL, "signed out")
	signed_out.emit()

	return DotResult.success(true)


# --- Identity --------------------------------------------------------------

func identity() -> DotAuthIdentity:
	return _identity


func is_signed_in() -> bool:
	return _identity != null and store.has_credentials()


## Re-reads the player's profile from `/api/app/v1/me`.
##
## For picking up a name or avatar change without signing out. Not needed on the
## join path — the identity from the token response is current enough.
func fetch_profile() -> DotResult:
	var token := await valid_access_token()
	if not token.ok:
		return token

	var res := await _http.get_json(
		config.me_endpoint(), {"Authorization": "Bearer %s" % token.value}
	)
	if not res.ok:
		return res.wrap("Could not load your profile.")

	var unwrapped := _unwrap(res.value)
	if not unwrapped.ok:
		return unwrapped

	var d: Dictionary = unwrapped.value
	var user: Variant = d.get("user", d)

	var identity_res := DotAuthIdentity.from_backbone_user(
		user if user is Dictionary else {}
	)
	if identity_res.ok:
		_identity = identity_res.value

	return identity_res


# --- Connect tickets -------------------------------------------------------

## Asks a ticket issuer for a short-lived credential scoped to one server.
##
## This is what a client sends to a game server under
## [constant DotAuthConfig.Strategy.TICKET]. The point is that the game server
## learns who you are without ever holding a credential for your site account.
##
## [param issuer_url] is the publisher's [DotAuthIssuer]. It is first-party — you
## are handing it your access token, exactly as you would any of the publisher's
## own services — and it hands back something scoped, short-lived and useless
## anywhere else.
func request_ticket(issuer_url: String, server_id: String) -> DotResult:
	var token := await valid_access_token()
	if not token.ok:
		return token

	var res := await _http.post_json(
		issuer_url.trim_suffix("/") + "/ticket",
		{"serverId": server_id},
		{"Authorization": "Bearer %s" % token.value}
	)

	if not res.ok:
		return _issuer_refusal(res, "Could not get a connect ticket.")

	var d: Dictionary = res.value
	var ticket := str(d.get("ticket", ""))

	if ticket == "":
		return DotResult.fail(
			DotError.CODE_PARSE, "The issuer returned no ticket."
		)

	DotLog.debug(CHANNEL, "connect ticket issued", {"server": server_id})
	return DotResult.success(ticket)


## Tells the issuer this player has left whatever server they were on.
##
## The polite half of [member DotAuthConfig.single_session]. The server they
## left will say so in its next roster report, but that can be a minute away,
## and a player who quit one server to join another should not spend it being
## told they are still on the first. Call it on disconnect. Harmless when the
## rule is off, when there was no session, or when the player is in fact still
## playing — the server's next report puts them back.
##
## Only ever ends the session behind this client's own token; there is no way to
## name somebody else.
func release_session(issuer_url: String) -> DotResult:
	var token := await valid_access_token()
	if not token.ok:
		return token

	var res := await _http.post_json(
		issuer_url.trim_suffix("/") + "/session/release",
		{},
		{"Authorization": "Bearer %s" % token.value}
	)

	if not res.ok:
		return _issuer_refusal(res, "Could not release the session.")

	var d: Dictionary = res.value
	var released := bool(d.get("released", false))

	DotLog.debug(CHANNEL, "session released", {"had_one": released})
	return DotResult.success(released)


## The issuer's own refusal, when it sent one, instead of "HTTP 403".
##
## The issuer answers with [code]{error, code}[/code] and its message is written
## for the player — "You are already connected to eu-west-1" is worth showing and
## "Not allowed." is not. [DotHttp] keeps the body as the error's detail, so it
## is recoverable without a second request, the same way [method _envelope_code]
## recovers the backbone's.
func _issuer_refusal(res: DotResult, fallback: String) -> DotResult:
	if res.ok or res.error == null:
		return res

	var parsed: Variant = JSON.parse_string(res.error.detail)
	if parsed is Dictionary and (parsed as Dictionary).has("error"):
		var body := parsed as Dictionary
		var err := DotError.make(
			str(body.get("code", res.error.code)),
			str(body["error"]),
			fallback
		)
		err.http_status = res.error.http_status
		err.retry_after = res.error.retry_after
		return DotResult.failure(err)

	return res.wrap(fallback)


# --- The app API, as this player --------------------------------------------

## POSTs to an app API endpoint with this player's own token.
##
## The player-side counterpart of [method DotBackboneClient.post_integration]:
## anything a client reports about ITSELF — its own statistics, a scope key
## request — goes through here, with the access token the device flow issued
## and nothing an integration holds. [param path] is relative to
## [code]/api/app/v1/[/code]. Returns the envelope's [code]data[/code].
func post_app(path: String, body: Dictionary) -> DotResult:
	var token := await valid_access_token()
	if not token.ok:
		return token

	var res := await _http.post_json(
		config.app_endpoint(path), body,
		{"Authorization": "Bearer %s" % token.value}
	)
	if not res.ok:
		return _app_refusal(res, "The request was refused.")

	return _unwrap_any(res.value)


## GETs an app API endpoint with this player's own token. See [method post_app].
func get_app(path: String, query: Dictionary = {}) -> DotResult:
	var token := await valid_access_token()
	if not token.ok:
		return token

	var url := config.app_endpoint(path)
	if not query.is_empty():
		var parts := PackedStringArray()
		for key in query:
			parts.append("%s=%s" % [str(key).uri_encode(), str(query[key]).uri_encode()])
		url += "?" + "&".join(parts)

	var res := await _http.get_json(url, {"Authorization": "Bearer %s" % token.value})
	if not res.ok:
		return _app_refusal(res, "The request was refused.")

	return _unwrap_any(res.value)


## The app API's `{ok, data}` envelope, whatever `data` is.
##
## [method _unwrap] knows the sign-in shapes; a stats or a scope-key reply is
## a plain object it would refuse for lacking a token, which is not a failure.
func _unwrap_any(response: Variant) -> DotResult:
	if not (response is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE, "The backbone sent an unexpected response."
		)
	var d := response as Dictionary
	if d.has("data"):
		return DotResult.success(d["data"])
	return DotResult.success(d)


## The app API's own error, when it sent one: `{ok: false, error: {code, message}}`.
func _app_refusal(res: DotResult, fallback: String) -> DotResult:
	if res.ok or res.error == null:
		return res

	var parsed: Variant = JSON.parse_string(res.error.detail)
	if parsed is Dictionary and (parsed as Dictionary).get("error") is Dictionary:
		var body: Dictionary = (parsed as Dictionary)["error"]
		var err := DotError.make(
			res.error.code, str(body.get("message", fallback)), str(body.get("code", ""))
		)
		err.http_status = res.error.http_status
		err.retry_after = res.error.retry_after
		return DotResult.failure(err)

	return res.wrap(fallback)


# --- Response helpers ------------------------------------------------------

## Unwraps the backbone's `{ok: true, data: …}` success envelope.
func _unwrap(response: Variant) -> DotResult:
	if not (response is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE, "The backbone sent an unexpected response."
		)

	var d := response as Dictionary

	if d.has("data"):
		var data: Variant = d["data"]
		if data is Dictionary:
			return DotResult.success(data)

	# Some endpoints answer with the payload directly. Accepting both keeps a
	# contract change from breaking sign-in outright.
	if d.has("accessToken") or d.has("deviceCode") or d.has("user"):
		return DotResult.success(d)

	return DotResult.fail(
		DotError.CODE_PARSE,
		"The backbone sent no data.",
		JSON.stringify(d).substr(0, 200)
	)


## The backbone's error `code` from a failed request, or [code]""[/code].
##
## Its handler puts the machine-readable code in the JSON body even for non-2xx
## responses, and [DotHttp] keeps that body as the error's detail — so the code is
## recoverable without a second request.
func _envelope_code(res: DotResult) -> String:
	if res.ok:
		return ""
	if res.error == null or res.error.detail == "":
		return ""

	var parsed: Variant = JSON.parse_string(res.error.detail)
	if not (parsed is Dictionary):
		return ""

	return str((parsed as Dictionary).get("code", ""))


func describe() -> Dictionary:
	return {
		"signed_in": is_signed_in(),
		"user": _identity.label() if _identity != null else "",
		"backbone": config.backbone_url if config != null else "",
		"store": store.describe() if store != null else {},
		"signing_in": _signing_in,
	}
