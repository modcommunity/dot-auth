@tool
class_name DotAuthClient
extends "res://addons/dot_auth/client/dot_auth_client_envelope.gd"

## Signs a player in against the website-city backbone and keeps them signed in.
##
## The backbone's device-code grant (`/api/app/v1/auth/*`, per `~/types/app-api/contract.ts`): PKCE start, polling with the server's interval and `slow_down`, rotating refresh. A device flow, not a password field, so the password is only ever typed on the website. Usage: docs/rationale.md.

const CHANNEL := "auth"

## The registry name this client takes, so a game running under a shell that signed the
## player in can find out who it is without being handed the shell's internals.
const SERVICE := &"dot_auth_client"

## Emitted once the backbone has issued a device code. Open [param verification_uri_complete]
## (code pre-filled); [param user_code] is for typing on another device.
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

## Accept an identity handed over by an embedding website (browser builds). On by default; turn off for a build that must not trust its embedder.
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

	# Before start(): a game that looks this up must find it even while a stored session is
	# still being restored, and read is_signed_in() / the signed_in signal from there.
	if not DotRegistry.has(SERVICE):
		DotRegistry.register(SERVICE, self)

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



## Signs the player in, reusing stored credentials when possible; a device login starts only with nothing to restore.
func sign_in() -> DotResult:
	if not _started:
		var s := start()
		if not s.ok:
			return s

	if _signing_in:
		return DotResult.fail(
			DotError.CODE_STATE, "A sign-in is already in progress."
		)

	# The page's handoff comes FIRST: the site knows who is at the keyboard now, while a browser store is per origin and may hold someone else.
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


## Signs in from the code the embedding page handed us, see [DotAuthWebHandoff].
##
## Every "no" (native build, nothing published, signed-out visitor, TMC identity off) is an ordinary failed [DotResult] for the caller to fall through, which [method sign_in] does at debug level.
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

	# Take the handing page's origin, not the configured one: it IS the backbone, and otherwise later calls (refresh, /me) go to the compiled-in `backbone_url`.
	var origin := _origin_of(redeem_url)

	if origin != "" and origin != config.backbone_url.trim_suffix("/"):
		DotLog.info(
			CHANNEL,
			"taking the backbone from the page",
			{"was": config.backbone_url, "now": origin}
		)
		config.backbone_url = origin

	var accepted := await _redeem_code(redeem_url, str(code_block.get("code", "")))

	# Spent either way. A handoff is single-use, so a code that reached the
	# backbone is worthless whatever came back, and leaving it on the page only
	# buys a retry that is guaranteed to fail.
	DotAuthWebHandoff.consume()

	if not accepted.ok:
		return accepted.wrap("The page's sign-in code was not accepted.")

	DotLog.info(CHANNEL, "signed in from the page's handoff")
	return accepted


## Signs in from a handoff code a LAUNCHER passed in, on any platform; the native twin of [method try_web_handoff].
##
## Redeemed at this client's own [member DotAuthConfig.backbone_url], never a URL the launcher names, or whoever wrote a shortcut could aim a member's code at their own host. Every refusal is a failed [DotResult] to fall through on.
func redeem_handoff(code: String) -> DotResult:
	code = code.strip_edges()
	if code == "":
		return DotResult.fail(DotError.CODE_INVALID, "No sign-in code was given.")

	if not _started:
		var s := start()
		if not s.ok:
			return s

	var accepted := await _redeem_code(config.app_endpoint("auth/handoff"), code)
	if not accepted.ok:
		return accepted.wrap("The launcher's sign-in code was not accepted.")

	DotLog.info(CHANNEL, "signed in from the launcher's handoff")
	return accepted


## Posts [param code] to [param redeem_url] and accepts the credential pair it buys.
func _redeem_code(redeem_url: String, code: String) -> DotResult:
	var res := await _http.post_json(
		redeem_url,
		{
			"code": code,
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

	if not res.ok:
		return res

	var unwrapped := _unwrap(res.value)
	if not unwrapped.ok:
		return unwrapped

	return _accept_tokens(unwrapped.value)


## [code]https://host:port[/code] from a URL, or [code]""[/code] if it is not one.
static func _origin_of(url: String) -> String:
	var scheme_end := url.find("://")

	if scheme_end <= 0:
		return ""

	var rest := url.substr(scheme_end + 3)
	var slash := rest.find("/")

	if slash >= 0:
		rest = rest.substr(0, slash)

	return "" if rest == "" else url.substr(0, scheme_end + 3) + rest


## Waits briefly for the page to post its auth block, which can lose the race against a cached export that boots at once.
func _await_page_auth(wait_sec: float) -> Dictionary:
	var deadline := Time.get_ticks_msec() + int(maxf(0.0, wait_sec) * 1000.0)

	while true:
		var auth := DotAuthWebHandoff.read()

		# An empty read is FINAL: the page publishes a `pending` marker while waiting, so nothing there means nobody will hand one over.
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



## Rotates the credential pair.
##
## The backbone retires the old refresh token on every use, so `token_reuse` means a retired token came back (a race or theft) and every device is signed out: clear the store and tell the player.
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


## A valid access token, refreshing first if close to expiry; use this rather than the store, which races the refresh.
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



## Signs out, telling the backbone to retire the whole token family; [param local_only] skips the network call, for when offline.
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



func identity() -> DotAuthIdentity:
	return _identity


func is_signed_in() -> bool:
	return _identity != null and store.has_credentials()


## A stable, non-secret key for the signed-in account, or "" for a guest: the identity's
## uid (the backbone's public user id), never a token. What a game files per-account local
## state under (a remembered loadout), so two accounts on one machine keep their own.
func account_key() -> String:
	if not is_signed_in():
		return ""
	return _identity.uid


## Re-reads the player's profile from `/api/app/v1/me`, to pick up a name or avatar change.
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



## Asks a ticket issuer for a short-lived credential scoped to one server, sent under [constant DotAuthConfig.Strategy.TICKET].
##
## [param issuer_url] is the publisher's first-party [DotAuthIssuer]; it gets your access token and returns something scoped and useless elsewhere.
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


## Asks for a connect ticket for the server at [param address], the address THIS client dialled, never one a server announced (a hostile server naming another's id would get a ticket valid there).
##
## [param issuer_url] defaults to [member DotAuthConfig.ticket_issuer_url]; [param nonce] is the server's challenge for this connection and binds the ticket to it.
func request_ticket_for_address(
	address: String, issuer_url: String = "", nonce: String = ""
) -> DotResult:
	if address.strip_edges() == "":
		return DotResult.fail(DotError.CODE_INVALID, "No server address to ask a ticket for.")
	var body := {"address": address}
	if nonce != "":
		body["nonce"] = nonce
	var issuer := issuer_url if issuer_url != "" else config.ticket_issuer_url
	var res: DotResult
	if issuer == "":
		if config.backbone_url.strip_edges() == "":
			return DotResult.fail(
				DotError.CODE_STATE, "This game has no sign-in service configured."
			)
		res = await post_app("auth/ticket", body)
		if not res.ok:
			return res
	else:
		var token := await valid_access_token()
		if not token.ok:
			return token
		res = await _http.post_json(
			issuer.trim_suffix("/") + "/ticket",
			body,
			{"Authorization": "Bearer %s" % token.value}
		)
		if not res.ok:
			return _issuer_refusal(res, "Could not get a connect ticket.")
	var d: Variant = res.value
	var ticket := str((d as Dictionary).get("ticket", "")) if d is Dictionary else ""
	if ticket == "":
		return DotResult.fail(DotError.CODE_PARSE, "The issuer returned no ticket.")
	DotLog.debug(CHANNEL, "connect ticket issued", {"address": address})
	return DotResult.success(ticket)



## Whether this client treats the server announcing [param audience] as first-party,
## i.e. may join it under [constant DotAuthConfig.Strategy.INTROSPECT]. See
## [member DotAuthConfig.first_party_audiences].
func is_first_party(audience: String) -> bool:
	return audience != "" and config.first_party_audiences.has(audience)


## Mints a single-use join token for ONE server, sent to an INTROSPECT server in place of the access token (which never leaves this client).
##
## [param audience] must be in [member DotAuthConfig.first_party_audiences]; the token lasts sixty seconds and only that audience's credential can spend it.
func request_join_token(audience: String) -> DotResult:
	if not is_first_party(audience):
		return DotResult.fail(
			DotError.CODE_FORBIDDEN,
			"This server is not one this game signs in to directly.",
			"audience %s is not in first_party_audiences" % audience
		)

	var res := await post_app("play/join-token", {"audience": audience})
	if not res.ok:
		return res

	var d: Variant = res.value
	var token := str((d as Dictionary).get("token", "")) if d is Dictionary else ""
	if not token.begins_with("tmc_jt_"):
		return DotResult.fail(
			DotError.CODE_PARSE, "The backbone returned no join token."
		)

	DotLog.debug(CHANNEL, "join token issued", {"audience": audience})
	return DotResult.success(token)


## Tells the issuer this player has left whatever server they were on; call it on disconnect.
##
## The polite half of [member DotAuthConfig.single_session]: the server's own roster report can be a minute away. Harmless when the rule is off or the player is still playing, and it only ends the session behind this client's own token.
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


## The issuer's own refusal when it sent one, instead of "HTTP 403": its message is written for the player. [DotHttp] keeps the body as the error's detail.
func _issuer_refusal(res: DotResult, fallback: String) -> DotResult:
	if res.ok or res.error == null:
		return res

	var parsed: Variant = _envelope_of(res.error.detail)
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



## POSTs to an app API endpoint with this player's own token, for anything a client reports about ITSELF; [param path] is relative to [code]/api/app/v1/[/code].
##
## The player-side counterpart of [method DotBackboneClient.post_integration]. Returns the envelope's [code]data[/code].
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


func describe() -> Dictionary:
	return {
		"signed_in": is_signed_in(),
		"user": _identity.label() if _identity != null else "",
		"backbone": config.backbone_url if config != null else "",
		"store": store.describe() if store != null else {},
		"signing_in": _signing_in,
	}
