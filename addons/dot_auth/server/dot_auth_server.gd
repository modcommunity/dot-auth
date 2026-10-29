@tool
class_name DotAuthServer
extends "res://addons/dot_auth/server/dot_auth_server_local.gd"

## Decides who a connecting client is: the game server's side of dot-auth.
##
## dot-server calls [method authenticate] with the client's credential and gets a [DotAuthIdentity] or a refusal; [member DotAuthConfig.strategy] picks the method. Registers as [code]dot_auth_server[/code] in [DotRegistry], and builds the [DotAuthSessionReporter] when [member DotAuthConfig.session_report_url] is set. Usage: docs/rationale.md.

## Registry name dot-server looks for.
const SERVICE := &"dot_auth_server"

## What a join token starts with (website-city's `JOIN_TOKEN_PREFIX`).
const JOIN_TOKEN_PREFIX := "tmc_jt_"

signal authenticated(identity: DotAuthIdentity)
signal rejected(reason: String, detail: String)
@export_group("Configuration")

@export var config_file: String = "user://dot_auth_server.json"

## Register in [DotRegistry] on ready. Turn off for two servers in one process that
## register scoped names themselves ([method DotRegistry.register_scoped]).
@export var register_service: bool = true

## Build a [DotAuthSessionReporter] when [member DotAuthConfig.session_report_url] is
## set. Off for a host that builds and feeds its own.
@export var create_session_reporter: bool = true

## The reporter this server built, or null (no [code]session_report_url[/code], or [member create_session_reporter] off).
##
## Built here because its lifetime and config are this node's; dot-game's per-GAME module would unload it mid-game, and dot-server never names dot-auth. It reaches dot-server by duck type through [DotRegistry].
var session_reporter: DotAuthSessionReporter = null

## The server's own backbone client, holding its integration credential.
##
## Set, INTROSPECT asks the backbone as THIS SERVER and gets the player's key in this server's scope, which other operators cannot correlate. Unset, it reads `/api/app/v1/me` (first-party servers only). Also learns [method join_audience] when not pinned.
var backbone: DotBackboneClient = null:
	set(value):
		backbone = value
		if value != null and config != null \
				and (config.join_audience == "" or config.adopt_ticket_trust):
			_discover_join_audience.call_deferred()

## The audience learnt from the backbone; see [method join_audience].
var _discovered_audience: String = ""

## How many failed `integration/v1/me` reads [method join_audience] discovery retries,
## with backoff capped at 30 s (the default is about an hour).
var discover_audience_tries: int = 130

## Refuse an INTROSPECT join while [member backbone] is unset, rather than falling back to `/me`.
##
## A player let in through `/me` before the credential loads is keyed by account id, splitting profile, avatar and bans from the identity they get a minute later.
var scoped_only: bool = false

var _limiter: DotRateLimiter = null

## Spent ticket ids: jti -> expiry unix seconds.
var _spent_tickets: Dictionary = {}

## Where [method authenticate] carries the host's connection nonce to the ticket check.
const CONNECTION_NONCE_KEY := "_connection_nonce"
var _last_sweep: int = 0

var _stats := {"ok": 0, "rejected": 0, "guests": 0}

## Refusals in a row, with no real sign-in between, before the pattern is logged at WARN.
##
## One refused ticket is the player's problem (INFO); ten in a row is almost always this server's (a foreign key, a wrong `server_id`, clock drift).
const REFUSAL_RUN_WARN := 10

var _refused_run: int = 0
var _warned_run: bool = false
# Edge state: a verifier that cannot be reached (the backbone behind INTROSPECT, or a
# provider's service) is said once when it starts failing and once when it recovers,
# rather than at WARN on every join while it is down.
var _verifier_down: bool = false

## Custom authentication providers, consulted before the built-in strategy.
##
## See [DotAuthProvider]. Kept sorted by priority.
var _providers: Array[DotAuthProvider] = []

## The provider built from [member DotAuthConfig.allow_local_profiles], if any; held so a console command can reach the store.
var _local_profiles: DotLocalProfileProvider = null


## Registers a custom authentication provider, validated now so a missing API key fails at boot, not on the first login.
func add_provider(provider: DotAuthProvider) -> DotResult:
	if provider == null:
		return DotResult.fail(DotError.CODE_INVALID, "Null provider.")

	var valid := provider.validate()
	if not valid.ok:
		return valid.wrap(
			"Auth provider '%s' refused to start." % provider.provider_name()
		)

	_providers.append(provider)
	_providers.sort_custom(func(a: DotAuthProvider, b: DotAuthProvider) -> bool:
		return a.priority < b.priority
	)

	DotLog.info(
		CHANNEL,
		"auth provider added",
		{"provider": provider.provider_name(), "priority": provider.priority}
	)

	return DotResult.success(provider)


func remove_provider(provider: DotAuthProvider) -> void:
	_providers.erase(provider)


func providers() -> Array[DotAuthProvider]:
	return _providers.duplicate()


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	var res := start()
	if not res.ok:
		DotLog.result(CHANNEL, "auth server start", res)


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

	var valid := config.validate()
	if not valid.ok:
		return valid

	config.warn_about_risky_settings()

	if config.server_id != "":
		_server_id_source = "config"
	if config.strategy == DotAuthConfig.Strategy.INTROSPECT or config.adopt_ticket_trust:
		_http = DotHttp.new()
		_http.name = "AuthServerHttp"
		_http.timeout_sec = 10.0
		add_child(_http)

	if config.strategy == DotAuthConfig.Strategy.LOCAL:
		var accounts := _load_accounts()
		if not accounts.ok:
			return accounts

	var profiles := _enable_local_profiles()
	if not profiles.ok:
		return profiles

	_limiter = DotRateLimiter.new(
		float(config.auth_attempts_per_minute) / 60.0,
		float(config.auth_attempts_per_minute)
	)

	if register_service:
		DotRegistry.register(SERVICE, self)

	_build_session_reporter()

	_started = true

	if config.adopt_ticket_trust:
		_begin_ticket_trust()

	DotLog.info(
		CHANNEL,
		"auth ready",
		{
			"strategy": DotAuthConfig.Strategy.keys()[config.strategy],
			"server_id": config.server_id,
			"guests": config.allow_guests,
			"local_profiles": config.allow_local_profiles,
		}
	)

	return DotResult.success(self)


## Local profiles are a PROVIDER, not a strategy, so they compose with whatever the
## server already does; built here so `allow_local_profiles` works on its own. A game
## owning the store registers its own provider and leaves this off.
func _enable_local_profiles() -> DotResult:
	if config.allow_local_profiles and _local_profiles == null:
		var store := DotLocalProfiles.at(config.local_profiles_path)
		store.max_profiles = config.max_local_profiles

		_local_profiles = DotLocalProfileProvider.new()
		_local_profiles.profiles = store
		_local_profiles.allow_creation = config.local_profile_signup

		var registered := add_provider(_local_profiles)
		if not registered.ok:
			return registered.wrap("Could not enable local profiles.")
	return DotResult.success(null)


func _begin_ticket_trust() -> void:
	_load_ticket_trust_cache()
	ticket_key_wanted.connect(func(_kid: String) -> void: refresh_ticket_keys())
	refresh_ticket_keys.call_deferred()
	var t := Timer.new()
	t.name = "TicketKeysRefresh"
	t.wait_time = _keys_refresh_sec
	t.autostart = true
	t.timeout.connect(func() -> void: refresh_ticket_keys(true))
	add_child(t)


## The local-profile provider this server built, or null; the way a game reaches the store.
func local_profiles() -> DotLocalProfileProvider:
	return _local_profiles


func _exit_tree() -> void:
	if register_service:
		DotRegistry.unregister_instance(SERVICE, self)
	if DotRegistry.signals().service_registered.is_connected(_on_service_registered):
		DotRegistry.signals().service_registered.disconnect(_on_service_registered)


## Off, and silent, unless the config names an issuer: a server with no
## session_report_url has no backbone to tell, and that is most of them.
## [method DotAuthConfig.validate] has already refused a URL without a key or a server id.
func _build_session_reporter() -> void:
	if not create_session_reporter or session_reporter != null:
		return
	if config.session_report_url.strip_edges() == "":
		return

	session_reporter = DotAuthSessionReporter.new()
	session_reporter.name = "SessionReporter"
	session_reporter.config = config
	add_child(session_reporter)

	# The dot-server may boot before or after this node starts.
	var server := DotRegistry.get_service(&"dot_server")
	if server != null:
		session_reporter.follow_server(server)
	else:
		DotRegistry.signals().service_registered.connect(_on_service_registered)
		DotLog.debug(CHANNEL, "session reporter waiting for a dot_server to follow")


func _on_service_registered(service: StringName, instance: Object) -> void:
	if service != &"dot_server" or session_reporter == null:
		return
	DotRegistry.signals().service_registered.disconnect(_on_service_registered)
	session_reporter.follow_server(instance)



## Resolves a client's credential to an identity.
##
## [param credential] keys: [code]ticket[/code], [code]access_token[/code], [code]username[/code], [code]password[/code], [code]device_id[/code], [code]name[/code]. [param rate_key] scopes the attempt limit (the peer's address); [param connection_nonce] is the host's nonce for THIS connection, and a ticket bound to another is refused.
func authenticate(
	credential: Dictionary,
	rate_key: Variant = null,
	connection_nonce: String = ""
) -> DotResult:
	if not _started:
		var s := start()
		if not s.ok:
			return s

	# The nonce must come from the host, never from what the client sent.
	credential = credential.duplicate()
	credential.erase(CONNECTION_NONCE_KEY)
	if connection_nonce != "":
		credential[CONNECTION_NONCE_KEY] = connection_nonce

	var key: Variant = rate_key if rate_key != null else str(
		credential.get("device_id", "anonymous")
	)

	if not _limiter.allow(key):
		# Rate limiting runs before providers, so a custom provider cannot turn this server into a hammer on an external service.
		var err := DotError.make(
			DotError.CODE_RATE_LIMITED,
			"Too many sign-in attempts. Please wait a moment."
		)
		err.retry_after = _limiter.retry_after(key)
		_stats["rejected"] += 1
		_log_refusal(err, key, credential)
		rejected.emit(err.message, "rate limited")
		return DotResult.failure(err)

	var res: DotResult = null

	# Custom providers first. One that claims a credential owns the outcome: falling through after a rejection would let a refused login in by another door.
	for provider in _providers:
		if not provider.handles(credential):
			continue

		res = await provider.authenticate(credential)

		if res.ok:
			var provided: DotAuthIdentity = res.value
			_apply_requested_name(provided, credential)
			DotLog.info(
				CHANNEL,
				"authenticated by provider",
				{"provider": provider.provider_name(), "user": provided.label()}
			)
		break

	if res != null:
		return _finish(res, key, credential)

	match config.strategy:
		DotAuthConfig.Strategy.TICKET:
			res = _authenticate_ticket(credential)
		DotAuthConfig.Strategy.INTROSPECT:
			res = await _authenticate_introspect(credential)
		DotAuthConfig.Strategy.LOCAL:
			res = _authenticate_local(credential)
		DotAuthConfig.Strategy.ANONYMOUS:
			res = _make_guest(credential)
		_:
			res = DotResult.fail(
				DotError.CODE_INTERNAL, "Unknown authentication strategy."
			)

	return _finish(res, key, credential)


## Applies the guest fallback and records the outcome, shared by the provider path and the built-in strategies so both get the same rules, counters and signals.
func _finish(
	res: DotResult,
	key: Variant,
	credential: Dictionary
) -> DotResult:
	# Before the guest fallback, because a verifier that is down is the operator's
	# problem whether or not the player was then let in as a guest.
	if not res.ok and res.error != null and res.error.is_retryable() and not _verifier_down:
		_verifier_down = true
		DotLog.warn(CHANNEL, "sign-ins cannot be verified right now", {
			"strategy": strategy_name(),
			"code": res.code(),
			"error": res.error.message,
			"detail": res.error.detail,
		})

	if not res.ok and config.allow_guests and config.strategy != DotAuthConfig.Strategy.ANONYMOUS:
		DotLog.info(
			CHANNEL,
			"authentication failed; admitting as a guest",
			{"why": res.code()}
		)
		res = _make_guest(credential)

	if res.ok:
		var identity: DotAuthIdentity = res.value
		if identity.is_guest:
			_stats["guests"] += 1
		else:
			_stats["ok"] += 1
			# A successful sign-in clears the attempt budget: the limit exists to
			# throttle guessing, not to throttle a player who has just proved who
			# they are and may need to reconnect.
			_limiter.reset(key)
			_refused_run = 0
			_warned_run = false
			if _verifier_down:
				_verifier_down = false
				DotLog.info(CHANNEL, "sign-ins are being verified again", {
					"strategy": strategy_name()
				})
		authenticated.emit(identity)
	else:
		_stats["rejected"] += 1
		_log_refusal(res.error, key, credential)
		rejected.emit(
			res.error.message, res.error.detail if res.error != null else ""
		)

	return res


## Says why a sign-in was refused, at the level of whoever has to act on it.
##
## A refused credential is the player's (INFO, kept as it is what a guessing attack looks like; a long run escalates once, see [constant REFUSAL_RUN_WARN]); rate limiting is DEBUG; an unreachable verifier is WARN in [method _finish]; this server's own fault is ERROR. Never the credential itself (no password, token or ticket); the username is logged because guessing aims at it.
func _log_refusal(err: DotError, key: Variant, credential: Dictionary) -> void:
	var code := err.code if err != null else DotError.CODE_INTERNAL
	var fields := {
		"code": code,
		"reason": err.message if err != null else "",
		"from": str(key),
		"strategy": strategy_name(),
	}
	if err != null and err.detail != "":
		fields["detail"] = err.detail
	var username := str(credential.get("username", ""))
	if username != "":
		fields["username"] = username.to_lower().substr(0, 64)

	if code == DotError.CODE_RATE_LIMITED:
		DotLog.debug(CHANNEL, "sign-in refused: too many attempts", fields)
		return

	if err != null and err.is_retryable():
		DotLog.debug(CHANNEL, "sign-in refused: could not be verified", fields)
		return

	if code in [
		DotError.CODE_INTERNAL, DotError.CODE_STATE, DotError.CODE_IO,
		DotError.CODE_UNSUPPORTED,
	]:
		DotLog.error(CHANNEL, "sign-in failed on this server's side", fields)
		return

	DotLog.info(CHANNEL, "sign-in refused", fields)

	_refused_run += 1
	if _refused_run >= REFUSAL_RUN_WARN and not _warned_run:
		_warned_run = true
		DotLog.warn(CHANNEL, "every recent sign-in has been refused", {
			"in_a_row": _refused_run,
			"last_code": code,
			"last_detail": fields.get("detail", ""),
			"strategy": strategy_name(),
			"hint": "if these are real players: ticket_public_key, server_id and the clock",
		})


## Verifies a signed connect ticket. Offline: no network call per join.
func _authenticate_ticket(credential: Dictionary) -> DotResult:
	var ticket := str(credential.get("ticket", ""))
	if ticket == "":
		return DotResult.fail(
			DotError.CODE_AUTH,
			"This server requires you to be signed in.",
			"no ticket presented"
		)

	if not ticket_trust_ready():
		return DotResult.fail(
			DotError.CODE_STATE,
			"This server cannot verify sign-ins yet. Try again in a moment.",
			"no server_id or issuer key adopted yet"
		)
	var key := _ticket_key_for(ticket)
	if not key.ok:
		return key

	var verified := DotAuthTicket.verify(
		ticket,
		str(key.value),
		config.server_id,
		config.ticket_leeway_sec
	)

	if not verified.ok:
		return verified

	var d: Dictionary = verified.value
	var jti := str(d["jti"])
	if jti == "":
		return DotResult.fail(
			DotError.CODE_INVALID, "This connect ticket is not valid.", "no jti"
		)

	var bound := _check_ticket_binding(str(d.get("nonce", "")), credential)
	if not bound.ok:
		return bound

	_sweep_spent()

	# Single use, so a ticket copied in flight cannot be replayed within its life.
	if _spent_tickets.has(jti):
		DotLog.warn(
			CHANNEL,
			"a connect ticket was presented twice",
			{"jti": jti.substr(0, 12)}
		)
		return DotResult.fail(
			DotError.CODE_FORBIDDEN,
			"This connect ticket has already been used.",
			"replay refused"
		)

	if _spent_tickets.size() >= config.ticket_replay_max:
		_last_sweep = 0
		_sweep_spent()
		if _spent_tickets.size() >= config.ticket_replay_max:
			DotLog.warn(CHANNEL, "the spent-ticket memory is full; refusing tickets", {
				"max": config.ticket_replay_max,
			})
			return DotResult.fail(
				DotError.CODE_RATE_LIMITED,
				"This server is busy. Try again in a moment.",
				"spent-ticket memory full"
			)
	_spent_tickets[jti] = int(d["exp"])

	var identity: DotAuthIdentity = d["identity"]
	_apply_requested_name(identity, credential)

	DotLog.info(CHANNEL, "authenticated by ticket", {"user": identity.label()})

	return DotResult.success(identity)


## A ticket bound to a connection nonce must name this connection's; an unbound one
## is refused only under [member DotAuthConfig.require_ticket_binding].
func _check_ticket_binding(ticket_nonce: String, credential: Dictionary) -> DotResult:
	var ours := str(credential.get(CONNECTION_NONCE_KEY, ""))
	if ticket_nonce == "":
		if config.require_ticket_binding:
			return DotResult.fail(
				DotError.CODE_FORBIDDEN,
				"This server needs a newer version of the game to sign in.",
				"unbound ticket refused (require_ticket_binding)"
			)
		return DotResult.success(null)
	if ours == "" or not DotHash.constant_time_equal(
			ticket_nonce.to_utf8_buffer(), ours.to_utf8_buffer()
	):
		DotLog.warn(CHANNEL, "a connect ticket bound to another connection was presented")
		return DotResult.fail(
			DotError.CODE_FORBIDDEN,
			"This connect ticket was issued for another connection.",
			"nonce mismatch"
		)
	return DotResult.success(null)


## Resolves what an INTROSPECT client sent.
##
## With a [member backbone]: a join token through `player/introspect`, yielding a scoped key. Without: `/api/app/v1/me`, first-party servers only. A client that will not send a token sends a connect ticket instead, verified offline.
func _authenticate_introspect(credential: Dictionary) -> DotResult:
	var token := str(credential.get("access_token", ""))
	if token == "" and str(credential.get("ticket", "")) != "" \
			and (config.ticket_public_key != "" or config.adopt_ticket_trust
				or not config.ticket_public_keys.is_empty()):
		return _authenticate_ticket(credential)
	if token == "":
		return DotResult.fail(
			DotError.CODE_AUTH, "This server requires you to be signed in."
		)

	if backbone != null:
		return await _authenticate_introspect_scoped(token, credential)

	# A current client sends a join token, which only `player/introspect` accepts —
	# the `/me` fallback below cannot resolve it, so say why instead of "not valid".
	if token.begins_with(JOIN_TOKEN_PREFIX):
		return DotResult.fail(
			DotError.CODE_STATE,
			"This server cannot verify sign-ins yet. Try again in a moment.",
			"a join token needs the server's integration credential (backbone is unset)"
		)

	if scoped_only:
		return DotResult.fail(
			DotError.CODE_STATE,
			"This server cannot verify sign-ins yet. Try again in a moment.",
			"scoped_only is set and no backbone client has been handed over"
		)

	var res := await _http.get_json(
		config.me_endpoint(), {"Authorization": "Bearer %s" % token}
	)

	if not res.ok:
		if res.error != null and res.error.http_status == 401:
			return DotResult.fail(
				DotError.CODE_AUTH, "Your sign-in is no longer valid."
			)
		# A backbone outage must not read as "you are not who you say you are".
		return res.wrap("Could not verify your sign-in right now.")

	var payload: Variant = res.value
	if not (payload is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE, "The backbone sent an unexpected response."
		)

	var user: Variant = (payload as Dictionary).get("data", payload)
	if user is Dictionary and (user as Dictionary).has("user"):
		user = (user as Dictionary)["user"]

	var identity_res := DotAuthIdentity.from_backbone_user(
		user if user is Dictionary else {}
	)
	if not identity_res.ok:
		return identity_res

	var identity: DotAuthIdentity = identity_res.value
	_apply_requested_name(identity, credential)

	DotLog.info(
		CHANNEL, "authenticated by introspection", {"user": identity.label()}
	)

	return DotResult.success(identity)


## INTROSPECT through the server's integration credential, see [member backbone].
##
## The identity has no account id: [member DotAuthIdentity.uid] is `tmc:<key>` and the key is the `scoped_key` claim dot-user files the profile under.
func _authenticate_introspect_scoped(token: String, credential: Dictionary) -> DotResult:
	var res := await backbone.post_integration(
		"player/introspect", {"access_token": token}
	)

	if not res.ok:
		if res.error != null and res.error.http_status == 401:
			return DotResult.fail(
				DotError.CODE_AUTH, "Your sign-in is no longer valid."
			)
		if res.error != null and res.error.http_status == 403:
			var code := _backbone_code(res)
			if code == "join_token_required":
				# An older client sent its account access token, which the backbone no
				# longer takes from a game server. Nothing to fix here but the client.
				return DotResult.fail(
					DotError.CODE_FORBIDDEN,
					"Your game needs an update to join this server.",
					"join_token_required"
				)
			if code == "wrong_audience":
				return DotResult.fail(
					DotError.CODE_FORBIDDEN,
					"That sign-in was issued for a different server.",
					"wrong_audience: check DotAuthConfig.join_audience"
				)
			return DotResult.fail(
				DotError.CODE_FORBIDDEN, "That sign-in cannot be used on this server."
			)
		# A backbone outage must not read as "you are not who you say you are".
		return res.wrap("Could not verify your sign-in right now.")

	var payload: Variant = res.value
	var user: Variant = (payload as Dictionary).get("user") if payload is Dictionary else null

	var identity_res := DotAuthIdentity.from_scoped_user(
		user if user is Dictionary else {}
	)
	if not identity_res.ok:
		return identity_res

	var identity: DotAuthIdentity = identity_res.value
	_apply_requested_name(identity, credential)

	DotLog.info(
		CHANNEL, "authenticated by scoped introspection", {"user": identity.label()}
	)

	return DotResult.success(identity)


## Forgets ticket ids that have expired anyway, bounded by [member DotAuthConfig.ticket_replay_memory_sec] (validated to exceed the ticket TTL).
func _sweep_spent() -> void:
	var now := int(Time.get_unix_time_from_system())
	if now - _last_sweep < 60:
		return
	_last_sweep = now

	var cutoff := now - config.ticket_replay_memory_sec
	var dead: Array = []

	for jti in _spent_tickets:
		if int(_spent_tickets[jti]) < cutoff:
			dead.append(jti)

	for jti in dead:
		_spent_tickets.erase(jti)



## The backbone audience this server announces in its handshake, or [code]""[/code] when not known yet.
##
## [member DotAuthConfig.join_audience] when pinned, else what `integration/v1/me` said; clients mint join tokens for it only if it is in their [member DotAuthConfig.first_party_audiences].
func join_audience() -> String:
	if config != null and config.join_audience != "":
		return config.join_audience
	return _discovered_audience


func _discover_join_audience() -> void:
	if backbone == null or not backbone.has_method("get_integration"):
		return
	var asked_of := backbone
	var res: DotResult = await asked_of.get_integration("me")
	# Any failure retries with backoff: a boot-time 429 or network blip that gave up
	# left the server announcing nothing, and every first-party client refused it.
	var tries := 0
	var delay := 0.5
	while not (res.ok and res.value is Dictionary):
		if tries == 4:
			DotLog.warn(CHANNEL, "could not learn this server's join audience yet; still trying", {
				"why": res.error.message if res.error != null else "unexpected reply",
			})
		tries += 1
		if tries > discover_audience_tries or not is_inside_tree():
			DotLog.warn(CHANNEL, "gave up learning this server's join audience", {
				"why": res.error.message if res.error != null else "unexpected reply",
				"fix": "pin join_audience in auth.yml",
			})
			return
		await get_tree().create_timer(delay).timeout
		delay = minf(delay * 2.0, 30.0)
		if backbone != asked_of or _discovered_audience != "":
			return
		res = await asked_of.get_integration("me")
	var target: Variant = (res.value as Dictionary).get("target")
	var audience := ""
	if target is Dictionary:
		audience = "%s:%s" % [
			str((target as Dictionary).get("kind", "")),
			str(int(_number_of(target, "id"))),
		]
	if not DotAuthConfig.is_audience(audience):
		DotLog.warn(CHANNEL, "integration/v1/me named no join audience", {"target": str(target)})
		return
	_discovered_audience = audience
	DotLog.info(CHANNEL, "join audience", {"audience": audience})
	_warn_about_hostname((target as Dictionary).get("hostname"))
	if config.adopt_ticket_trust and audience.begins_with("server:"):
		adopt_ticket_trust(audience.trim_prefix("server:"), {})


## Players sign in by the name they dial, so an unproven or copied name is the
## operator's to fix (by enrolling the server again).
func _warn_about_hostname(h: Variant) -> void:
	if not (h is Dictionary) or str(h.get("name", "")) == "":
		return
	var rivals := int(_number_of(h, "rivals"))
	if h.get("proven") != true or rivals > 0:
		DotLog.warn(CHANNEL, "this server's hostname is not proven to the site", {
			"name": str(h["name"]), "proven": h.get("proven") == true, "rivals": rivals,
			"fix": "enroll the server again from the host that answers at that name",
		})



## The backbone's `code` from a failed integration call's JSON body, or "".
static func _backbone_code(res: DotResult) -> String:
	if res.error == null or res.error.detail == "":
		return ""
	var parsed: Variant = JSON.parse_string(res.error.detail)
	if parsed is Dictionary:
		return str((parsed as Dictionary).get("code", ""))
	return ""


func strategy_name() -> String:
	if config == null:
		return "unconfigured"
	return DotAuthConfig.Strategy.keys()[config.strategy]


func describe() -> Dictionary:
	return {
		"strategy": strategy_name(),
		"server_id": config.server_id if config != null else "",
		"ticket_trust_ready": ticket_trust_ready(),
		"ticket_keys": config.ticket_public_keys.keys() if config != null else [],
		"guests_allowed": config.allow_guests if config != null else false,
		"local_profiles": (
			_local_profiles.describe() if _local_profiles != null else null
		),
		"authenticated": _stats["ok"],
		"guests": _stats["guests"],
		"rejected": _stats["rejected"],
		"spent_tickets": _spent_tickets.size(),
		"local_accounts": _accounts.size(),
		"session_reporter": (
			session_reporter.describe() if session_reporter != null else null
		),
	}


func describe_lines() -> PackedStringArray:
	var out := PackedStringArray()
	var d := describe()
	var keys := d.keys()
	keys.sort()
	for k in keys:
		out.append("%-18s %s" % [str(k), str(d[k])])
	return out
