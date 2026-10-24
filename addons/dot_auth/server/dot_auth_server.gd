@tool
class_name DotAuthServer
extends Node

## Decides who a connecting client is. The game server's side of dot-auth.
##
## dot-server calls [method authenticate] with whatever credential a client
## presented and gets back a [DotAuthIdentity] or a refusal. Which strategy runs
## is [member DotAuthConfig.strategy], so the same server binary works as a
## public ticket-verifying server, a first-party introspecting one, a LAN server
## with a local account file, or an open anonymous one.
##
## [codeblock]
## var res := await auth.authenticate({
##     "ticket": ticket_from_client,
##     "name": requested_name,
##     "device_id": client_device_id,
## })
## if not res.ok:
##     session.reject(res.error.message)
##     return
## session.identity = res.value
## [/codeblock]
##
## Registers itself in [DotRegistry] as [code]dot_auth_server[/code] so
## dot-server can find it without a hard dependency in either direction.
##
## [b]It also builds the [DotAuthSessionReporter][/b] when the config names an issuer
## to report to ([member DotAuthConfig.session_report_url]), and points it at the
## [code]dot_server[/code] it finds in [DotRegistry]. See [member session_reporter] for
## why here and not in dot-game or dot-server.

const CHANNEL := "auth.server"

## Registry name dot-server looks for.
const SERVICE := &"dot_auth_server"

## What a join token starts with (website-city's `JOIN_TOKEN_PREFIX`).
const JOIN_TOKEN_PREFIX := "tmc_jt_"

signal authenticated(identity: DotAuthIdentity)
signal rejected(reason: String, detail: String)
## A ticket named a key id this server does not hold: the issuer rotated its key.
## The host refetches the issuer's keys (from its own backbone, never the client).
signal ticket_key_wanted(kid: String)

@export_group("Configuration")

@export var config: DotAuthConfig = null

@export var config_file: String = "user://dot_auth_server.json"

## Register in [DotRegistry] on ready.
##
## Turn off when running two servers in one process and register scoped names
## yourself — see [method DotRegistry.register_scoped].
@export var register_service: bool = true

## Build a [DotAuthSessionReporter] when [member DotAuthConfig.session_report_url] is
## set. Off for a host that builds and feeds its own.
@export var create_session_reporter: bool = true

## The reporter this server built, or null (no [code]session_report_url[/code], or
## [member create_session_reporter] off).
##
## [b]Why the auth server builds it.[/b] The reporter's lifetime is the server
## process's and its config is this node's: the issuer key, URL and server id are
## [DotAuthConfig] fields the host already hands here. The alternatives each get one of
## those wrong. dot-game's [code]DotGameModule[/code] is per GAME: a game change would
## unload it with every player still connected (so it could neither say goodbye nor
## stay silent honestly), and arena, g2gfast, hungario and playground are not on it.
## Games never own authentication; the host's [code]dot_auth_server[/code] is the same
## for every game it runs. dot-server never names dot-auth. So it lives beside the
## config it reads, and reaches dot-server by duck type through [DotRegistry], the way
## dot-server reaches this node.
var session_reporter: DotAuthSessionReporter = null

## The server's own backbone client, holding its integration credential.
##
## [b]Set it and INTROSPECT asks the backbone as THIS SERVER[/b] —
## `POST integration/v1/player/introspect` — and gets back the player's key in this
## server's scope rather than their account id. That key is the only identifier the
## backbone's avatar, profile and stats routes resolve for this server, and it is one
## other operators cannot correlate. Unset, INTROSPECT reads `/api/app/v1/me` as it
## always has, which answers with the account id and is for first-party servers only
## (and fails for a current client, whose join token `/me` refuses).
##
## Setting it also learns [method join_audience] from `integration/v1/me` when
## [member DotAuthConfig.join_audience] is not pinned.
var backbone: DotBackboneClient = null:
	set(value):
		backbone = value
		if value != null and config != null \
				and (config.join_audience == "" or config.adopt_ticket_trust):
			_discover_join_audience.call_deferred()

## The audience learnt from the backbone; see [method join_audience].
var _discovered_audience: String = ""

## How often adopted issuer keys are refetched, and the least time between two fetches
## an unknown `kid` may cause.
const TICKET_KEYS_REFRESH_SEC := 900.0
const TICKET_KEYS_MIN_GAP_MSEC := 60_000

## "config" when auth.yml named the server id (it then wins over the site's).
var _server_id_source := ""
var _keys_fetched_msec := -TICKET_KEYS_MIN_GAP_MSEC
var _keys_fetching := false
## The site's `refreshSec`, clamped, so a revocation reaches this server in time.
var _keys_refresh_sec := TICKET_KEYS_REFRESH_SEC

## How many failed `integration/v1/me` reads [method join_audience] discovery retries,
## with backoff capped at 30 s (the default is about an hour).
var discover_audience_tries: int = 130

## Refuse an INTROSPECT join while [member backbone] is unset, rather than falling back
## to `/me`.
##
## For a host that hands the client over after boot: the listener opens before the
## server's integration credential is loaded, and a player let in through `/me` in that
## window is keyed by their account id — a different identity from the one the same
## player gets a minute later, so their profile, avatar and bans would split in two.
var scoped_only: bool = false

var _http: DotHttp = null
var _limiter: DotRateLimiter = null

## Local accounts, for [constant DotAuthConfig.Strategy.LOCAL].
var _accounts: Dictionary = {}

## Spent ticket ids: jti -> expiry unix seconds.
var _spent_tickets: Dictionary = {}

## Key ids the issuer revoked: never trusted again, kept in the trust cache.
var _revoked_kids: Dictionary = {}

## Where [method authenticate] carries the host's connection nonce to the ticket check.
const CONNECTION_NONCE_KEY := "_connection_nonce"
var _last_sweep: int = 0

var _started: bool = false
var _stats := {"ok": 0, "rejected": 0, "guests": 0}

## Refusals in a row, with no real sign-in between, before the pattern is logged at WARN.
##
## One refused ticket is a player's problem -- an expired one, a copy from the wrong
## server -- and is INFO. Ten in a row with nobody getting in is almost always this
## server's: a `ticket_public_key` from another deployment, a `server_id` that does not
## match what the backbone issues for, a clock that has drifted. Nothing else in the
## process can tell those apart, and every one of them reads, from the player's side, as
## "the server will not let me in".
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

## The provider built from [member DotAuthConfig.allow_local_profiles], if any.
##
## Held so [method describe] can report it and a game can reach the store — an
## operator's "remove that player's profile" console command needs it, and going
## back through [member _providers] to find it by name would be worse.
var _local_profiles: DotLocalProfileProvider = null


## Registers a custom authentication provider.
##
## Validated at registration so a provider missing an API key fails at boot rather
## than on the first player's login.
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

	# Local profiles are a PROVIDER, not a strategy, so they compose with
	# whatever the server already does — a server taking backbone tickets can
	# also let a visitor with no site account make one that lives here. Built
	# here so `allow_local_profiles` is a switch that does something on its own;
	# a game wanting to own the store still registers its own provider and
	# leaves this off.
	if config.allow_local_profiles and _local_profiles == null:
		var store := DotLocalProfiles.at(config.local_profiles_path)
		store.max_profiles = config.max_local_profiles

		_local_profiles = DotLocalProfileProvider.new()
		_local_profiles.profiles = store
		_local_profiles.allow_creation = config.local_profile_signup

		var registered := add_provider(_local_profiles)
		if not registered.ok:
			return registered.wrap("Could not enable local profiles.")

	_limiter = DotRateLimiter.new(
		float(config.auth_attempts_per_minute) / 60.0,
		float(config.auth_attempts_per_minute)
	)

	if register_service:
		DotRegistry.register(SERVICE, self)

	_build_session_reporter()

	_started = true

	if config.adopt_ticket_trust:
		_load_ticket_trust_cache()
		ticket_key_wanted.connect(func(_kid: String) -> void: refresh_ticket_keys())
		refresh_ticket_keys.call_deferred()
		var t := Timer.new()
		t.name = "TicketKeysRefresh"
		t.wait_time = _keys_refresh_sec
		t.autostart = true
		t.timeout.connect(func() -> void: refresh_ticket_keys(true))
		add_child(t)

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


## The local-profile provider this server built, or null.
##
## The way a game reaches the store — an operator console command that removes an
## abusive player's profile needs it, and hunting through the provider list by name
## is the kind of thing every caller would do slightly differently.
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


# --- Authentication --------------------------------------------------------

## Resolves a client's credential to an identity.
##
## [param credential] carries whatever the client sent. Recognised keys:
## [code]ticket[/code], [code]access_token[/code], [code]username[/code] /
## [code]password[/code], [code]device_id[/code], [code]name[/code].
## [param rate_key] scopes the attempt limit — pass the peer's address so one
## client cannot exhaust another's budget. [param connection_nonce] is the nonce the
## host put in THIS connection's challenge; a ticket bound to another is refused.
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
		# Rate limiting runs before providers, so a custom provider that talks to an
		# external service cannot be used to make this server hammer it.
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

	# Custom providers first. One that claims a credential owns the outcome — a
	# provider that recognised a platform ticket and then rejected it has decided, and
	# falling through to the built-in strategy would let a refused login in by
	# another door.
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


## Applies the guest fallback and records the outcome.
##
## Shared by the provider path and the built-in strategies, so both get the same
## fallback rules, the same counters and the same signals — a provider whose result
## skipped this would be authenticated differently from everyone else.
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
## [b]The level is chosen by who is expected to act[/b], which is the family's rule and the
## reason this is not one line at one level:
##
## - A refused credential -- wrong password, expired or forged ticket, a ticket for another
##   server -- is the player's, and INFO: an admin wants failed sign-ins kept (they are what
##   a guessing attack looks like) but nobody has to do anything about one. A long run of
##   them with no success between is escalated once to WARN; see [constant REFUSAL_RUN_WARN].
## - Rate limiting is the limiter doing its job, at DEBUG. The attempts that tripped it were
##   each logged at INFO already.
## - A verifier that cannot be reached is WARN, once per outage, in [method _finish]; each
##   refusal it causes is DEBUG here.
## - Anything that is this server's own fault -- an unknown strategy, a provider that failed
##   internally, a file it could not read -- is ERROR.
##
## Never the credential itself: no password, no token, no ticket. The username is logged
## because it is what a guessing attack is aimed at, and an operator needs it to see one.
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

	DotLog.info(
		CHANNEL, "authenticated by ticket", {"user": identity.label()}
	)

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


## True when tickets can be verified: a server id and at least one issuer key.
func ticket_trust_ready() -> bool:
	if config == null or config.server_id == "":
		return false
	return config.ticket_public_key.strip_edges() != "" \
		or not config.ticket_public_keys.is_empty()


## Adopts the server id and issuer keys ([code]{kid: pem}[/code]) the host fetched from
## its backbone. An explicit [member DotAuthConfig.server_id] or
## [member DotAuthConfig.ticket_public_key] wins; only public-key PEMs are taken.
func adopt_ticket_trust(server_id: String, keys: Dictionary) -> DotResult:
	if config == null:
		return DotResult.fail(DotError.CODE_STATE, "No configuration.")
	var ring := {}
	for kid in keys:
		var pem := str(keys[kid])
		if str(kid) == "" or not pem.contains("BEGIN PUBLIC KEY") or pem.contains("PRIVATE"):
			return DotResult.fail(
				DotError.CODE_INVALID, "Issuer keys must be public-key PEMs with a key id."
			)
		if not _revoked_kids.has(str(kid)):
			ring[str(kid)] = pem
	var sid := server_id.strip_edges()
	if sid != "" and not sid.is_valid_int():
		return DotResult.fail(DotError.CODE_INVALID, "A server id is a number.", sid)
	var pinned := _server_id_source == "config" or (not _started and config.server_id != "")
	if sid != "" and sid != config.server_id:
		if pinned:
			DotLog.warn(CHANNEL, "auth.yml's server_id differs from the site's; keeping auth.yml's", {
				"configured": config.server_id, "site": sid,
			})
		else:
			config.server_id = sid
	if not ring.is_empty():
		config.ticket_public_keys = ring
	for kid in _revoked_kids:
		config.ticket_public_keys.erase(kid)
	_save_ticket_trust_cache()
	DotLog.info(CHANNEL, "ticket trust adopted", {
		"server_id": config.server_id,
		"keys": ",".join(PackedStringArray(config.ticket_public_keys.keys())),
		"explicit_key": config.ticket_public_key.strip_edges() != "",
	})
	return DotResult.success(ticket_trust_ready())


## Fetches the issuer's public keys from this server's own backbone
## (`/api/app/v1/auth/ticket-keys`), never from a client or a dialled server. HTTPS with
## a verified certificate unless the backbone is on loopback. At most once a minute
## unless [param force].
func refresh_ticket_keys(force: bool = false) -> DotResult:
	if config == null or _http == null:
		return DotResult.fail(DotError.CODE_STATE, "Not fetching issuer keys now.")
	if _keys_fetching:
		while _keys_fetching and is_inside_tree():
			await get_tree().process_frame
		return DotResult.success(ticket_trust_ready()) if not config.ticket_public_keys.is_empty() \
			else DotResult.fail(DotError.CODE_STATE, "The issuer's keys could not be fetched.")
	if not force and Time.get_ticks_msec() - _keys_fetched_msec < TICKET_KEYS_MIN_GAP_MSEC:
		return DotResult.fail(DotError.CODE_RATE_LIMITED, "Issuer keys were fetched recently.")
	var url := config.app_endpoint("auth/ticket-keys")
	if not _trusted_key_url(url):
		DotLog.error(CHANNEL, "refusing to fetch issuer keys over plain HTTP", {
			"url": url, "fix": "an https backbone_url, or issuer_public_key_file",
		})
		return DotResult.fail(DotError.CODE_FORBIDDEN, "Issuer keys need HTTPS.", url)
	_keys_fetching = true
	_keys_fetched_msec = Time.get_ticks_msec()
	var res: DotResult = await _http.get_json(url)
	_keys_fetching = false
	if not res.ok:
		DotLog.warn(CHANNEL, "could not fetch the issuer's keys", {
			"url": url, "why": res.error.message, "have": config.ticket_public_keys.size(),
		})
		return res
	revoke_ticket_keys(parse_ticket_revoked(res.value))
	_apply_keys_refresh(parse_ticket_refresh_sec(res.value))
	var ring := parse_ticket_keys(res.value)
	if ring.is_empty():
		DotLog.warn(CHANNEL, "the backbone publishes no ticket keys yet", {"url": url})
		return DotResult.fail(DotError.CODE_STATE, "The site publishes no ticket keys.")
	return adopt_ticket_trust("", ring)


## [code]{kid: pem}[/code] from a `ticket-keys` reply (enveloped or not), RS256 only.
static func parse_ticket_keys(reply: Variant) -> Dictionary:
	var ring := {}
	if not (reply is Dictionary):
		return ring
	var body: Dictionary = reply
	if body.get("data") is Dictionary:
		body = body["data"]
	var keys: Variant = body.get("keys")
	if not (keys is Array):
		return ring
	for k in keys:
		if k is Dictionary and str(k.get("alg", "")) == "RS256" and str(k.get("kid", "")) != "" \
				and str(k.get("pem", "")).contains("BEGIN PUBLIC KEY") \
				and not str(k.get("pem", "")).contains("PRIVATE"):
			ring[str(k["kid"])] = str(k["pem"])
	return ring


## Key ids a `ticket-keys` reply lists under `revoked`.
static func parse_ticket_revoked(reply: Variant) -> PackedStringArray:
	var out := PackedStringArray()
	var body: Variant = reply
	if body is Dictionary and (body as Dictionary).get("data") is Dictionary:
		body = body["data"]
	if body is Dictionary and (body as Dictionary).get("revoked") is Array:
		for kid in body["revoked"]:
			if kid is String and kid != "":
				out.append(kid)
	return out


## The `refreshSec` a `ticket-keys` reply asks for, or 0.
static func parse_ticket_refresh_sec(reply: Variant) -> float:
	var body: Variant = reply
	if body is Dictionary and (body as Dictionary).get("data") is Dictionary:
		body = body["data"]
	if body is Dictionary:
		return _number_of(body, "refreshSec")
	return 0.0


## Never trusts [param kids] again, now or after a restart (the trust cache keeps them).
func revoke_ticket_keys(kids: PackedStringArray) -> void:
	var added := PackedStringArray()
	for kid in kids:
		if not _revoked_kids.has(kid):
			_revoked_kids[kid] = true
			added.append(kid)
		config.ticket_public_keys.erase(kid)
	if added.is_empty():
		return
	DotLog.warn(CHANNEL, "issuer keys revoked", {"kids": ",".join(added)})
	_save_ticket_trust_cache()


func _apply_keys_refresh(sec: float) -> void:
	if sec <= 0.0:
		return
	_keys_refresh_sec = clampf(sec, 300.0, 6 * 3600.0)
	var t := get_node_or_null("TicketKeysRefresh") as Timer
	if t != null and not is_equal_approx(t.wait_time, _keys_refresh_sec):
		t.wait_time = _keys_refresh_sec


static func _trusted_key_url(url: String) -> bool:
	if url.begins_with("https://"):
		return true
	for local in ["http://127.0.0.1", "http://localhost", "http://[::1]"]:
		if url.begins_with(local + ":") or url.begins_with(local + "/"):
			return true
	return false


func _load_ticket_trust_cache() -> void:
	if config.ticket_trust_cache == "" or not FileAccess.file_exists(config.ticket_trust_cache):
		return
	var parsed: Variant = JSON.parse_string(FileAccess.get_file_as_string(config.ticket_trust_cache))
	if not (parsed is Dictionary) or str(parsed.get("backbone_url", "")) != config.backbone_url:
		return
	if parsed.get("revoked") is Array:
		for kid in parsed["revoked"]:
			if kid is String and kid != "":
				_revoked_kids[kid] = true
	var keys: Variant = parsed.get("keys")
	var adopted := adopt_ticket_trust(
		str(parsed.get("server_id", "")), keys if keys is Dictionary else {}
	)
	if not adopted.ok:
		DotLog.warn(CHANNEL, "ignoring a bad ticket trust cache", {
			"path": config.ticket_trust_cache, "why": adopted.error.message,
		})


func _save_ticket_trust_cache() -> void:
	if config.ticket_trust_cache == "" or not _started:
		return
	var f := FileAccess.open(config.ticket_trust_cache, FileAccess.WRITE)
	if f == null:
		DotLog.warn(CHANNEL, "could not write the ticket trust cache", {
			"path": config.ticket_trust_cache, "err": error_string(FileAccess.get_open_error()),
		})
		return
	f.store_string(JSON.stringify({
		"backbone_url": config.backbone_url,
		"server_id": config.server_id if _server_id_source != "config" else "",
		"keys": config.ticket_public_keys,
		"revoked": _revoked_kids.keys(),
	}, "\t"))
	f.close()
	DotWeb.sync_filesystem()


## The PEM to verify [param ticket] with: the explicit key, else the ring entry its
## `kid` names. An unknown kid asks the host for a refetch and refuses this join.
func _ticket_key_for(ticket: String) -> DotResult:
	if config.ticket_public_key.strip_edges() != "":
		return DotResult.success(config.ticket_public_key)
	var peeked := DotJwt.peek(ticket)
	if not peeked.ok:
		return DotResult.fail(DotError.CODE_AUTH, "This connect ticket is not valid.", "malformed")
	var kid := str((peeked.value["header"] as Dictionary).get("kid", ""))
	if _revoked_kids.has(kid):
		return DotResult.fail(
			DotError.CODE_FORBIDDEN, "This connect ticket is not valid.", "revoked key id"
		)
	if kid == "" and config.ticket_public_keys.size() == 1:
		return DotResult.success(config.ticket_public_keys.values()[0])
	if config.ticket_public_keys.has(kid):
		return DotResult.success(config.ticket_public_keys[kid])
	ticket_key_wanted.emit(kid)
	return DotResult.fail(
		DotError.CODE_STATE,
		"This server is updating its sign-in keys. Try again in a moment.",
		"unknown ticket key id %s" % kid.substr(0, 24)
	)


## Resolves what an INTROSPECT client sent.
##
## With a [member backbone]: a single-use join token (or a legacy web build's GAME
## token) through `player/introspect`, which yields a scoped key and leaves the
## operator nothing to replay. Without one: `/api/app/v1/me`, first-party servers
## only. A client that will not send a token here (this server is not on its
## first-party list) sends a connect ticket instead, which is verified offline when
## an issuer key is set or adopted.
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


## INTROSPECT through the server's integration credential. See [member backbone].
##
## The identity it builds carries no account id at all: [member DotAuthIdentity.uid]
## is `tmc:<key>` and the key is in the `scoped_key` claim, which is what dot-user
## files the profile under and what the backbone's avatar route resolves.
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


## Checks a username and password against the local accounts file.
func _authenticate_local(credential: Dictionary) -> DotResult:
	var username := str(credential.get("username", "")).to_lower()
	var password := str(credential.get("password", ""))

	if username == "" or password == "":
		return DotResult.fail(
			DotError.CODE_AUTH, "A username and password are required."
		)

	if not _accounts.has(username):
		# The same message and the same work as a wrong password, so the response
		# does not reveal which usernames exist. The hash runs either way.
		DotHash.sha256_text(password)
		return DotResult.fail(
			DotError.CODE_AUTH, "Incorrect username or password."
		)

	var account: Dictionary = _accounts[username]
	var salt := str(account.get("salt", ""))
	var expected := str(account.get("hash", ""))
	var actual := hash_password(password, salt)

	if not DotHash.constant_time_equal_hex(actual, expected):
		return DotResult.fail(
			DotError.CODE_AUTH, "Incorrect username or password."
		)

	var identity := DotAuthIdentity.new()
	identity.provider = "local"
	identity.provider_id = username
	identity.uid = "local:%s" % username
	identity.username = username
	identity.display_name = str(account.get("display_name", username))
	identity.role = str(account.get("role", ""))
	identity.authenticated_at = int(Time.get_unix_time_from_system())

	if account.get("claims") is Dictionary:
		identity.claims = account["claims"]

	_apply_requested_name(identity, credential)

	DotLog.info(
		CHANNEL, "authenticated locally", {"user": identity.label()}
	)

	return DotResult.success(identity)


func _make_guest(credential: Dictionary) -> DotResult:
	var device_id := str(credential.get("device_id", ""))
	if device_id == "":
		# Random rather than derived: without a device id there is nothing stable
		# to derive from, and a shared constant would make every guest the same
		# person as far as mutes and kicks are concerned.
		device_id = DotHash.random_hex(8)

	var name := str(credential.get("name", ""))
	var identity := DotAuthIdentity.guest(
		DotHash.sha256_text(device_id).substr(0, 16), name
	)

	return DotResult.success(identity)


## Applies a client-requested display name, when the identity has none of its own.
##
## A guest may name themselves; an authenticated player may not. Letting a signed-in
## account display an arbitrary name is how impersonation happens, and the account
## name is the one thing a server can vouch for.
func _apply_requested_name(
	identity: DotAuthIdentity,
	credential: Dictionary
) -> void:
	var requested := str(credential.get("name", "")).strip_edges()
	if requested == "":
		return

	if not identity.is_guest:
		return

	identity.display_name = requested.substr(0, 64)


# --- Local accounts --------------------------------------------------------

## Salted SHA-256 of a password.
##
## [b]Not adequate for a public account system.[/b] A password store deserves
## argon2 or bcrypt, and Godot ships neither. This exists for LAN servers and
## development, where the alternative is a plaintext password in a JSON file.
## Anything with real users belongs on the backbone, which does this properly.
static func hash_password(password: String, salt: String) -> String:
	var out := salt + password
	# A few thousand rounds is not key stretching in any serious sense, but it
	# does make an offline attack against this file cost something.
	for _i in range(4096):
		out = DotHash.sha256_text(out)
	return out


func _load_accounts() -> DotResult:
	_accounts.clear()

	if not FileAccess.file_exists(config.local_accounts_path):
		DotLog.info(
			CHANNEL,
			"no local accounts file; nobody can sign in with LOCAL",
			{"path": config.local_accounts_path}
		)
		return DotResult.success(0)

	var read := DotPaths.read_json(config.local_accounts_path)
	if not read.ok:
		return read.wrap("Could not read the local accounts file.")

	var data: Variant = read.value
	if not (data is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE,
			"The accounts file must be a JSON object of username -> account."
		)

	for username in (data as Dictionary):
		var entry: Variant = (data as Dictionary)[username]
		if entry is Dictionary:
			_accounts[str(username).to_lower()] = entry

	DotLog.info(
		CHANNEL, "local accounts loaded", {"count": _accounts.size()}
	)

	return DotResult.success(_accounts.size())


## Adds or replaces a local account and writes the file.
##
## For an admin console command. Never expose it to unauthenticated clients.
func upsert_local_account(
	username: String,
	password: String,
	display_name: String = "",
	role: String = ""
) -> DotResult:
	var salt := DotHash.random_hex(16)

	_accounts[username.to_lower()] = {
		"salt": salt,
		"hash": hash_password(password, salt),
		"display_name": display_name if display_name != "" else username,
		"role": role,
	}

	var written := DotPaths.write_json(
		config.local_accounts_path, _accounts
	)
	if not written.ok:
		return written

	DotLog.info(CHANNEL, "local account saved", {"user": username})
	return DotResult.success(username)


func remove_local_account(username: String) -> DotResult:
	if not _accounts.erase(username.to_lower()):
		return DotResult.fail(
			DotError.CODE_INVALID, "No such account.", username
		)
	return DotPaths.write_json(config.local_accounts_path, _accounts)


# --- Replay memory ---------------------------------------------------------

## Forgets ticket ids that have expired anyway.
##
## Bounded by [member DotAuthConfig.ticket_replay_memory_sec], which config
## validation requires to exceed the ticket TTL — otherwise a ticket could
## outlive the record of having been spent.
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


# --- Reporting -------------------------------------------------------------

## The backbone audience this server announces in its handshake, `server:<id>` or
## `app:<id>`, or [code]""[/code] when it is not known yet.
##
## [member DotAuthConfig.join_audience] when pinned, else what `integration/v1/me`
## said about [member backbone]'s credential. A client mints its join token for this
## value and only for a server it lists as first-party; see
## [member DotAuthConfig.first_party_audiences].
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


static func _number_of(d: Dictionary, key: String) -> float:
	var v: Variant = d.get(key, 0)
	return float(v) if (v is int or v is float) else 0.0


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
