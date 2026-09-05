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

const CHANNEL := "auth.server"

## Registry name dot-server looks for.
const SERVICE := &"dot_auth_server"

signal authenticated(identity: DotAuthIdentity)
signal rejected(reason: String, detail: String)

@export_group("Configuration")

@export var config: DotAuthConfig = null

@export var config_file: String = "user://dot_auth_server.json"

## Register in [DotRegistry] on ready.
##
## Turn off when running two servers in one process and register scoped names
## yourself — see [method DotRegistry.register_scoped].
@export var register_service: bool = true

var _http: DotHttp = null
var _limiter: DotRateLimiter = null

## Local accounts, for [constant DotAuthConfig.Strategy.LOCAL].
var _accounts: Dictionary = {}

## Spent ticket ids: jti -> expiry unix seconds.
var _spent_tickets: Dictionary = {}
var _last_sweep: int = 0

var _started: bool = false
var _stats := {"ok": 0, "rejected": 0, "guests": 0}

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

	if config.strategy == DotAuthConfig.Strategy.INTROSPECT:
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

	_started = true

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


# --- Authentication --------------------------------------------------------

## Resolves a client's credential to an identity.
##
## [param credential] carries whatever the client sent. Recognised keys:
## [code]ticket[/code], [code]access_token[/code], [code]username[/code] /
## [code]password[/code], [code]device_id[/code], [code]name[/code].
## [param rate_key] scopes the attempt limit — pass the peer's address so one
## client cannot exhaust another's budget.
func authenticate(
	credential: Dictionary,
	rate_key: Variant = null
) -> DotResult:
	if not _started:
		var s := start()
		if not s.ok:
			return s

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
		authenticated.emit(identity)
	else:
		_stats["rejected"] += 1
		rejected.emit(
			res.error.message, res.error.detail if res.error != null else ""
		)

	return res


## Verifies a signed connect ticket. Offline: no network call per join.
func _authenticate_ticket(credential: Dictionary) -> DotResult:
	var ticket := str(credential.get("ticket", ""))
	if ticket == "":
		return DotResult.fail(
			DotError.CODE_AUTH,
			"This server requires you to be signed in.",
			"no ticket presented"
		)

	var verified := DotAuthTicket.verify(
		ticket,
		config.ticket_public_key,
		config.server_id,
		config.ticket_leeway_sec
	)

	if not verified.ok:
		return verified

	var d: Dictionary = verified.value
	var jti := str(d["jti"])

	_sweep_spent()

	# Single use. A ticket captured in flight — on a shared network, in a proxy
	# log — must not be replayable while it is still inside its validity window.
	if jti != "" and _spent_tickets.has(jti):
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

	if jti != "":
		_spent_tickets[jti] = int(d["exp"])

	var identity: DotAuthIdentity = d["identity"]
	_apply_requested_name(identity, credential)

	DotLog.info(
		CHANNEL, "authenticated by ticket", {"user": identity.label()}
	)

	return DotResult.success(identity)


## Resolves a backbone access token by calling `/api/app/v1/me`.
##
## First-party servers only — see the warning [DotAuthConfig] logs. Costs a
## backbone round trip per join, and the operator ends up holding a live
## credential for the player's site account.
func _authenticate_introspect(credential: Dictionary) -> DotResult:
	var token := str(credential.get("access_token", ""))
	if token == "":
		return DotResult.fail(
			DotError.CODE_AUTH, "This server requires you to be signed in."
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

func strategy_name() -> String:
	if config == null:
		return "unconfigured"
	return DotAuthConfig.Strategy.keys()[config.strategy]


func describe() -> Dictionary:
	return {
		"strategy": strategy_name(),
		"server_id": config.server_id if config != null else "",
		"guests_allowed": config.allow_guests if config != null else false,
		"local_profiles": (
			_local_profiles.describe() if _local_profiles != null else null
		),
		"authenticated": _stats["ok"],
		"guests": _stats["guests"],
		"rejected": _stats["rejected"],
		"spent_tickets": _spent_tickets.size(),
		"local_accounts": _accounts.size(),
	}


func describe_lines() -> PackedStringArray:
	var out := PackedStringArray()
	var d := describe()
	var keys := d.keys()
	keys.sort()
	for k in keys:
		out.append("%-18s %s" % [str(k), str(d[k])])
	return out
