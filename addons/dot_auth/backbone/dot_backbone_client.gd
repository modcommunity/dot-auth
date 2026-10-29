@tool
class_name DotBackboneClient
extends Node

## Reports a dedicated server's own state to its listing on the backbone, with a server-scoped credential.
##
## The credential is bound to one server row, so nothing sent names a server and a leaked token cannot be pointed at another listing. Every request carries a Unix-seconds `ts` and a random `nonce` for replay protection.

const CHANNEL := "backbone"

## Registry name, so consumers (chat relay, stats reporter, leaderboard) find the client without the host wiring each one.
const SERVICE := &"dot_backbone_client"

## Scopes the backbone requires. Documented here so a misconfigured integration
## produces a useful log line rather than an opaque 403.
const SCOPE_STATS := "SERVER_STATS"
const SCOPE_USERS := "SERVER_USERS"

## The backbone caps a roster report at this many players.
const MAX_REPORTED_PLAYERS := 512

## Emitted after each report, successful or not.
signal reported(kind: String, result: DotResult)

@export var config: DotAuthConfig = null

## Report automatically on a timer once [method start] has run.
@export var auto_report: bool = true

var _http: DotHttp = null
var _timer: Timer = null
var _limiter: DotRateLimiter = null
var _started: bool = false

## Supplies the current server state at report time (set by dot-server), sampled when sent, not when it last changed.
var stats_provider: Callable = Callable()

## Supplies the current roster. Same contract as [member stats_provider].
var roster_provider: Callable = Callable()

## Registry name to publish under, or empty not to publish.
@export var register_as: StringName = SERVICE

var _last_error: String = ""
var _report_count: int = 0


func start() -> DotResult:
	if _started:
		return DotResult.success(self)

	if config == null:
		return DotResult.fail(
			DotError.CODE_STATE, "DotBackboneClient has no config."
		)

	if config.integration_token.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_STATE,
			"No integration token; server reporting is off.",
			"create a server-scoped integration on the site and set "
			+ "DotAuthConfig.integration_token"
		)

	_http = DotHttp.new()
	_http.name = "BackboneHttp"
	_http.timeout_sec = 15.0
	_http.max_retries = 2
	add_child(_http)

	# A local ceiling so a bug — a retry loop, a stuck timer — cannot get the
	# server's credential rate-limited or revoked by the backbone.
	_limiter = DotRateLimiter.new(
		float(config.backbone_requests_per_minute) / 60.0,
		float(config.backbone_requests_per_minute)
	)

	if auto_report and config.report_interval_sec > 0.0:
		_timer = Timer.new()
		_timer.wait_time = config.report_interval_sec
		_timer.autostart = true
		_timer.timeout.connect(_on_report_due)
		add_child(_timer)

	_started = true

	if register_as != &"":
		DotRegistry.register(register_as, self)

	DotLog.info(
		CHANNEL,
		"backbone reporting ready",
		{
			"url": config.backbone_url,
			"interval": config.report_interval_sec,
			"roster": config.report_roster,
		}
	)

	return DotResult.success(self)


func _exit_tree() -> void:
	if register_as != &"" and DotRegistry.get_service(register_as) == self:
		DotRegistry.unregister(register_as)

	# A final "offline" so the listing does not show a dead server as full for
	# however long the backbone's staleness window is.
	if _started and _http != null:
		pass


## Reports offline and waits for it. Call before shutting down.
func report_offline() -> DotResult:
	if not _started:
		return DotResult.success(false)
	return await report_stats({"online": false, "curUsers": 0})



## Sends live server state as a PATCH: absent fields are left alone. Keys mirror the backbone's `IngestServerStatsInput`.
func report_stats(stats: Dictionary) -> DotResult:
	if not _started:
		return DotResult.fail(DotError.CODE_STATE, "Not started.")

	if not _limiter.allow("backbone"):
		return DotResult.fail(
			DotError.CODE_RATE_LIMITED,
			"Local backbone request limit reached."
		)

	var body := stats.duplicate()

	# An empty string is refused by the backbone rather than treated as "clear",
	# so a reporter that does not know its map must omit the field entirely.
	if body.has("map") and str(body["map"]).strip_edges() == "":
		body.erase("map")

	# Clamp rather than let the backbone refuse the whole report: a bad number
	# from a game mode should not stop the player count being updated.
	for key in ["curUsers", "maxUsers", "bots"]:
		if body.has(key):
			body[key] = clampi(int(body[key]), 0, 10_000)

	if not body.has("os"):
		body["os"] = _os_tag()
	if not body.has("dedicated"):
		body["dedicated"] = DotPlatform.is_headless()

	_stamp(body)

	var res := await _http.post_json(
		config.server_stats_endpoint(), body, _headers()
	)

	_note(res, "stats")
	reported.emit("stats", res)
	return res


## Sends the whole current roster.
##
## Absolute, not incremental: one dropped incremental report would leave somebody "online" forever. An empty list closes every open session, so a server that does not know its roster must not call this. Needs `SERVER_USERS`, kept apart from `SERVER_STATS` because a player list is personal data.
func report_users(
	users: Array,
	set_count: bool = true
) -> DotResult:
	if not _started:
		return DotResult.fail(DotError.CODE_STATE, "Not started.")

	if not _limiter.allow("backbone"):
		return DotResult.fail(
			DotError.CODE_RATE_LIMITED,
			"Local backbone request limit reached."
		)

	var cleaned: Array = []

	for entry in users:
		if not (entry is Dictionary):
			continue

		var u := entry as Dictionary
		var name := str(u.get("name", "")).strip_edges()
		if name == "":
			continue

		var out := {"name": name.substr(0, 128)}

		if u.has("steamId") and str(u["steamId"]) != "":
			out["steamId"] = str(u["steamId"]).substr(0, 32)
		if u.has("score"):
			out["score"] = clampi(int(u["score"]), -1_000_000, 1_000_000)
		if u.has("seconds"):
			out["seconds"] = clampi(int(u["seconds"]), 0, 31_536_000)

		cleaned.append(out)

		if cleaned.size() >= MAX_REPORTED_PLAYERS:
			break

	# Truncating silently would make setCount a lie, so it is turned off when the
	# list did not fit — exactly the case the backbone's own docs warn about.
	var truncated := users.size() > cleaned.size()
	if truncated:
		DotLog.warn(
			CHANNEL,
			"roster truncated for reporting",
			{"had": users.size(), "sent": cleaned.size()}
		)

	var body := {
		"users": cleaned,
		"setCount": set_count and not truncated,
	}

	_stamp(body)

	var res := await _http.post_json(
		config.server_users_endpoint(), body, _headers()
	)

	_note(res, "users")
	reported.emit("users", res)
	return res


## Resolves an in-game name to a site member, within a party only; it is not a general name lookup.
func lookup_user(
	party_id: String,
	name: String,
	steam_id: String = ""
) -> DotResult:
	if not _started:
		return DotResult.fail(DotError.CODE_STATE, "Not started.")

	var query := "partyId=%s&name=%s" % [
		party_id.uri_encode(), name.uri_encode()
	]
	if steam_id != "":
		query += "&steamId=%s" % steam_id.uri_encode()

	return await _http.get_json(
		config.integration_endpoint("user/lookup") + "?" + query,
		_headers()
	)


## POSTs to an arbitrary integration endpoint, with stamping and headers applied (the party endpoints, say).
func post_integration(path: String, body: Dictionary) -> DotResult:
	if not _started:
		return DotResult.fail(DotError.CODE_STATE, "Not started.")

	if not _limiter.allow("backbone"):
		return DotResult.fail(
			DotError.CODE_RATE_LIMITED, "Local backbone request limit reached."
		)

	var payload := body.duplicate()
	_stamp(payload)

	return await _http.post_json(
		config.integration_endpoint(path), payload, _headers()
	)


## GETs an arbitrary integration endpoint; [code]ts[/code] goes in [param query] and the nonce in the header, as a GET has no body.
func get_integration(path: String, query: Dictionary = {}) -> DotResult:
	if not _started:
		return DotResult.fail(DotError.CODE_STATE, "Not started.")

	if not _limiter.allow("backbone"):
		return DotResult.fail(
			DotError.CODE_RATE_LIMITED, "Local backbone request limit reached."
		)

	var params := query.duplicate()
	params["ts"] = int(Time.get_unix_time_from_system())

	return await _http.get_json(
		config.integration_endpoint(path) + "?" + encode_query(params),
		_headers()
	)


## `a=1&b=two`, every key and value URI-encoded.
static func encode_query(params: Dictionary) -> String:
	var parts := PackedStringArray()
	for key in params:
		parts.append("%s=%s" % [str(key).uri_encode(), str(params[key]).uri_encode()])
	return "&".join(parts)



## Adds the replay-protection fields; [code]ts[/code] is Unix [b]seconds[/b], and the backbone refuses milliseconds loudly.
func _stamp(body: Dictionary) -> void:
	body["ts"] = int(Time.get_unix_time_from_system())
	body["nonce"] = DotHash.random_hex(16)


func _headers() -> Dictionary:
	return {
		"Authorization": "Bearer %s" % config.integration_token,
		# The backbone also reads the nonce from a header, which covers GET
		# requests that have no body to put it in.
		"x-tmc-nonce": DotHash.random_hex(16),
	}


## The platform tag the backbone's `ServerOsVals` enum expects.
func _os_tag() -> String:
	match DotPlatform.kind():
		DotPlatform.Kind.WINDOWS: return "WINDOWS"
		DotPlatform.Kind.LINUX: return "LINUX"
		DotPlatform.Kind.MACOS: return "MACOS"
		_: return "OTHER"


func _on_report_due() -> void:
	if stats_provider.is_valid():
		var stats: Variant = stats_provider.call()
		if stats is Dictionary:
			await report_stats(stats as Dictionary)

	if config.report_roster and roster_provider.is_valid():
		var roster: Variant = roster_provider.call()
		if roster is Array:
			await report_users(roster as Array)


func _note(res: DotResult, kind: String) -> void:
	if res.ok:
		_report_count += 1
		_last_error = ""
		DotLog.debug(CHANNEL, "reported", {"kind": kind})
		return

	_last_error = res.error.message

	# A 403 means the integration lacks the scope, and that will not fix itself —
	# say which scope so the operator can tick the box.
	if res.error.http_status == 403:
		DotLog.warn(
			CHANNEL,
			"the backbone refused a report; the integration may lack a scope",
			{
				"kind": kind,
				"need": SCOPE_STATS if kind == "stats" else SCOPE_USERS,
			}
		)
	else:
		DotLog.warn(
			CHANNEL,
			"report failed",
			{"kind": kind, "why": res.error.message}
		)


func describe() -> Dictionary:
	return {
		"started": _started,
		"url": config.backbone_url if config != null else "",
		"reports": _report_count,
		"interval": config.report_interval_sec if config != null else 0.0,
		"roster": config.report_roster if config != null else false,
		"last_error": _last_error,
	}
