@tool
class_name DotBackboneClient
extends Node

## Reports a dedicated server's own state to its listing on the backbone.
##
## Speaks the backbone's integration API (`/api/integration/v1/*` and
## `/api/content/server/integration/*`) with a server-scoped credential. That
## credential is bound to one server row, so nothing sent here names a server —
## the token decides which listing this is about, which is what stops a leaked
## token being pointed at somebody else's.
##
## What it is for: a server that reports its own player count, map and roster is
## strictly better data than a listing scraped by a query packet — no packet loss,
## no rate-limited A2S, no player list truncated at 255.
##
## [b]Replay protection is mandatory and this class handles it.[/b] Every request
## carries a Unix-seconds `ts` and a random `nonce`; the backbone refuses anything
## outside its skew window and remembers nonces inside it. A reporter that omits
## them still gets the timestamp window, but sending both is free and closes the
## gap.

const CHANNEL := "backbone"

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

## Supplies the current server state at report time.
##
## Set by dot-server. Must return a dictionary shaped like
## [method report_stats]'s argument. A callable rather than pushed state so the
## numbers are sampled when they are sent, not when they last changed.
var stats_provider: Callable = Callable()

## Supplies the current roster. Same contract as [member stats_provider].
var roster_provider: Callable = Callable()

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
	# A final "offline" so the listing does not show a dead server as full for
	# however long the backbone's staleness window is.
	if _started and _http != null:
		pass


## Reports offline and waits for it. Call before shutting down.
func report_offline() -> DotResult:
	if not _started:
		return DotResult.success(false)
	return await report_stats({"online": false, "curUsers": 0})


# --- Reporting -------------------------------------------------------------

## Sends live server state.
##
## A PATCH in behaviour: absent fields are left alone, so a tick that only changes
## the player count sends two numbers rather than the whole record. Recognised
## keys mirror the backbone's `IngestServerStatsInput` — [code]online[/code],
## [code]curUsers[/code], [code]maxUsers[/code], [code]bots[/code],
## [code]map[/code], [code]gameMode[/code], [code]version[/code],
## [code]password[/code], [code]secure[/code], [code]dedicated[/code],
## [code]os[/code], [code]vars[/code].
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
## [b]Absolute, not incremental.[/b] The backbone reconciles from the full list
## every time, because an incremental protocol needs guaranteed delivery of every
## join and leave, and one dropped report leaves somebody "online" forever.
##
## An empty list therefore means "nobody is connected" and closes every open
## session. A server that does not know its roster must not call this at all.
##
## Needs the `SERVER_USERS` scope, which the backbone keeps separate from
## `SERVER_STATS` on purpose: a player list is personal data about third parties.
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


## Resolves an in-game name to a site member, within a party.
##
## Deliberately narrow on the backbone's side: it answers only within a party the
## integration is entitled to, only for members who joined that party themselves,
## and returns an id and a display name. It is not a general name lookup and must
## not be treated as one.
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


## POSTs to an arbitrary integration endpoint, with stamping and headers applied.
##
## For the party endpoints a game mode might use (`party/create`, `party/state`,
## `party/session`, `party/end`) without this class having to model each one.
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


## GETs an arbitrary integration endpoint, with the same headers and limits.
##
## The read half of [method post_integration]: a leaderboard page, a player's
## statistics. [param query] is encoded and appended; [code]ts[/code] is added
## to it and the nonce rides in the header, because a GET has no body to carry
## either and the backbone reads both from where a GET can put them.
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


# --- Plumbing --------------------------------------------------------------

## Adds the replay-protection fields the backbone checks.
##
## [code]ts[/code] is Unix [b]seconds[/b]. Milliseconds are refused loudly by the
## backbone's window check, which is a mistake worth making impossible here rather
## than at four call sites.
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
