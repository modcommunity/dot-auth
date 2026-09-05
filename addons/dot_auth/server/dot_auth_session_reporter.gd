@tool
class_name DotAuthSessionReporter
extends Node

## Tells the issuer who is playing on this server.
##
## The server half of [member DotAuthConfig.single_session]. The issuer learns
## that a player is [i]going[/i] somewhere when it mints their ticket; it learns
## they [i]arrived[/i], and later that they [i]left[/i], from this. A server
## that does not run one still works with the rule on — its players are held
## for the lease after their ticket and then let go — but it cannot free a
## player the moment they leave, and it cannot hold one for a whole match.
##
## Every report is the whole roster, exactly as [DotBackboneClient] reports to
## the site: absent means gone. So the host supplies a callable returning the
## current uids rather than pushing joins and leaves, and a report lost in
## transit costs one interval, not a stuck record.
##
## [codeblock]
## var reporter := DotAuthSessionReporter.new()
## reporter.config = auth_config           # session_report_url, _key, server_id
## reporter.roster_provider = func() -> Array:
##     return server.playing_sessions().map(func(s): return s.identity.uid)
## add_child(reporter)
## [/codeblock]
##
## Authenticated to the issuer with [member DotAuthConfig.session_report_key],
## which the publisher issues per server. It travels as a bearer token over the
## reverse proxy's TLS, the same way a player's access token reaches
## [code]/ticket[/code].

const CHANNEL := "auth.sessions"

## The issuer caps a request; a roster past this is truncated with a warning.
##
## Past the cap a report can no longer say "absent means gone" for everybody, and
## the players it dropped are freed at the issuer. That is the honest failure — a
## report that stayed silent would hold them all for the lease instead.
const MAX_REPORTED_PLAYERS := 512

## Emitted after each report, successful or not.
signal reported(result: DotResult)

@export var config: DotAuthConfig = null

## Report on a timer once [method start] has run.
@export var auto_report: bool = true

## Supplies the current roster at report time: an [Array] of uid [String]s,
## [DotAuthIdentity]s, or dictionaries with a [code]uid[/code] key.
##
## A callable rather than pushed state, so the list is what is true when it is
## sent and a join that raced a report is in the next one.
var roster_provider: Callable = Callable()

var _http: DotHttp = null
var _timer: Timer = null
var _started: bool = false
var _report_count: int = 0
var _last_error: String = ""
var _last_sent: int = 0


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	var res := start()
	if not res.ok:
		DotLog.result(CHANNEL, "session reporting", res)


func start() -> DotResult:
	if _started:
		return DotResult.success(self)

	if config == null:
		return DotResult.fail(
			DotError.CODE_STATE, "DotAuthSessionReporter has no config."
		)

	if config.session_report_url.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_STATE,
			"No session_report_url; the issuer will not hear about this roster.",
			"set DotAuthConfig.session_report_url and session_report_key"
		)

	if config.session_report_key.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_STATE,
			"No session_report_key; the issuer would refuse every report."
		)

	if config.server_id.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_STATE,
			"No server_id; a roster has to say which server it is the roster of."
		)

	_http = DotHttp.new()
	_http.name = "SessionReportHttp"
	_http.timeout_sec = 15.0
	# One retry, not two: the next scheduled report supersedes this one anyway,
	# and a long retry tail would make reports arrive out of order.
	_http.max_retries = 1
	add_child(_http)

	if auto_report and config.session_report_interval_sec > 0.0:
		_timer = Timer.new()
		_timer.wait_time = config.session_report_interval_sec
		_timer.autostart = true
		_timer.timeout.connect(_on_report_due)
		add_child(_timer)

	_started = true

	DotLog.info(
		CHANNEL,
		"session reporting ready",
		{
			"issuer": config.session_report_url,
			"server": config.server_id,
			"interval": config.session_report_interval_sec,
		}
	)

	return DotResult.success(self)


## Sends the roster now. See [method normalise_roster] for what is accepted.
func report(roster: Array) -> DotResult:
	if not _started:
		return DotResult.fail(DotError.CODE_STATE, "Not started.")

	var uids := normalise_roster(roster)

	if uids.size() > MAX_REPORTED_PLAYERS:
		DotLog.warn(
			CHANNEL,
			"roster truncated for the issuer; players past the cap are freed there",
			{"had": uids.size(), "sent": MAX_REPORTED_PLAYERS}
		)
		uids = uids.slice(0, MAX_REPORTED_PLAYERS)

	var res := await _http.post_json(
		config.session_report_url.trim_suffix("/") + "/session",
		{"serverId": config.server_id, "users": Array(uids)},
		{"Authorization": "Bearer %s" % config.session_report_key}
	)

	if res.ok:
		_report_count += 1
		_last_sent = uids.size()
		_last_error = ""
		DotLog.debug(CHANNEL, "roster reported", {"players": uids.size()})
	else:
		_last_error = res.error.message
		if res.error.http_status == 401:
			# Will not fix itself. Say what to check rather than logging the
			# same refusal once a minute for the rest of the server's life.
			DotLog.warn(
				CHANNEL,
				"the issuer does not recognise this server's key; check "
				+ "session_report_key and that the issuer holds it under "
				+ "this server_id",
				{"server": config.server_id}
			)
		else:
			DotLog.warn(
				CHANNEL, "roster report failed", {"why": res.error.message}
			)

	reported.emit(res)
	return res


## Reports an empty roster and waits for it. Call before shutting down.
##
## Without it every player on a server that stops is held at the issuer for the
## lease, unable to join anywhere else, for no better reason than that nobody
## said goodbye.
func report_offline() -> DotResult:
	if not _started:
		return DotResult.success(false)
	return await report([])


## The uids in a roster, deduplicated, in order, with guests left out.
##
## A guest never held a ticket, so the issuer has no session to confirm and
## nothing a report could end. Sending them would only fill the issuer's table
## with per-device ids it will never be asked about.
static func normalise_roster(roster: Array) -> PackedStringArray:
	var seen := {}
	var out := PackedStringArray()

	for entry in roster:
		var uid := ""
		if entry is String or entry is StringName:
			uid = str(entry)
		elif entry is Dictionary:
			uid = str((entry as Dictionary).get("uid", ""))
		elif entry is Object and (entry as Object).get("uid") != null:
			uid = str((entry as Object).get("uid"))

		uid = uid.strip_edges()
		if uid == "" or uid.begins_with("guest:") or seen.has(uid):
			continue

		seen[uid] = true
		out.append(uid)

	return out


func _on_report_due() -> void:
	if not roster_provider.is_valid():
		return
	var roster: Variant = roster_provider.call()
	if roster is Array:
		await report(roster as Array)


func describe() -> Dictionary:
	return {
		"started": _started,
		"issuer": config.session_report_url if config != null else "",
		"server": config.server_id if config != null else "",
		"reports": _report_count,
		"last_sent": _last_sent,
		"interval": config.session_report_interval_sec if config != null else 0.0,
		"last_error": _last_error,
	}
