@tool
class_name DotAuthSessionReporter
extends Node

## Tells the issuer who is playing on this server: the server half of [member DotAuthConfig.single_session].
##
## Every report is the whole roster (absent means gone), from a callable the host supplies, so a lost report costs one interval. [DotAuthServer] builds it when [member DotAuthConfig.session_report_url] is set, authenticated with [member DotAuthConfig.session_report_key] as a bearer token over the proxy's TLS. Goodbye on shutdown and SIGINT limits: docs/rationale.md.

const CHANNEL := "auth.sessions"

## The issuer caps a request; a longer roster is truncated with a warning, so the dropped players are freed at the issuer rather than silently held for the lease.
const MAX_REPORTED_PLAYERS := 512

## Emitted after each report, successful or not.
signal reported(result: DotResult)

@export var config: DotAuthConfig = null

## Report on a timer once [method start] has run.
@export var auto_report: bool = true

## Supplies the current roster at report time: uid [String]s, [DotAuthIdentity]s, or dictionaries with a [code]uid[/code] key. A callable, so it is what is true when sent.
var roster_provider: Callable = Callable()

## How long the goodbye in [method report_offline_now] may hold up a process that is
## stopping. An issuer that does not answer in this long is treated as unreachable and
## the players fall back to its lease.
@export_range(0.5, 30.0, 0.5) var offline_timeout_sec: float = 3.0

var _http: DotHttp = null
var _timer: Timer = null
var _started: bool = false
var _report_count: int = 0
var _last_error: String = ""
var _last_sent: int = 0
## The empty roster has been delivered since the last real one, so leaving the tree
## does not send it twice.
var _offline_sent: bool = false
var _server: WeakRef = null


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
		# A roster after a goodbye (a server stopped and booted again) means the next
		# stop has to say goodbye again.
		_offline_sent = uids.is_empty()
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


## Reports an empty roster and waits for it; call before shutting down. Without it the players are held at the issuer for the lease. An about-to-quit host wants [method report_offline_now].
func report_offline() -> DotResult:
	if not _started:
		return DotResult.success(false)
	return await report([])


## Reports an empty roster [i]synchronously[/i], for a process about to end, on the calling thread for at most [member offline_timeout_sec].
##
## [method report_offline] goes through a node the tree frees first. Sends once. Not on web, where it cannot be waited for.
func report_offline_now() -> DotResult:
	if not _started:
		return DotResult.success(false)
	if _offline_sent:
		return DotResult.success(true)
	if DotPlatform.is_web():
		return DotResult.fail(
			DotError.CODE_UNSUPPORTED, "A browser cannot block on a request."
		)

	var res := _post_blocking(
		{"serverId": config.server_id, "users": []}, offline_timeout_sec
	)

	if res.ok:
		_offline_sent = true
		_report_count += 1
		_last_sent = 0
		_last_error = ""
		DotLog.info(CHANNEL, "told the issuer this server is empty", {
			"server": config.server_id,
		})
	else:
		_last_error = res.error.message
		DotLog.warn(
			CHANNEL,
			"could not tell the issuer this server stopped; its players are held "
			+ "for the lease",
			{"why": res.error.message, "lease": "the issuer's session_lease_sec"}
		)

	reported.emit(res)
	return res


## Reports [param server]'s signed-on players and says goodbye when it stops.
##
## Duck-typed: needs [code]sessions()[/code], a [code]state_changed[/code] signal and [code]state_name()[/code]. The roster is every signed-on session, not only those in play, or a loading player could take a ticket elsewhere. Holds a weak reference; an unknown roster is not sent (an empty one would free everybody).
func follow_server(server: Object) -> void:
	if server == null:
		return
	_server = weakref(server)
	if not roster_provider.is_valid():
		roster_provider = _server_roster
	if server.has_signal("state_changed") \
		and not server.is_connected("state_changed", _on_server_state):
		server.connect("state_changed", _on_server_state)


func _server_roster() -> Variant:
	var server: Object = _server.get_ref() if _server != null else null
	if server == null or not server.has_method("sessions"):
		return null

	var out: Array = []
	for session in server.call("sessions"):
		if session == null:
			continue
		if session.has_method("is_authenticated") \
			and not bool(session.call("is_authenticated")):
			continue
		if session.has_method("uid"):
			out.append(str(session.call("uid")))
		else:
			out.append(session)
	return out


func _on_server_state(_state: Variant) -> void:
	var server: Object = _server.get_ref() if _server != null else null
	if server == null or not server.has_method("state_name"):
		return
	if str(server.call("state_name")) == "SHUTTING_DOWN":
		report_offline_now()


func _exit_tree() -> void:
	if Engine.is_editor_hint():
		return
	# Leaving the tree is the last moment this node can speak: `quit()` takes every
	# node out of the tree before the process ends, and a reporter that is gone reports
	# nobody, which the issuer should hear rather than infer from a silent lease.
	if _started and not _offline_sent:
		report_offline_now()


## One JSON POST to the issuer's /session, on this thread, bounded by [param timeout].
func _post_blocking(payload: Dictionary, timeout: float) -> DotResult:
	var url := config.session_report_url.strip_edges().trim_suffix("/")
	var tls := false
	if url.to_lower().begins_with("https://"):
		tls = true
		url = url.substr(8)
	elif url.to_lower().begins_with("http://"):
		url = url.substr(7)

	var slash := url.find("/")
	var host_port := url if slash < 0 else url.substr(0, slash)
	var prefix := "" if slash < 0 else url.substr(slash)
	var host := host_port
	var port := 443 if tls else 80
	var colon := host_port.rfind(":")
	if colon > 0 and host_port.substr(colon + 1).is_valid_int():
		host = host_port.substr(0, colon)
		port = host_port.substr(colon + 1).to_int()

	var deadline := Time.get_ticks_msec() + int(timeout * 1000.0)
	var client := HTTPClient.new()
	var err := client.connect_to_host(
		host, port, TLSOptions.client() if tls else null
	)
	if err != OK:
		return DotResult.fail(DotError.CODE_NETWORK, "Could not reach the issuer.", host)

	var waiting := [HTTPClient.STATUS_RESOLVING, HTTPClient.STATUS_CONNECTING]
	while client.get_status() in waiting:
		client.poll()
		if Time.get_ticks_msec() > deadline:
			client.close()
			return DotResult.fail(DotError.CODE_TIMEOUT, "The issuer did not answer.")
		OS.delay_msec(2)

	if client.get_status() != HTTPClient.STATUS_CONNECTED:
		client.close()
		return DotResult.fail(DotError.CODE_NETWORK, "Could not reach the issuer.", host)

	err = client.request(
		HTTPClient.METHOD_POST,
		prefix + "/session",
		PackedStringArray([
			"Content-Type: application/json",
			"Authorization: Bearer %s" % config.session_report_key,
		]),
		JSON.stringify(payload)
	)
	if err != OK:
		client.close()
		return DotResult.fail(DotError.CODE_NETWORK, "The report could not be sent.")

	while client.get_status() == HTTPClient.STATUS_REQUESTING:
		client.poll()
		if Time.get_ticks_msec() > deadline:
			client.close()
			return DotResult.fail(DotError.CODE_TIMEOUT, "The issuer did not answer.")
		OS.delay_msec(2)

	if not client.has_response():
		client.close()
		return DotResult.fail(DotError.CODE_NETWORK, "The issuer closed the connection.")

	var status := client.get_response_code()
	client.close()

	if status == 401:
		var refused := DotError.make(
			DotError.CODE_AUTH, "The issuer does not recognise this server's key."
		)
		refused.http_status = status
		return DotResult.failure(refused)
	if status < 200 or status >= 300:
		var failed := DotError.make(
			DotError.CODE_HTTP, "The issuer answered %d." % status
		)
		failed.http_status = status
		return DotResult.failure(failed)

	return DotResult.success(true)


## The uids in a roster, deduplicated, in order, guests left out (they hold no ticket, so there is nothing to confirm or end).
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
		"offline_sent": _offline_sent,
		"following_server": _server != null and _server.get_ref() != null,
	}
