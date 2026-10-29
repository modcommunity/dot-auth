extends Node

## A dedicated server that stops frees its players' seats on its own report, not the lease.
##
## Real [DotServer]s (linked from dot-server) with a [DotAuthServer] child and a real [DotAuthIssuer] on a 300-second lease, so a seat freed seconds after confirming can only have been freed by a report. The issuer's socket is a fake on a thread: the goodbye is synchronous and would block the main thread the real listener polls on. Armed by: [member DotAuthServer.create_session_reporter] defaulting false, or removing [code]follow_server[/code]. Run: timeout 120 examples/session_reporter_selftest.tscn.

const SERVER_A := "eu-west-1"
const SERVER_B := "us-east-2"
const KEY_A := "server-a-key-0123456789abcdef"
const FAKE_PORT := 18796
const SILENT_PORT := 18795
const SERVER_PORTS := [18797, 18798, 18799]

## See auth_demo for why both counts. docs/testing.md.
const SECTIONS := 5
const CHECKS := 33

var _entered := 0
var _completed := 0
var _passed := 0
var _failed := 0

var _issuer: DotAuthIssuer = null
var _ada: DotAuthIdentity = null

# The fake issuer socket. Everything the thread touches is behind the mutex.
var _fake: TCPServer = null
var _fake_thread: Thread = null
var _fake_mutex := Mutex.new()
var _fake_stop := false
var _fake_received: Array = []


func _ready() -> void:
	DotLog.set_level(DotLog.Level.ERROR)
	await _run()


func _run() -> void:
	print("dot-auth session reporter self-test")

	_fake = TCPServer.new()
	if _fake.listen(FAKE_PORT, "127.0.0.1") != OK:
		# An environment problem, not the code under test. The totals say what did not run.
		print("  port %d is in use; nothing here can run" % FAKE_PORT)
		return _finish()
	_fake_thread = Thread.new()
	_fake_thread.start(_fake_loop)

	var key := Crypto.new().generate_rsa(2048)
	var issuer_config := DotAuthConfig.new()
	issuer_config.issuer_private_key = key.save_to_string(false)
	issuer_config.issuer_name = "dot-auth-test"
	issuer_config.backbone_url = "http://127.0.0.1:1"
	issuer_config.ticket_ttl_sec = 300
	issuer_config.session_lease_sec = 300
	issuer_config.single_session = true

	_issuer = DotAuthIssuer.new()
	_issuer.name = "Issuer"
	_issuer.config = issuer_config
	_issuer.config_file = ""
	_issuer.listen_port = 0
	add_child(_issuer)
	var _keyed := _issuer.add_server_key(SERVER_A, KEY_A)

	_ada = DotAuthIdentity.new()
	_ada.uid = "backbone:ada"
	_ada.provider = "backbone"
	_ada.provider_id = "ada"
	_ada.display_name = "Ada"

	await _test_off_without_a_url()
	await _test_shutdown_reports()
	await _test_leaving_the_tree_reports()
	_test_unreachable_issuer()
	await _test_control_without_the_reporter()

	print("")
	_check(
		"every section ran to its last line (%d of %d)" % [_completed, SECTIONS],
		_completed == _entered and _entered == SECTIONS
	)
	_check(
		"every check ran (%d of %d)" % [_passed + _failed + 1, CHECKS],
		_passed + _failed + 1 == CHECKS
	)
	print("%d passed, %d failed" % [_passed, _failed])
	_finish()



func _test_off_without_a_url() -> void:
	_section("no session_report_url: nothing is built, nothing is sent")

	var server := await _boot_server(SERVER_PORTS[0])
	var auth := _auth_server("")
	server.add_child(auth)

	_check("the auth server starts", auth._started)
	_check("and builds no reporter", auth.session_reporter == null)
	_check("describe() says so", auth.describe()["session_reporter"] == null)

	await _adopt(server, 501, _ada)
	server.shutdown("test over")
	await _settle()
	_check("a stop sends nothing", _drain().is_empty())

	_free_server(server)
	_done()



func _test_shutdown_reports() -> void:
	_section("shutdown(): the seat frees on the report")

	var server := await _boot_server(SERVER_PORTS[1])
	var auth := _auth_server(_fake_url())
	server.add_child(auth)
	var reporter := auth.session_reporter

	_check("the auth server builds a reporter", reporter != null)
	if reporter == null:
		_free_server(server)
		return _done()
	_check("which follows the registered dot_server", bool(reporter.describe()["following_server"]))

	await _adopt(server, 601, _ada)
	await _adopt(server, 602, DotAuthIdentity.guest("device-1", "Visitor"))

	_check(
		"the roster is the signed-on uids, guests left out",
		DotAuthSessionReporter.normalise_roster(reporter.roster_provider.call())
			== PackedStringArray([_ada.uid])
	)

	var _ticket := _issuer.issue_for_identity(_ada, SERVER_A)
	await reporter._on_report_due()
	_drain()
	_check(
		"a scheduled report confirms the seat",
		_issuer.session_of(_ada.uid) == SERVER_A
			and bool(_issuer._sessions[_ada.uid]["confirmed"])
	)
	_check("so another server is refused", not _issuer.issue_for_identity(_ada, SERVER_B).ok)

	var started := Time.get_ticks_msec()
	server.shutdown("test over")
	var reports := _drain()
	_check(
		"shutdown() has sent the empty roster by the time it returns",
		reports.size() == 1 and (reports[0] as Array).is_empty()
	)
	_check("the seat is free", _issuer.session_of(_ada.uid) == "")
	_check(
		"seconds into a 300 s lease",
		Time.get_ticks_msec() - started < 10_000 and _issuer.config.session_lease_sec == 300
	)
	var elsewhere := _issuer.issue_for_identity(_ada, SERVER_B)
	_check("and another server takes them", elsewhere.ok)
	var _released := _issuer.release_session(_ada.uid)

	_free_server(server)
	await _settle()
	_check("leaving the tree after that sends nothing twice", _drain().is_empty())
	_done()



## What `quit` (the console's, a scheduled restart's, the host's) does: every node leaves
## the tree, children first, so the reporter goes before DotServer's own `_exit_tree`
## shutdown.
func _test_leaving_the_tree_reports() -> void:
	_section("leaving the tree (quit): the seat frees on the report")

	# Built before the server boots, so the reporter has to find the server when it
	# registers rather than at start.
	var server := DotServer.new()
	server.name = "ServerQuit"
	server.config = _server_config(SERVER_PORTS[2])
	server.config_file = ""
	server.auto_boot = false
	add_child(server)
	var auth := _auth_server(_fake_url())
	server.add_child(auth)
	var reporter := auth.session_reporter
	_check("a reporter built before the server boots", reporter != null)
	if reporter == null:
		_free_server(server)
		return _done()
	_check("is not following anything yet", not bool(reporter.describe()["following_server"]))

	var booted := await server.boot()
	_check("the server boots", booted.ok)
	_check("and the reporter follows it", bool(reporter.describe()["following_server"]))

	await _adopt(server, 701, _ada)
	var _ticket := _issuer.issue_for_identity(_ada, SERVER_A)
	await reporter._on_report_due()
	_drain()
	_check("the seat is confirmed", bool(_issuer._sessions[_ada.uid]["confirmed"]))

	remove_child(server)
	var reports := _drain()
	_check(
		"the tree teardown sent the empty roster",
		reports.size() >= 1 and (reports[0] as Array).is_empty()
	)
	_check("the seat is free", _issuer.session_of(_ada.uid) == "")
	_check("and another server takes them", _issuer.issue_for_identity(_ada, SERVER_B).ok)
	var _released := _issuer.release_session(_ada.uid)

	server.queue_free()
	await _settle()
	_done()



func _test_unreachable_issuer() -> void:
	_section("an issuer that is not there costs a stop at most the timeout")

	var config := _auth_config("http://127.0.0.1:1")
	var reporter := DotAuthSessionReporter.new()
	reporter.config = config
	reporter.auto_report = false
	reporter.offline_timeout_sec = 1.0
	add_child(reporter)

	var started := Time.get_ticks_msec()
	var res := reporter.report_offline_now()
	var took := Time.get_ticks_msec() - started
	_check("the goodbye fails", not res.ok)
	_check("inside its timeout (%d ms)" % took, took < 1500)
	_check("and says why in describe()", str(reporter.describe()["last_error"]) != "")

	# Leaving the tree tries once more, and is bounded the same way.
	started = Time.get_ticks_msec()
	remove_child(reporter)
	_check("leaving the tree is bounded too", Time.get_ticks_msec() - started < 1500)
	reporter.queue_free()

	# Refused is quick. The case the timeout is for is a host that takes the connection
	# and never answers (a wedged issuer, a proxy with no upstream): the kernel completes
	# the handshake from the listen backlog and nobody ever reads.
	var silent := TCPServer.new()
	if silent.listen(SILENT_PORT, "127.0.0.1") != OK:
		print("  port %d is in use; the silent-issuer half was not run" % SILENT_PORT)
		return _done()
	var hung := DotAuthSessionReporter.new()
	hung.config = _auth_config("http://127.0.0.1:%d" % SILENT_PORT)
	hung.auto_report = false
	hung.offline_timeout_sec = 1.0
	add_child(hung)
	started = Time.get_ticks_msec()
	var unanswered := hung.report_offline_now()
	took = Time.get_ticks_msec() - started
	_check("an issuer that never answers fails the goodbye", not unanswered.ok)
	_check("after the timeout and no longer (%d ms)" % took, took >= 900 and took < 1600)
	remove_child(hung)
	hung.queue_free()
	silent.stop()
	_done()



## The control: the same stop with the reporter switched off leaves the seat to the
## lease. This is what every server did before the auth server built one.
func _test_control_without_the_reporter() -> void:
	_section("control: with no reporter the seat waits for the lease")

	var server := await _boot_server(SERVER_PORTS[0])
	var auth := _auth_server(_fake_url())
	auth.create_session_reporter = false
	server.add_child(auth)
	_check("no reporter when switched off", auth.session_reporter == null)

	await _adopt(server, 801, _ada)
	var _ticket := _issuer.issue_for_identity(_ada, SERVER_A)
	var _confirmed := _issuer.report_sessions(SERVER_A, PackedStringArray([_ada.uid]))

	server.shutdown("test over")
	remove_child(server)
	_drain()
	_check("the seat is still held after the stop", _issuer.session_of(_ada.uid) == SERVER_A)
	_check("so another server is refused", not _issuer.issue_for_identity(_ada, SERVER_B).ok)
	var _released := _issuer.release_session(_ada.uid)

	server.queue_free()
	await _settle()
	_done()



func _server_config(port: int) -> DotServerConfig:
	var config := DotServerConfig.new()
	config.hostname = "dot-auth reporter selftest"
	config.port = port
	config.max_players = 4
	config.a2s_enabled = false
	config.query_enabled = false
	config.hibernate_when_empty = false
	config.startup_config = ""
	config.autoexec_config = ""
	# A thread blocked in a stdin read keeps the process alive after quit(). See dot-game.
	config.stdin_console_enabled = false
	return config


func _boot_server(port: int) -> DotServer:
	var server := DotServer.new()
	server.name = "Server%d" % port
	server.config = _server_config(port)
	server.config_file = ""
	server.auto_boot = false
	add_child(server)
	var booted := await server.boot()
	if not booted.ok:
		print("  server on %d did not boot: %s" % [port, booted.error.message])
	return server


func _auth_config(url: String) -> DotAuthConfig:
	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.ANONYMOUS
	config.server_id = SERVER_A
	config.session_report_url = url
	config.session_report_key = KEY_A if url != "" else ""
	return config


func _auth_server(url: String) -> DotAuthServer:
	var auth := DotAuthServer.new()
	auth.name = "Auth"
	auth.config = _auth_config(url)
	auth.config_file = ""
	return auth


func _adopt(server: DotServer, peer: int, identity: DotAuthIdentity) -> void:
	var session := DotClientSession.new()
	session.peer_id = peer
	session.identity = identity
	session.display_name = identity.display_name
	var _adopted := server.adopt_session(session)
	await get_tree().process_frame


func _free_server(server: DotServer) -> void:
	if server.state == DotServer.State.RUNNING or server.state == DotServer.State.HIBERNATING:
		server.shutdown("test over")
	if server.get_parent() == self:
		remove_child(server)
	server.queue_free()


func _fake_url() -> String:
	return "http://127.0.0.1:%d" % FAKE_PORT


func _settle() -> void:
	for _i in 3:
		await get_tree().process_frame


## Hands every roster the fake received to the real issuer, as its /session route would,
## and returns the rosters (each an Array of uids) in arrival order.
func _drain() -> Array:
	_fake_mutex.lock()
	var got := _fake_received.duplicate()
	_fake_received.clear()
	_fake_mutex.unlock()

	var rosters: Array = []
	for entry in got:
		var token := str(entry["auth"]).trim_prefix("Bearer ").strip_edges()
		var body: Variant = JSON.parse_string(str(entry["body"]))
		if not (body is Dictionary):
			continue
		var server_id := str((body as Dictionary).get("serverId", ""))
		if not _issuer.authorize_server(server_id, token):
			continue
		var uids := PackedStringArray()
		for u in (body as Dictionary).get("users", []):
			uids.append(str(u))
		var _reported := _issuer.report_sessions(server_id, uids)
		rosters.append(Array(uids))
	return rosters


func _fake_loop() -> void:
	while true:
		_fake_mutex.lock()
		var stop := _fake_stop
		_fake_mutex.unlock()
		if stop:
			return
		if _fake.is_connection_available():
			_fake_serve(_fake.take_connection())
		OS.delay_msec(1)


func _fake_serve(peer: StreamPeerTCP) -> void:
	var buf := PackedByteArray()
	var deadline := Time.get_ticks_msec() + 3000
	while Time.get_ticks_msec() < deadline:
		peer.poll()
		if peer.get_status() != StreamPeerTCP.STATUS_CONNECTED:
			return
		var n := peer.get_available_bytes()
		if n > 0:
			var got := peer.get_data(n)
			if int(got[0]) == OK:
				buf.append_array(got[1])

		var text := buf.get_string_from_ascii()
		var end := text.find("\r\n\r\n")
		if end >= 0:
			var auth := ""
			var length := 0
			for line in text.substr(0, end).split("\r\n"):
				var lower := line.to_lower()
				if lower.begins_with("authorization:"):
					auth = line.substr(14).strip_edges()
				elif lower.begins_with("content-length:"):
					length = line.substr(15).strip_edges().to_int()
			if buf.size() >= end + 4 + length:
				var body := buf.slice(end + 4, end + 4 + length).get_string_from_utf8()
				_fake_mutex.lock()
				_fake_received.append({"auth": auth, "body": body})
				_fake_mutex.unlock()
				var reply := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" \
					+ "Content-Length: 2\r\nConnection: close\r\n\r\n{}"
				var _put := peer.put_data(reply.to_ascii_buffer())
				OS.delay_msec(5)
				peer.disconnect_from_host()
				return
		OS.delay_msec(1)
	peer.disconnect_from_host()


func _section(title: String) -> void:
	_entered += 1
	print("")
	print(title)


func _done() -> void:
	_completed += 1


func _check(what: String, passed: bool) -> bool:
	if passed:
		_passed += 1
		print("  %-60s ok" % what)
	else:
		_failed += 1
		print("  %-60s FAILED" % what)
	return passed


func _finish() -> void:
	if _fake_thread != null:
		_fake_mutex.lock()
		_fake_stop = true
		_fake_mutex.unlock()
		_fake_thread.wait_to_finish()
	if _fake != null:
		_fake.stop()
	await get_tree().process_frame
	get_tree().quit(1 if _failed > 0 or _passed == 0 else 0)
