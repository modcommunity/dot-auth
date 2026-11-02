## Backbone, launcher handoff, ticket trust and audience discovery sections of auth_demo.gd.
## Path-based, no class_name: it exists to keep each script under the size budget.
extends "res://examples/auth_demo_base.gd"


## A backbone client publishes itself, so a consumer can find one it was not handed (a consumer built during module load exists before any host could assign one).
func _test_backbone_registry() -> void:
	_line("")
	_section("[b]the registry[/b]")

	var config := DotAuthConfig.new()
	config.integration_token = "tmci_selftest_not_a_real_token"
	config.report_interval_sec = 0.0

	var client := DotBackboneClient.new()
	client.config = config
	client.auto_report = false
	add_child(client)

	var started := client.start()
	_check("the client starts", started.ok, started)
	_check(
		"and publishes itself under dot_backbone_client",
		DotRegistry.get_service(&"dot_backbone_client") == client,
		DotResult.success(null)
	)

	# And takes it back down with it, or the next one to look finds a freed object.
	client.queue_free()
	await get_tree().process_frame
	_check(
		"and takes the registration with it",
		DotRegistry.get_service(&"dot_backbone_client") == null,
		DotResult.success(null)
	)
	_done()



## website-city refuses flat: `{ok: false, code, message, retryAfter?}`; the site's code must survive through post_app/get_app, not the fallback text.
func _test_app_refusal() -> void:
	_line("")
	_section("[b]app API refusals[/b]")

	var client := DotAuthClient.new()
	var body := "{\"ok\":false,\"code\":\"party.join.deny.full\",\"message\":\"This party is full.\"}"
	var got := client._app_refusal(DotResult.failure(DotError.from_http(409, body)), "fallback")
	_check("the site's code survives", not got.ok and got.error.detail == "party.join.deny.full", got)
	_check("and its message", got.error.message == "This party is full.", got)
	_check("and the HTTP status", got.error.http_status == 409, got)

	var slow := "{\"ok\":false,\"code\":\"rate_limited\",\"message\":\"Slow down.\",\"retryAfter\":12}"
	var limited := client._app_refusal(DotResult.failure(DotError.from_http(429, slow)), "fallback")
	_check("a retry-after is kept", limited.error.retry_after == 12.0, limited)

	var nested := "{\"ok\":false,\"error\":{\"code\":\"x\",\"message\":\"Nested.\"}}"
	var old := client._app_refusal(DotResult.failure(DotError.from_http(400, nested)), "fallback")
	_check("the nested shape still reads", old.error.detail == "x" and old.error.message == "Nested.", old)
	client.free()
	_done()


## A launcher's sign-in code, redeemed at the client's OWN backbone (the native twin of the page handoff).
##
## A loopback stub answers the one good code once and refuses others like the site (400 `invalid_grant`). Armed by: posting to a launcher-named URL, and skipping the empty-code guard.
func _test_launcher_handoff() -> void:
	_line("")
	_section("[b]launcher handoff[/b]")

	var tcp := TCPServer.new()
	if tcp.listen(0, "127.0.0.1") != OK:
		_line("  (no loopback port; skipped)")
		_passed += 7
		_done()
		return
	var seen: Array[Dictionary] = []
	var spent := [false]
	var serve := _launcher_stub_serve(tcp, seen, spent)
	get_tree().process_frame.connect(serve)

	var client := DotAuthClient.new()
	client.auto_sign_in = false
	client.config_file = ""
	client.config = DotAuthConfig.new()
	client.config.backbone_url = "http://127.0.0.1:%d" % tcp.get_local_port()
	client.config.token_store_path = "user://auth_demo_launcher_tokens.dat"
	add_child(client)

	var empty := await client.redeem_handoff("  ")
	_check("an empty code is refused", not empty.ok and empty.code() == DotError.CODE_INVALID, empty)
	_check("and asks nobody", seen.is_empty(), null)

	var good := await client.redeem_handoff("tmc_gh_good")
	_check("a good code signs in", good.ok and client.is_signed_in(), good)
	_check("as the member it names", good.ok and (good.value as DotAuthIdentity).uid == "backbone:u-ada", good)
	_check("redeemed at the backbone's handoff route",
		seen.size() == 1 and str(seen[0]["line"]).begins_with("POST /api/app/v1/auth/handoff "), null)

	client.sign_out(true)
	var again := await client.redeem_handoff("tmc_gh_good")
	_check("a spent code is refused", not again.ok and not client.is_signed_in(), again)
	_check("with the site's status kept", not again.ok and again.error.http_status == 400, again)

	get_tree().process_frame.disconnect(serve)
	tcp.stop()
	client.queue_free()
	DirAccess.remove_absolute(ProjectSettings.globalize_path("user://auth_demo_launcher_tokens.dat"))
	_done()


## Ticket trust adopted at runtime: server id from `integration/v1/me`, issuer keys from `ticket-keys` (a loopback stub) selected by `kid`, and tickets requested by the dialled address.
##
## Armed by: verifying with an empty audience, or ignoring `kid`.
func _test_ticket_trust(keys: Dictionary) -> void:
	_line("")
	_section("[b]ticket trust by address[/b]")

	var other := DotCloudKeys_generate()
	var id := "3550523"
	var ada: DotAuthIdentity = DotAuthIdentity.from_scoped_user(
		{"key": "Kq3_scopedKey-forThis1", "name": "Ada", "username": "ada"}).value
	var mint := func(aud: String, pem: String, kid: String, nonce: String = "") -> String:
		return str(DotAuthTicket.issue(ada, aud, pem, "tmc-site", 120, kid, nonce).value)
	var phase := {"extra": [], "revoked": [], "refresh": 900}

	var tcp := TCPServer.new()
	if tcp.listen(0, "127.0.0.1") != OK:
		_line("  (no loopback port; skipped)")
		_passed += 36
		_done()
		return
	var seen: Array[Dictionary] = []
	var serve := _trust_stub_serve(tcp, keys, id, phase, seen)
	get_tree().process_frame.connect(serve)
	var stub := "http://127.0.0.1:%d" % tcp.get_local_port()
	var cache := "user://auth_demo_ticket_trust.json"
	DirAccess.remove_absolute(ProjectSettings.globalize_path(cache))

	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.TICKET
	config.adopt_ticket_trust = true
	config.allow_guests = false
	config.backbone_url = stub
	config.ticket_trust_cache = cache
	_check("ticket mode starts with no id or key", config.validate().ok, config.validate())
	var server := DotAuthServer.new()
	server.config = config
	server.config_file = ""
	server.register_service = false
	server.discover_audience_tries = 1
	add_child(server)
	server.start()
	_check("and is not ready to verify", not server.ticket_trust_ready(), null)

	await _trust_before_adoption(server, config, mint, id, keys, seen)

	var me := FlakyMeBackbone.new()
	me.fail_first = 0
	server.backbone = me
	for i in 20:
		if config.server_id != "":
			break
		await get_tree().process_frame
	_check("server id adopted from integration/v1/me", config.server_id == id and server.ticket_trust_ready(), null)

	await _trust_basic_tickets(server, mint, id, keys, other, ada)

	var conn_a := "nonce-of-connection-A1"
	await _trust_bound_tickets(server, config, mint, id, keys, ada, conn_a)

	var priv := server.adopt_ticket_trust("", {"x": str(keys["private"])})
	_check("a private key is never adopted", not priv.ok and not config.ticket_public_keys.has("x"), priv)
	_check("plain HTTP to a remote backbone is refused",
		not DotAuthServer._trusted_key_url("http://example.com/api/app/v1/auth/ticket-keys")
			and DotAuthServer._trusted_key_url("https://example.com/x"), null)

	var second := _trust_restart(stub, cache, id)

	var third := await _trust_rotation(server, config, mint, id, keys, other, phase, stub, cache)

	var client := await _trust_client(stub, seen, conn_a)

	get_tree().process_frame.disconnect(serve)
	tcp.stop()
	client.queue_free()
	server.queue_free()
	second.queue_free()
	third.queue_free()
	me.free()
	DirAccess.remove_absolute(ProjectSettings.globalize_path(cache))
	DirAccess.remove_absolute(ProjectSettings.globalize_path("user://auth_demo_trust_tokens.dat"))
	_done()


func _trust_before_adoption(server: DotAuthServer, config: DotAuthConfig, mint: Callable, id: String, keys: Dictionary, seen: Array[Dictionary]) -> void:
	var early := await server.authenticate({"ticket": mint.call(id, str(keys["private"]), "k1")}, "p1")
	_check("so a sign-in waits, refused as STATE", not early.ok and early.code() == DotError.CODE_STATE, early)

	var fetched := await server.refresh_ticket_keys(true)
	_check("keys fetched from the backbone", fetched.ok and config.ticket_public_keys.has("k1"), fetched)
	_check("only RS256 public keys kept", config.ticket_public_keys.keys() == ["k1"], null)
	_check("at its ticket-keys route", seen.size() >= 1 and str(seen[-1]["line"]).begins_with("GET /api/app/v1/auth/ticket-keys "), null)
	var noid := await server.authenticate({"ticket": mint.call(id, str(keys["private"]), "k1")}, "p2")
	_check("a key alone is not enough (no audience)", not noid.ok and noid.code() == DotError.CODE_STATE, noid)


func _trust_basic_tickets(server: DotAuthServer, mint: Callable, id: String, keys: Dictionary, other: Dictionary, ada: DotAuthIdentity) -> void:
	var good: String = mint.call(id, str(keys["private"]), "k1")
	var first := await server.authenticate({"ticket": good}, "p3")
	_check("a ticket for this server verifies", first.ok and (first.value as DotAuthIdentity).uid == ada.uid, first)
	var again := await server.authenticate({"ticket": good}, "p4")
	_check("and is single-use", not again.ok and again.code() == DotError.CODE_FORBIDDEN, again)
	var elsewhere := await server.authenticate({"ticket": mint.call("3550524", str(keys["private"]), "k1")}, "p5")
	_check("one for another server is refused", not elsewhere.ok and elsewhere.code() == DotError.CODE_FORBIDDEN, elsewhere)

	var wanted: Array[String] = []
	server.ticket_key_wanted.connect(func(kid: String) -> void: wanted.append(kid))
	var rotated := await server.authenticate({"ticket": mint.call(id, str(other["private"]), "k2")}, "p6")
	_check("an unknown kid is refused as STATE", not rotated.ok and rotated.code() == DotError.CODE_STATE, rotated)
	_check("and asks for a refetch", wanted == ["k2"], null)
	var forged := await server.authenticate({"ticket": mint.call(id, str(other["private"]), "k1")}, "p7")
	_check("a known kid with the wrong key is refused", not forged.ok and forged.code() == DotError.CODE_INTEGRITY, forged)


func _trust_bound_tickets(server: DotAuthServer, config: DotAuthConfig, mint: Callable, id: String, keys: Dictionary, ada: DotAuthIdentity, conn_a: String) -> void:
	var bound: String = mint.call(id, str(keys["private"]), "k1", conn_a)
	var stolen := await server.authenticate({"ticket": bound}, "p8", "nonce-of-connection-B2")
	_check("a copied bound ticket is refused on another connection",
		not stolen.ok and stolen.code() == DotError.CODE_FORBIDDEN, stolen)
	var spoof := await server.authenticate({"ticket": bound, DotAuthServer.CONNECTION_NONCE_KEY: conn_a}, "p9")
	_check("and a client cannot supply the nonce itself",
		not spoof.ok and spoof.code() == DotError.CODE_FORBIDDEN, spoof)
	var owner := await server.authenticate({"ticket": bound}, "p10", conn_a)
	_check("the connection it was issued for signs in", owner.ok, owner)
	var replay := await server.authenticate({"ticket": bound}, "p11", conn_a)
	_check("once", not replay.ok and replay.code() == DotError.CODE_FORBIDDEN, replay)
	config.require_ticket_binding = true
	var unbound := await server.authenticate({"ticket": mint.call(id, str(keys["private"]), "k1")}, "p12", conn_a)
	_check("require_ticket_binding refuses an unbound ticket",
		not unbound.ok and unbound.code() == DotError.CODE_FORBIDDEN, unbound)
	config.require_ticket_binding = false
	var bare := DotJwt.base_claims("tmc-site", ada.uid, id, 120)
	bare.erase("jti")
	var nojti := await server.authenticate({"ticket": str(DotJwt.encode_rs256(bare, str(keys["private"]), "k1").value)}, "p13")
	_check("a ticket with no jti is refused", not nojti.ok and nojti.code() == DotError.CODE_INVALID, nojti)
	config.ticket_replay_max = server._spent_tickets.size()
	var full := await server.authenticate({"ticket": mint.call(id, str(keys["private"]), "k1")}, "p14")
	_check("a full replay memory refuses, never forgets",
		not full.ok and full.code() == DotError.CODE_RATE_LIMITED, full)
	config.ticket_replay_max = 100000


func _trust_restart(stub: String, cache: String, id: String) -> DotAuthServer:
	var reloaded := DotAuthConfig.new()
	reloaded.strategy = DotAuthConfig.Strategy.TICKET
	reloaded.adopt_ticket_trust = true
	reloaded.backbone_url = stub
	reloaded.ticket_trust_cache = cache
	reloaded.server_id = "777"
	var second := DotAuthServer.new()
	second.config = reloaded
	second.config_file = ""
	second.register_service = false
	add_child(second)
	second.start()
	_check("a restart reads the cached keys", reloaded.ticket_public_keys.has("k1"), null)
	_check("and auth.yml's server_id still wins", reloaded.server_id == "777", null)
	second.adopt_ticket_trust(id, {})
	_check("over the site's too", reloaded.server_id == "777", null)
	return second


func _trust_rotation(server: DotAuthServer, config: DotAuthConfig, mint: Callable, id: String, keys: Dictionary, other: Dictionary, phase: Dictionary, stub: String, cache: String) -> DotAuthServer:
	phase["extra"] = [{"kid": "k2", "alg": "RS256", "pem": str(other["public"])}]
	phase["refresh"] = 600
	var overlap := await server.refresh_ticket_keys(true)
	_check("rotation: the next key is adopted beside the old",
		overlap.ok and config.ticket_public_keys.has("k1") and config.ticket_public_keys.has("k2"), overlap)
	var by_old := await server.authenticate({"ticket": mint.call(id, str(keys["private"]), "k1")}, "p20")
	var by_new := await server.authenticate({"ticket": mint.call(id, str(other["private"]), "k2")}, "p21")
	_check("and both keys' tickets verify in the overlap", by_old.ok and by_new.ok, by_new if by_old.ok else by_old)
	_check("the site's refreshSec sets the refetch", is_equal_approx(server._keys_refresh_sec, 600.0), null)
	phase["revoked"] = ["k1"]
	var revoking := await server.refresh_ticket_keys(true)
	_check("revocation drops the revoked kid",
		revoking.ok and not config.ticket_public_keys.has("k1") and config.ticket_public_keys.has("k2"), revoking)
	var by_revoked := await server.authenticate({"ticket": mint.call(id, str(keys["private"]), "k1")}, "p22")
	_check("and refuses its tickets", not by_revoked.ok and by_revoked.code() == DotError.CODE_FORBIDDEN, by_revoked)
	server.adopt_ticket_trust("", {"k1": str(keys["public"])})
	_check("and never adopts it again", not config.ticket_public_keys.has("k1"), null)
	var third_cfg := DotAuthConfig.new()
	third_cfg.strategy = DotAuthConfig.Strategy.TICKET
	third_cfg.adopt_ticket_trust = true
	third_cfg.backbone_url = stub
	third_cfg.ticket_trust_cache = cache
	var third := DotAuthServer.new()
	third.config = third_cfg
	third.config_file = ""
	third.register_service = false
	add_child(third)
	third.start()
	third.adopt_ticket_trust("", {"k1": str(keys["public"])})
	_check("a restart remembers the revocation",
		not third_cfg.ticket_public_keys.has("k1") and third_cfg.ticket_public_keys.has("k2"), null)
	return third


func _trust_client(stub: String, seen: Array[Dictionary], conn_a: String) -> DotAuthClient:
	var client := DotAuthClient.new()
	client.auto_sign_in = false
	client.config_file = ""
	client.config = DotAuthConfig.new()
	client.config.backbone_url = stub
	client.config.token_store_path = "user://auth_demo_trust_tokens.dat"
	add_child(client)
	client.store.set_tokens("player-access", "player-refresh", 900)
	var asked := await client.request_ticket_for_address("play.example.com:6005")
	_check("a client asks by the address it dialled", asked.ok and asked.value == "t-for-6005", asked)
	var with_nonce := await client.request_ticket_for_address("play.example.com:6005", "", conn_a)
	_check("and passes the server's challenge nonce", with_nonce.ok
		and (seen[-1]["body"] as Dictionary).get("nonce", "") == conn_a, with_nonce)
	var unknown := await client.request_ticket_for_address("other.example.com:6005")
	_check("an unlisted address keeps the site's code",
		not unknown.ok and unknown.error.detail == "unknown_address", unknown)
	return client


## A backbone client that answers `player/introspect` from a table, the way the site's
## route does, and records what it was asked.
class FakeBackbone extends DotBackboneClient:
	var asked: Array = []

	func post_integration(path: String, body: Dictionary) -> DotResult:
		asked.append([path, body.duplicate()])
		var token := str(body.get("access_token", ""))
		if token == "live":
			return DotResult.success({"user": {
				"key": "Kq3_scopedKey-forThis1", "name": "Ada", "username": "ada"}})
		if token == "other-app":
			return DotResult.failure(DotError.from_http(403, "{\"code\":\"wrong_app\"}"))
		if token == "device-token":
			return DotResult.failure(DotError.from_http(403, "{\"code\":\"join_token_required\"}"))
		if token == "tmc_jt_elsewhere":
			return DotResult.failure(DotError.from_http(403, "{\"code\":\"wrong_audience\"}"))
		return DotResult.failure(DotError.from_http(401, "{\"code\":\"token_expired\"}"))


## Answers `integration/v1/me` only after [member fail_first] failures.
class FlakyMeBackbone extends DotBackboneClient:
	var fail_first := 2
	var target: Variant = {"kind": "server", "id": 3550523}
	var calls := 0

	func get_integration(_path: String, _query: Dictionary = {}) -> DotResult:
		calls += 1
		if calls <= fail_first:
			return DotResult.failure(DotError.from_http(429, "{\"code\":\"rate_limited\"}"))
		return DotResult.success({"ok": true, "target": target})


func _test_audience_discovery() -> void:
	_line("")
	_section("[b]join audience discovery[/b]")

	var flaky := FlakyMeBackbone.new()
	var server := _discovery_server(flaky)
	for i in 60:
		if server.join_audience() != "":
			break
		await get_tree().create_timer(0.1).timeout
	_check("a failed integration/v1/me is retried until it answers",
		server.join_audience() == "server:3550523" and flaky.calls == 3, null)
	server.queue_free()
	flaky.free()

	var bad := FlakyMeBackbone.new()
	bad.fail_first = 0
	bad.target = {"kind": "", "id": 0}
	server = _discovery_server(bad)
	for i in 10:
		await get_tree().process_frame
	_check("a reply naming no target announces nothing",
		server.join_audience() == "" and bad.calls == 1, null)
	server.queue_free()
	bad.free()

	var down := FlakyMeBackbone.new()
	down.fail_first = 1000
	server = _discovery_server(down)
	server.discover_audience_tries = 2
	await get_tree().create_timer(2.0).timeout
	_check("a backbone that never answers gives up after the bound",
		server.join_audience() == "" and down.calls == 3, null)
	server.queue_free()
	down.free()
	_done()


func _discovery_server(backbone: DotBackboneClient) -> DotAuthServer:
	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.INTROSPECT
	config.backbone_url = "http://127.0.0.1:9"
	var server := DotAuthServer.new()
	server.config = config
	server.config_file = ""
	server.register_service = false
	add_child(server)
	server.backbone = backbone
	return server

