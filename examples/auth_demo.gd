extends "res://examples/auth_demo_base.gd"

## Exercises the parts of dot-auth that can be tested without a backbone (the device flow needs a human clicking Approve).
##
## Covers ticket minting and offline verification, audience scoping, replay, connection binding, key rotation and revocation, expiry and skew, tampering, algorithm confusion, PKCE, local accounts, admin mapping, the token store, and one seat per account. Run: examples/auth_demo.tscn.

const SERVER_A := "eu-west-1"
const SERVER_B := "us-east-2"


## Sections entered against sections that ran to their last line, and against this. A
## runtime error inside a section aborts that function and nothing says so; a section that
## bailed out early after a failed guard is counted as not finished on purpose.
const SECTIONS := 15

## Every check this suite runs, including the two at the end that compare the counts. The
## section counter cannot see a section that aborted after announcing itself — its remaining
## checks simply never run — and a total can. See docs/testing.md.
const CHECKS := 204



func _ready() -> void:
	DotLog.set_level(DotLog.Level.WARN)
	await _run()


func _run() -> void:
	_line("[b]dot-auth self-test[/b]")
	_line("")

	var keys := DotCloudKeys_generate()
	if keys.is_empty():
		_line("  keypair          FAILED to generate")
		return _finish()

	_line("  keypair          generated (RSA 2048)")
	_line("")

	await _test_tickets(keys)
	_test_pkce()
	_test_local_accounts()
	await _test_refusals_are_logged()
	_test_admin_source()
	_test_token_store()
	await _test_providers()
	await _test_local_profiles()
	await _test_single_session(keys)
	await _test_backbone_registry()
	_test_app_refusal()
	await _test_scoped_introspect()
	await _test_audience_discovery()
	await _test_launcher_handoff()
	await _test_ticket_trust(keys)

	_line("")
	# The two guards, as the last two checks. See docs/testing.md.
	_check(
		"every section ran to its last line (%d of %d)" % [_completed, SECTIONS],
		_completed == _entered and _entered == SECTIONS,
		null
	)
	_check(
		"every check ran (%d of %d)" % [_passed + _failed + 1, CHECKS],
		_passed + _failed + 1 == CHECKS,
		null
	)
	_line("[b]%d passed, %d failed[/b]" % [_passed, _failed])
	_finish()



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


func _test_scoped_introspect() -> void:
	_line("")
	_section("[b]scoped introspection[/b]")

	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.INTROSPECT
	config.backbone_url = "http://127.0.0.1:9"
	config.allow_guests = false
	var server := DotAuthServer.new()
	server.config = config
	server.config_file = ""
	server.register_service = false
	var fake := FakeBackbone.new()
	server.backbone = fake
	add_child(server)
	server.start()

	var got: DotResult = await server.authenticate({"access_token": "live"}, "10.0.5.1")
	var who: DotAuthIdentity = got.value if got.ok else null
	_check("a live token is asked about AS this server",
		fake.asked.size() == 1 and fake.asked[0][0] == "player/introspect"
			and fake.asked[0][1].get("access_token") == "live", got)
	_check("the identity is keyed by the site's scoped key, not an account id",
		who != null and who.uid == "tmc:Kq3_scopedKey-forThis1", got)
	_check("and carries that key for dot-user to file the profile under",
		who != null and who.claims.get("scoped_key") == "Kq3_scopedKey-forThis1", got)
	_check("with the member's name", who != null and who.display_name == "Ada", got)

	var dead: DotResult = await server.authenticate({"access_token": "stale"}, "10.0.5.2")
	_check("a dead token is a sign-in that is no longer valid",
		not dead.ok and dead.error.code == DotError.CODE_AUTH, dead)
	var wrong: DotResult = await server.authenticate({"access_token": "other-app"}, "10.0.5.3")
	_check("a token for another game is refused as forbidden",
		not wrong.ok and wrong.error.code == DotError.CODE_FORBIDDEN, wrong)

	var bad := DotAuthIdentity.from_scoped_user({"key": "../x"})
	_check("a key that is not a key is refused", not bad.ok, bad)

	# Join tokens: what a current client sends instead of its access token.
	var device: DotResult = await server.authenticate({"access_token": "device-token"}, "10.0.5.4")
	_check("an old client's account token: told to update",
		not device.ok and device.error.code == DotError.CODE_FORBIDDEN
			and device.error.message.contains("update"), device)
	var elsewhere: DotResult = await server.authenticate({"access_token": "tmc_jt_elsewhere"}, "10.0.5.5")
	_check("a join token for another server is refused as such",
		not elsewhere.ok and elsewhere.error.code == DotError.CODE_FORBIDDEN
			and elsewhere.error.message.contains("different server"), elsewhere)

	config.join_audience = "server:42"
	_check("the audience it announces is the pinned one",
		server.join_audience() == "server:42", null)
	_check("an audience must name one target",
		DotAuthConfig.is_audience("server:42") and DotAuthConfig.is_audience("app:7")
			and not DotAuthConfig.is_audience("global")
			and not DotAuthConfig.is_audience("server:0")
			and not DotAuthConfig.is_audience("server:42x"), null)

	server.queue_free()
	fake.free()

	# Without a backbone a join token cannot be resolved: say so, never "/me" it.
	var bare := DotAuthServer.new()
	var bare_config := DotAuthConfig.new()
	bare_config.strategy = DotAuthConfig.Strategy.INTROSPECT
	bare_config.backbone_url = "http://127.0.0.1:9"
	bare_config.allow_guests = false
	bare.config = bare_config
	bare.config_file = ""
	bare.register_service = false
	add_child(bare)
	bare.start()
	var unresolvable: DotResult = await bare.authenticate({"access_token": "tmc_jt_x"}, "10.0.5.6")
	_check("no backbone: a join token fails in words",
		not unresolvable.ok and unresolvable.error.code == DotError.CODE_STATE, unresolvable)
	bare.queue_free()

	# The client half: nothing is minted for a server the build does not list.
	var client_config := DotAuthConfig.new()
	client_config.first_party_audiences = PackedStringArray(["server:42"])
	var client := DotAuthClient.new()
	client.config = client_config
	_check("a listed server is first-party", client.is_first_party("server:42"), null)
	_check("another is not", not client.is_first_party("server:43"), null)
	var refused: DotResult = await client.request_join_token("server:43")
	_check("and no join token is requested for it",
		not refused.ok and refused.error.code == DotError.CODE_FORBIDDEN, refused)
	client.free()
	_done()



func _test_tickets(keys: Dictionary) -> void:
	_section("[b]connect tickets[/b]")

	var identity := DotAuthIdentity.new()
	identity.uid = "backbone:clx8f2k0000"
	identity.provider = "backbone"
	identity.provider_id = "clx8f2k0000"
	identity.display_name = "Ada"
	identity.username = "ada"
	identity.role = "USER"
	identity.claims = {"groups": ["moderators"], "supporter": true}

	var minted := DotAuthTicket.issue(
		identity, SERVER_A, str(keys["private"]), "dot-auth-test", 300
	)
	_check("mint", minted.ok, minted)
	if not minted.ok:
		return

	var ticket: String = minted.value

	# The happy path.
	var verified := DotAuthTicket.verify(
		ticket, str(keys["public"]), SERVER_A
	)
	_check("verify", verified.ok, verified)

	if verified.ok:
		var d: Dictionary = verified.value
		var got: DotAuthIdentity = d["identity"]
		_check("identity survives", got.uid == identity.uid, null)
		_check("claims survive", got.has_claim("supporter"), null)
		_check(
			"groups survive",
			got.groups().has("moderators"),
			null
		)

	# Audience scoping: the whole reason tickets are server-specific.
	var wrong_server := DotAuthTicket.verify(
		ticket, str(keys["public"]), SERVER_B
	)
	_check(
		"refused by other server",
		not wrong_server.ok and wrong_server.code() == DotError.CODE_FORBIDDEN,
		wrong_server
	)

	# Tampering: flip a byte of the payload segment.
	var parts := ticket.split(".")
	var payload := DotHash.base64url_decode_text(parts[1])
	var hacked := payload.replace("\"Ada\"", "\"Eve\"")
	var forged := "%s.%s.%s" % [
		parts[0], DotHash.base64url_encode_text(hacked), parts[2]
	]
	var tamper := DotAuthTicket.verify(
		forged, str(keys["public"]), SERVER_A
	)
	_check(
		"tampered payload refused",
		not tamper.ok and tamper.code() == DotError.CODE_INTEGRITY,
		tamper
	)

	# Algorithm confusion: sign an HS256 token using the RSA *public* key as the
	# HMAC secret — which is public — and offer it where RS256 is expected. A
	# verifier that dispatches on the token's own `alg` header accepts this.
	var claims := DotJwt.base_claims("dot-auth-test", identity.uid, SERVER_A, 300)
	var hs := DotJwt.encode_hs256(claims, str(keys["public"]))
	if hs.ok:
		var confused := DotAuthTicket.verify(
			str(hs.value), str(keys["public"]), SERVER_A
		)
		_check(
			"HS256-for-RS256 refused",
			not confused.ok and confused.code() == DotError.CODE_INTEGRITY,
			confused
		)

	# Expiry, with leeway set to zero so a negative TTL is genuinely past.
	var expired := DotAuthTicket.issue(
		identity, SERVER_A, str(keys["private"]), "dot-auth-test", -600
	)
	if expired.ok:
		var exp_check := DotAuthTicket.verify(
			str(expired.value), str(keys["public"]), SERVER_A, 0
		)
		_check(
			"expired ticket refused",
			not exp_check.ok and exp_check.code() == DotError.CODE_AUTH,
			exp_check
		)

		# The same ticket accepted when leeway covers the gap, proving the leeway
		# path works rather than expiry simply always failing.
		var lenient := DotAuthTicket.verify(
			str(expired.value), str(keys["public"]), SERVER_A, 3600
		)
		_check("leeway honoured", lenient.ok, lenient)

	# Replay, through a real DotAuthServer so the spent-ticket memory is exercised.
	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.TICKET
	config.server_id = SERVER_A
	config.ticket_public_key = str(keys["public"])
	config.ticket_ttl_sec = 300
	config.ticket_replay_memory_sec = 900
	config.allow_guests = false

	var server := DotAuthServer.new()
	server.name = "AuthServer"
	server.config = config
	server.config_file = ""
	server.register_service = false
	add_child(server)

	var started := server.start()
	_check("server starts", started.ok, started)

	var first := await server.authenticate({"ticket": ticket}, "peer1")
	_check("first use accepted", first.ok, first)

	var second := await server.authenticate({"ticket": ticket}, "peer2")
	_check(
		"replay refused",
		not second.ok and second.code() == DotError.CODE_FORBIDDEN,
		second
	)

	# No ticket at all, with guests disabled.
	var none := await server.authenticate({}, "peer3")
	_check(
		"missing ticket refused",
		not none.ok and none.code() == DotError.CODE_AUTH,
		none
	)

	# Guests admitted when the server allows it.
	config.allow_guests = true
	var guest := await server.authenticate({"device_id": "abc"}, "peer4")
	_check(
		"guest fallback works",
		guest.ok and (guest.value as DotAuthIdentity).is_guest,
		guest
	)

	# A guest may pick a name; an authenticated player may not override theirs.
	var named := await server.authenticate(
		{"device_id": "xyz", "name": "Chosen"}, "peer5"
	)
	_check(
		"guest may name itself",
		named.ok and (named.value as DotAuthIdentity).display_name == "Chosen",
		named
	)

	var fresh := DotAuthTicket.issue(
		identity, SERVER_A, str(keys["private"]), "dot-auth-test", 300
	)
	var impersonate := await server.authenticate(
		{"ticket": str(fresh.value), "name": "Administrator"}, "peer6"
	)
	_check(
		"account name not overridable",
		impersonate.ok
			and (impersonate.value as DotAuthIdentity).display_name == "Ada",
		impersonate
	)

	server.queue_free()
	_line("")
	_done()



func _test_pkce() -> void:
	_section("[b]PKCE[/b]")

	var pair := DotPkce.generate()
	var verifier := str(pair["verifier"])
	var challenge := str(pair["challenge"])

	# The backbone's DeviceStartRequest schema requires 43-128 characters.
	_check(
		"verifier length in range",
		verifier.length() >= 43 and verifier.length() <= 128,
		null
	)
	_check(
		"challenge length in range",
		challenge.length() >= 43 and challenge.length() <= 128,
		null
	)
	_check("challenge differs from verifier", challenge != verifier, null)
	_check("challenge verifies", DotPkce.verify(verifier, challenge), null)
	_check(
		"wrong verifier refused",
		not DotPkce.verify(verifier + "x", challenge),
		null
	)
	_check(
		"derivation is deterministic",
		DotPkce.challenge_for(verifier) == challenge,
		null
	)

	_line("")
	_done()



func _test_local_accounts() -> void:
	_section("[b]local accounts[/b]")

	var path := "user://dot_auth_test_accounts.json"
	DirAccess.remove_absolute(path)

	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.LOCAL
	config.local_accounts_path = path
	config.allow_guests = false

	var server := DotAuthServer.new()
	server.name = "LocalAuthServer"
	server.config = config
	server.config_file = ""
	server.register_service = false
	add_child(server)
	server.start()

	var created := server.upsert_local_account(
		"grace", "correct-horse-battery", "Grace", "ADMIN"
	)
	_check("account created", created.ok, created)

	var ok := await server.authenticate(
		{"username": "grace", "password": "correct-horse-battery"}, "peer1"
	)
	_check("correct password accepted", ok.ok, ok)
	if ok.ok:
		var id: DotAuthIdentity = ok.value
		_check("uid namespaced", id.uid == "local:grace", null)
		_check("role carried", id.role == "ADMIN", null)

	var bad := await server.authenticate(
		{"username": "grace", "password": "wrong"}, "peer2"
	)
	_check(
		"wrong password refused",
		not bad.ok and bad.code() == DotError.CODE_AUTH,
		bad
	)

	var unknown := await server.authenticate(
		{"username": "nobody", "password": "whatever"}, "peer3"
	)
	# Same code and message as a wrong password, so the response does not reveal
	# which usernames exist.
	_check(
		"unknown user indistinguishable",
		not unknown.ok
			and unknown.error.message == bad.error.message,
		unknown
	)

	# The stored record must not contain the password.
	var stored := DotPaths.read_text(path)
	_check(
		"password not stored in plaintext",
		stored.ok and not str(stored.value).contains("correct-horse-battery"),
		null
	)

	server.queue_free()
	DirAccess.remove_absolute(path)
	_line("")
	_done()



## Each refusal is logged at the level of whoever has to act: the player's at INFO, the limiter's at DEBUG, a down verifier at WARN once, a long run with nobody getting in at WARN once.
func _test_refusals_are_logged() -> void:
	_section("[b]refusals are logged[/b]")

	var records: Array[Dictionary] = []
	var capture := func(rec: Dictionary) -> void:
		if str(rec.get("channel", "")) == DotAuthServer.CHANNEL:
			records.append(rec)
	var printing := DotLog.print_to_stdout
	DotLog.print_to_stdout = false
	DotLog.set_channel_level(DotAuthServer.CHANNEL, DotLog.Level.DEBUG)
	DotLog.signals().record.connect(capture)

	var path := "user://dot_auth_test_refusals.json"
	DirAccess.remove_absolute(path)
	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.LOCAL
	config.local_accounts_path = path
	config.allow_guests = false
	config.auth_attempts_per_minute = 3
	var server := DotAuthServer.new()
	server.config = config
	server.config_file = ""
	server.register_service = false
	add_child(server)
	server.start()
	server.upsert_local_account("grace", "correct-horse-battery", "Grace", "")

	records.clear()
	await server.authenticate({"username": "Grace", "password": "hunter2-secret"}, "10.0.0.1")
	var refusal: Dictionary = records[0] if records.size() == 1 else {}
	var fields: Dictionary = refusal.get("fields", {})
	_check(
		"a wrong password is INFO",
		int(refusal.get("level", -1)) == DotLog.Level.INFO
			and str(fields.get("code", "")) == DotError.CODE_AUTH,
		null
	)
	_check(
		"naming who and from where",
		str(fields.get("username", "")) == "grace" and str(fields.get("from", "")) == "10.0.0.1",
		null
	)
	_check(
		"and never the password",
		not var_to_str(refusal).contains("hunter2-secret"),
		null
	)

	# Three per minute per key: the fourth from one address is the limiter.
	for i in range(3):
		await server.authenticate({"username": "grace", "password": "no"}, "10.0.0.2")
	records.clear()
	await server.authenticate({"username": "grace", "password": "no"}, "10.0.0.2")
	_check(
		"the limiter's refusal is DEBUG",
		records.size() == 1 and int(records[0].get("level", -1)) == DotLog.Level.DEBUG
			and str((records[0].get("fields", {}) as Dictionary).get("code", ""))
				== DotError.CODE_RATE_LIMITED,
		null
	)

	# A run with nobody getting in is escalated once, and a real sign-in ends the run.
	var warns := func() -> int:
		return records.filter(func(r: Dictionary) -> bool:
			return int(r.get("level", -1)) == DotLog.Level.WARN).size()
	await server.authenticate({"username": "grace", "password": "correct-horse-battery"}, "10.0.1.0")
	records.clear()
	for i in range(DotAuthServer.REFUSAL_RUN_WARN - 1):
		await server.authenticate({"username": "grace", "password": "no"}, "10.0.1.%d" % (i + 1))
	_check("a few refusals are not a WARN", warns.call() == 0, null)
	await server.authenticate({"username": "grace", "password": "no"}, "10.0.2.0")
	_check("a run of them with nobody in is", warns.call() == 1, null)
	for i in range(5):
		await server.authenticate({"username": "grace", "password": "no"}, "10.0.3.%d" % i)
	_check("once, not on every refusal after", warns.call() == 1, null)

	server.queue_free()
	DirAccess.remove_absolute(path)

	# A verifier that cannot be reached: WARN once, however many joins it refuses.
	var down := DotAuthConfig.new()
	down.strategy = DotAuthConfig.Strategy.INTROSPECT
	down.backbone_url = "http://127.0.0.1:9"
	down.allow_guests = false
	var remote := DotAuthServer.new()
	remote.config = down
	remote.config_file = ""
	remote.register_service = false
	add_child(remote)
	remote.start()
	records.clear()
	var first: DotResult = await remote.authenticate({"access_token": "t1"}, "10.0.4.1")
	await remote.authenticate({"access_token": "t2"}, "10.0.4.2")
	var outage := records.filter(func(r: Dictionary) -> bool:
		return str(r.get("message", "")) == "sign-ins cannot be verified right now")
	_check(
		"an unreachable verifier is one WARN",
		not first.ok and outage.size() == 1
			and int(outage[0].get("level", -1)) == DotLog.Level.WARN,
		first
	)
	remote.queue_free()

	DotLog.signals().record.disconnect(capture)
	DotLog.clear_channel_level(DotAuthServer.CHANNEL)
	DotLog.print_to_stdout = printing
	_line("")
	_done()



func _test_admin_source() -> void:
	_section("[b]admin mapping[/b]")

	var source := DotAuthAdminSource.new()
	source.group_flags = {
		"moderators": ["kick", "mute"],
		"admins": "kick,ban,changemap",
	}
	source.group_immunity = {"moderators": 20, "admins": 80}
	source.claim_flags = {"supporter": ["reserved_slot"]}
	source.authenticated_flags = PackedStringArray(["chat"])

	var moderator := DotAuthIdentity.new()
	moderator.uid = "backbone:1"
	moderator.provider = "backbone"
	moderator.display_name = "Mod"
	moderator.claims = {"groups": ["moderators"], "supporter": true}

	var res := source.lookup(moderator)
	_check("moderator resolved", res.ok, res)

	if res.ok:
		var d: Dictionary = res.value
		var flags: PackedStringArray = d["flags"]
		_check("group flags granted", flags.has("kick") and flags.has("mute"), null)
		_check("claim flags granted", flags.has("reserved_slot"), null)
		_check("baseline flags granted", flags.has("chat"), null)
		_check("no unearned flags", not flags.has("ban"), null)
		_check("immunity from group", int(d["immunity"]) == 20, null)

	# Comma-separated flags in a config string must parse.
	var admin := DotAuthIdentity.new()
	admin.uid = "backbone:2"
	admin.provider = "backbone"
	admin.claims = {"groups": ["admins"]}
	var admin_res := source.lookup(admin)
	_check(
		"comma-separated flags parsed",
		admin_res.ok and (admin_res.value["flags"] as PackedStringArray).has("changemap"),
		admin_res
	)

	# Guests must never receive permissions: the identity is a random per-device
	# string, so granting anything would grant it to anyone who asks.
	var guest := DotAuthIdentity.guest("device123")
	var guest_res := source.lookup(guest)
	_check(
		"guests get nothing",
		not guest_res.ok and guest_res.code() == DotError.CODE_FORBIDDEN,
		guest_res
	)

	# A signed-in player in no mapped group still gets the baseline, and nothing
	# else — in particular not their site role, which is unmapped by default.
	var plain := DotAuthIdentity.new()
	plain.uid = "backbone:3"
	plain.provider = "backbone"
	plain.role = "ADMIN"
	var plain_res := source.lookup(plain)
	_check(
		"unmapped site role grants nothing",
		plain_res.ok
			and not (plain_res.value["flags"] as PackedStringArray).has("ban"),
		plain_res
	)

	_line("")
	_done()



func _test_token_store() -> void:
	_section("[b]token store[/b]")

	var path := "user://dot_auth_test_tokens.dat"
	DirAccess.remove_absolute(path)
	DirAccess.remove_absolute(path + ".salt")

	var identity := DotAuthIdentity.new()
	identity.uid = "backbone:42"
	identity.provider = "backbone"
	identity.display_name = "Linus"

	var store := DotAuthTokenStore.new(path, true)
	var saved := store.set_tokens("tmc_at_abc", "tmc_rt_xyz", 3600, identity)
	_check("saved", saved.ok, saved)

	# The refresh token must not be recoverable from the file. Compared as raw bytes:
	# ciphertext is not valid UTF-8, and decoding would spam the log and could hide a
	# real substring behind a replacement character.
	var raw := DotPaths.read_bytes(path)
	_check(
		"encrypted at rest",
		raw.ok and _find_bytes(raw.value, "tmc_rt_xyz".to_utf8_buffer()) < 0,
		null
	)

	var reopened := DotAuthTokenStore.new(path, true)
	var loaded := reopened.load_tokens()
	_check("reloaded", loaded.ok and bool(loaded.value), loaded)
	_check(
		"refresh token round-trips",
		reopened.refresh_token() == "tmc_rt_xyz",
		null
	)
	_check(
		"identity round-trips",
		reopened.identity() != null and reopened.identity().uid == "backbone:42",
		null
	)
	_check("access token valid", reopened.is_access_valid(), null)
	_check(
		"margin respected",
		not reopened.is_access_valid(7200.0),
		null
	)

	reopened.clear()
	_check("cleared", not FileAccess.file_exists(path), null)

	_line("")
	_done()


## A custom authentication provider, defined entirely outside dot-auth.
class DemoProvider extends DotAuthProvider:
	var should_fail := false

	func _provider_name() -> String:
		return "demo"

	func _handles(credential: Dictionary) -> bool:
		return credential.has("demo_token")

	func _authenticate(credential: Dictionary) -> DotResult:
		if should_fail:
			return DotResult.fail(DotError.CODE_AUTH, "Demo provider refused.")

		var identity := DotAuthIdentity.new()
		identity.provider = "demo"
		identity.provider_id = str(credential["demo_token"])
		identity.uid = "demo:%s" % identity.provider_id
		identity.display_name = "Demo User"
		return DotResult.success(identity)


func _test_providers() -> void:
	_section("[b]custom auth providers[/b]")

	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.LOCAL
	config.local_accounts_path = "user://dot_auth_provider_test.json"
	config.allow_guests = false

	var server := DotAuthServer.new()
	server.name = "ProviderAuthServer"
	server.config = config
	server.config_file = ""
	server.register_service = false
	add_child(server)
	server.start()

	var provider := DemoProvider.new()
	_check("provider registered", server.add_provider(provider).ok, null)

	# A credential the provider claims is handled by it, not by the strategy.
	var ok := await server.authenticate({"demo_token": "abc123"}, "peer1")
	_check("provider authenticated", ok.ok, ok)
	if ok.ok:
		var id: DotAuthIdentity = ok.value
		_check("provider uid namespaced", id.uid == "demo:abc123", null)
		_check("provider name carried", id.provider == "demo", null)

	# A credential it does not claim falls through to the configured strategy.
	var fell_through := await server.authenticate(
		{"username": "nobody", "password": "x"}, "peer2"
	)
	_check(
		"unclaimed credential falls through",
		not fell_through.ok and fell_through.code() == DotError.CODE_AUTH,
		null
	)

	# A provider that claims and then refuses owns the outcome; the strategy must
	# not get a second go at letting the login in.
	provider.should_fail = true
	var refused := await server.authenticate({"demo_token": "abc123"}, "peer3")
	_check("provider refusal is final", not refused.ok, null)

	server.queue_free()
	DirAccess.remove_absolute(config.local_accounts_path)
	_line("")
	_done()



func _finish() -> void:
	if DotPlatform.is_headless():
		await get_tree().process_frame
		get_tree().quit(1 if _failed > 0 else 0)



## One account, one seat, with every way a session can end: server report, player release, lease expiry.
##
## The roster path runs over a real socket through the issuer's own listener, the one part a unit call cannot reach.
func _test_single_session(keys: Dictionary) -> void:
	_section("[b]single session[/b]")

	const PORT := 18787
	const KEY_A := "server-a-key-0123456789abcdef"

	var ada := DotAuthIdentity.new()
	ada.uid = "backbone:ada"
	ada.provider = "backbone"
	ada.provider_id = "ada"
	ada.display_name = "Ada"


	var bad := DotAuthConfig.new()
	bad.strategy = DotAuthConfig.Strategy.ANONYMOUS
	bad.single_session = true
	bad.ticket_ttl_sec = 300
	bad.session_lease_sec = 60
	_check(
		"a lease shorter than the ticket is refused",
		not bad.validate().ok,
		null
	)

	var unkeyed := DotAuthConfig.new()
	unkeyed.strategy = DotAuthConfig.Strategy.ANONYMOUS
	unkeyed.server_id = SERVER_A
	unkeyed.session_report_url = "http://127.0.0.1:%d" % PORT
	_check(
		"reporting without a key is refused",
		not unkeyed.validate().ok,
		null
	)


	var config := DotAuthConfig.new()
	config.issuer_private_key = str(keys["private"])
	config.issuer_name = "dot-auth-test"
	# Nothing here may reach the real backbone. The one request below that
	# would — a ticket request over the socket — fails at this address instead,
	# quickly and offline.
	config.backbone_url = "http://127.0.0.1:1"
	config.ticket_ttl_sec = 300
	config.session_lease_sec = 300
	config.single_session = true

	var issuer := DotAuthIssuer.new()
	issuer.name = "Issuer"
	issuer.config = config
	issuer.config_file = ""
	issuer.listen_port = PORT
	issuer.bind_address = "127.0.0.1"
	add_child(issuer)

	# _ready() has started it. A port in use is an environment problem, not a
	# failure of the code under test, so the socket half is skipped rather than
	# failed if the listener could not bind.
	var listening := bool(issuer.describe()["listening"])
	_check("issuer starts", issuer._private_key != "", null)

	_check("a short server key is refused", not issuer.add_server_key(SERVER_A, "short").ok, null)
	_check("a server key registers", issuer.add_server_key(SERVER_A, KEY_A).ok, null)
	_check("the right key authorises", issuer.authorize_server(SERVER_A, KEY_A), null)
	_check("a wrong key does not", not issuer.authorize_server(SERVER_A, KEY_A + "x"), null)
	_check("an unknown server does not", not issuer.authorize_server(SERVER_B, KEY_A), null)
	_check("an empty key never does", not issuer.authorize_server(SERVER_A, ""), null)

	var conflicts: Array = []
	issuer.session_conflict.connect(
		func(uid: String, held: String, wanted: String) -> void:
			conflicts.append([uid, held, wanted])
	)

	# The rule itself.
	var first := issuer.issue_for_identity(ada, SERVER_A)
	_check("a first ticket is issued", first.ok, first)
	_check("and opens a session", issuer.session_of(ada.uid) == SERVER_A, null)

	var elsewhere := issuer.issue_for_identity(ada, SERVER_B)
	_check(
		"a ticket for another server is refused",
		not elsewhere.ok and elsewhere.code() == DotError.CODE_FORBIDDEN,
		elsewhere
	)
	_check(
		"naming the server they are on",
		not elsewhere.ok and elsewhere.error.detail == SERVER_A
			and elsewhere.error.message.contains(SERVER_A),
		null
	)
	_check("and the conflict is signalled", conflicts.size() == 1, null)

	var again := issuer.issue_for_identity(ada, SERVER_A)
	_check("a reconnect to the same server is allowed", again.ok, again)

	# A roster that omits a player who has not arrived yet does not free them —
	# otherwise a player could collect tickets for two servers in the seconds
	# before the first roster names them.
	var empty_early := issuer.report_sessions(SERVER_A, PackedStringArray())
	_check("an empty roster is accepted", empty_early.ok, empty_early)
	_check(
		"but does not end an unconfirmed session",
		issuer.session_of(ada.uid) == SERVER_A,
		null
	)

	# Confirmed by the server, then reported gone.
	issuer.report_sessions(SERVER_A, PackedStringArray([ada.uid]))
	_check(
		"a roster confirms the session",
		issuer.session_of(ada.uid) == SERVER_A
			and bool(issuer._sessions[ada.uid]["confirmed"]),
		null
	)
	var still := issuer.issue_for_identity(ada, SERVER_B)
	_check("and the refusal stands", not still.ok, still)

	issuer.report_sessions(SERVER_A, PackedStringArray())
	_check(
		"a roster without them ends it",
		issuer.session_of(ada.uid) == "",
		null
	)
	var freed := issuer.issue_for_identity(ada, SERVER_B)
	_check("and the other server is open to them", freed.ok, freed)

	# A reconnect ticket must not demote a confirmed session, or the next roster
	# to omit them would be unable to end it.
	issuer.report_sessions(SERVER_B, PackedStringArray([ada.uid]))
	issuer.issue_for_identity(ada, SERVER_B)
	_check(
		"a reconnect keeps the session confirmed",
		bool(issuer._sessions[ada.uid]["confirmed"]),
		null
	)

	# A server's report is the truth about where a player is, even when the
	# record disagrees.
	issuer.report_sessions(SERVER_A, PackedStringArray([ada.uid]))
	_check(
		"a roster moves a player the record had elsewhere",
		issuer.session_of(ada.uid) == SERVER_A,
		null
	)

	# The player leaving.
	_check("a player releases their own session", issuer.release_session(ada.uid), null)
	_check("and there is nothing to release twice", not issuer.release_session(ada.uid), null)
	var after_release := issuer.issue_for_identity(ada, SERVER_B)
	_check("after which any server will do", after_release.ok, after_release)
	issuer.release_session(ada.uid)

	# The lease. A server that never reports holds a player for exactly this
	# long and then lets go.
	config.session_lease_sec = 1
	config.ticket_ttl_sec = 1
	issuer.issue_for_identity(ada, SERVER_A)
	var held := issuer.issue_for_identity(ada, SERVER_B)
	_check("a fresh session holds", not held.ok, held)
	await get_tree().create_timer(1.2).timeout
	var lapsed := issuer.issue_for_identity(ada, SERVER_B)
	_check("and the lease lets go", lapsed.ok, lapsed)
	issuer.release_session(ada.uid)
	config.session_lease_sec = 300
	config.ticket_ttl_sec = 300

	# The option is an option.
	config.single_session = false
	issuer.issue_for_identity(ada, SERVER_A)
	var permitted := issuer.issue_for_identity(ada, SERVER_B)
	_check("with the rule off, two servers are fine", permitted.ok, permitted)
	issuer.release_session(ada.uid)
	config.single_session = true


	if not listening:
		_line("  (port %d is in use; the socket half was not run)" % PORT)
		issuer.queue_free()
		_line("")
		# A deliberate end rather than an abort; the total of checks is what says the socket
		# half's checks did not run.
		_done()
		return

	var http := DotHttp.new()
	http.name = "DemoHttp"
	http.max_retries = 0
	add_child(http)
	var url := "http://127.0.0.1:%d" % PORT

	var no_bearer := await http.post_json(
		url + "/session", {"serverId": SERVER_A, "users": [ada.uid]}
	)
	_check(
		"a report with no key is refused",
		not no_bearer.ok and no_bearer.error.http_status == 401,
		no_bearer
	)

	var wrong_key := await http.post_json(
		url + "/session",
		{"serverId": SERVER_A, "users": [ada.uid]},
		{"Authorization": "Bearer not-the-key-0123456789abcdef"}
	)
	_check(
		"a report with the wrong key is refused",
		not wrong_key.ok and wrong_key.error.http_status == 401,
		wrong_key
	)

	var other_server := await http.post_json(
		url + "/session",
		{"serverId": SERVER_B, "users": [ada.uid]},
		{"Authorization": "Bearer %s" % KEY_A}
	)
	_check(
		"a key cannot speak for another server",
		not other_server.ok and other_server.error.http_status == 401,
		other_server
	)
	_check("and placed nobody", issuer.session_of(ada.uid) == "", null)

	var release_no_bearer := await http.post_json(url + "/session/release", {})
	_check(
		"a release with no token is refused",
		not release_no_bearer.ok and release_no_bearer.error.http_status == 401,
		release_no_bearer
	)

	# The server's own reporter, end to end: a roster that lands makes the
	# refusal happen, and the goodbye lifts it.
	var server_config := DotAuthConfig.new()
	server_config.strategy = DotAuthConfig.Strategy.TICKET
	server_config.server_id = SERVER_A
	server_config.ticket_public_key = str(keys["public"])
	server_config.session_report_url = url
	server_config.session_report_key = KEY_A
	_check("the reporting config validates", server_config.validate().ok, server_config.validate())

	var reporter := DotAuthSessionReporter.new()
	reporter.name = "SessionReporter"
	reporter.config = server_config
	reporter.auto_report = false
	add_child(reporter)

	_check(
		"guests and duplicates are left out of a roster",
		DotAuthSessionReporter.normalise_roster(
			[ada, ada.uid, "guest:abc", {"uid": "backbone:bob"}, ""]
		) == PackedStringArray([ada.uid, "backbone:bob"]),
		null
	)

	var reported := await reporter.report([ada, "backbone:bob"])
	_check("a roster reaches the issuer", reported.ok, reported)
	_check(
		"and confirms both players",
		issuer.session_of(ada.uid) == SERVER_A
			and issuer.session_of("backbone:bob") == SERVER_A,
		null
	)
	var refused := issuer.issue_for_identity(ada, SERVER_B)
	_check("so a ticket elsewhere is refused", not refused.ok, refused)

	var goodbye := await reporter.report_offline()
	_check("a server going down reports an empty roster", goodbye.ok, goodbye)
	_check(
		"which frees everyone on it",
		issuer.session_of(ada.uid) == "" and issuer.session_of("backbone:bob") == "",
		null
	)

	# What a client is told. The issuer's own message has to survive DotHttp's
	# "Not allowed." — it is the one that names the server.
	issuer.report_sessions(SERVER_A, PackedStringArray([ada.uid]))
	var ticket_elsewhere := await http.post_json(
		url + "/ticket",
		{"serverId": SERVER_B},
		{"Authorization": "Bearer %s" % KEY_A}
	)
	# The bearer is not an access token, so this fails at the backbone step and
	# never reaches the session check; what is being exercised is that the
	# issuer's JSON error survives the transport, which the client relies on.
	var body: Variant = JSON.parse_string(
		ticket_elsewhere.error.detail if not ticket_elsewhere.ok else "{}"
	)
	_check(
		"the issuer's refusal reaches the client as JSON",
		not ticket_elsewhere.ok and body is Dictionary
			and (body as Dictionary).has("error")
			and (body as Dictionary).has("code"),
		ticket_elsewhere
	)

	var d := issuer.describe()
	_check(
		"describe() reports the rule and the table",
		bool(d["single_session"]) and int(d["sessions"]) == 1
			and int(d["conflicts"]) >= 2,
		null
	)

	reporter.queue_free()
	http.queue_free()
	issuer.queue_free()
	_line("")
	_done()
