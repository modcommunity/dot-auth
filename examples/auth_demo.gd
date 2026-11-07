extends "res://examples/auth_demo_accounts.gd"

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
const CHECKS := 211



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
	# Address binding (default off): refuse a reply that does not echo addressVerified.
	_check("address binding is off by default", not client_config.bind_join_address, null)
	var ok_reply := {"token": "tmc_jt_abc", "addressVerified": true}
	var old_reply := {"token": "tmc_jt_abc"}
	_check("off: an old reply is accepted",
		client.join_token_from_reply(old_reply, "server:42", false).ok, null)
	_check("on: a verified reply is accepted",
		client.join_token_from_reply(ok_reply, "server:42", true).ok, null)
	var unverified: DotResult = client.join_token_from_reply(old_reply, "server:42", true)
	_check("on: a reply lacking addressVerified is refused",
		not unverified.ok and unverified.error.code == DotError.CODE_FORBIDDEN, unverified)
	_check("on: addressVerified false is refused",
		not client.join_token_from_reply({"token": "tmc_jt_abc", "addressVerified": false}, "server:42", true).ok, null)
	_check("on: a non-object reply is refused",
		not client.join_token_from_reply("x", "server:42", true).ok, null)
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



func _finish() -> void:
	if DotPlatform.is_headless():
		await get_tree().process_frame
		get_tree().quit(1 if _failed > 0 else 0)



## One account, one seat, with every way a session can end: server report, player release, lease expiry.
##
## The roster path runs over a real socket through the issuer's own listener, the one part a unit call cannot reach.
func _check_session_config_refusals(port: int) -> void:
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
	unkeyed.session_report_url = "http://127.0.0.1:%d" % port
	_check(
		"reporting without a key is refused",
		not unkeyed.validate().ok,
		null
	)


func _test_single_session(keys: Dictionary) -> void:
	_section("[b]single session[/b]")

	const PORT := 18787
	const KEY_A := "server-a-key-0123456789abcdef"

	var ada := DotAuthIdentity.new()
	ada.uid = "backbone:ada"
	ada.provider = "backbone"
	ada.provider_id = "ada"
	ada.display_name = "Ada"


	_check_session_config_refusals(PORT)

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

	var by_address := await http.post_json(
		url + "/ticket",
		{"address": "play.example.com:6005", "nonce": "n"},
		{"Authorization": "Bearer x"}
	)
	_check(
		"an address/nonce request is refused 400 as id-only",
		not by_address.ok and by_address.error.http_status == 400,
		by_address
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
