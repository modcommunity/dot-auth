## PKCE, local accounts, refusal logging, admin mapping, token store and provider sections of auth_demo.gd.
## Path-based, no class_name: it exists to keep each script under the size budget.
extends "res://examples/auth_demo_trust.gd"


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

	await _refusals_run_escalates(server, records)

	server.queue_free()
	DirAccess.remove_absolute(path)

	await _refusals_verifier_down(records)

	DotLog.signals().record.disconnect(capture)
	DotLog.clear_channel_level(DotAuthServer.CHANNEL)
	DotLog.print_to_stdout = printing
	_line("")
	_done()



func _refusals_run_escalates(server: DotAuthServer, records: Array[Dictionary]) -> void:
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


func _refusals_verifier_down(records: Array[Dictionary]) -> void:
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



