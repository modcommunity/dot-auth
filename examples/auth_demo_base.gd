## Base of auth_demo.gd: the suite counters and report helpers, and the local-profiles section.
## Path-based, no class_name: it exists to keep each script under the size budget.
extends Control

@onready var _output: RichTextLabel = $Output

var _entered := 0
var _completed := 0
var _passed := 0
var _failed := 0


## The loopback stubs answer from the main thread, so the client's reads must not wait on it.
func _init() -> void:
	ProjectSettings.set_setting("dot/http/use_threads", true)


func _section(title: String) -> void:
	_entered += 1
	_line(title)


## A section reached its last line. See [constant SECTIONS].
func _done() -> void:
	_completed += 1


func _check(what: String, passed: bool, res: DotResult) -> void:
	if passed:
		_passed += 1
		_line("  %-32s ok" % what)
		return

	_failed += 1
	var why := ""
	if res != null and not res.ok and res.error != null:
		why = " — %s" % res.error.message
	_line("  %-32s [b]FAILED[/b]%s" % [what, why])


func _line(text: String) -> void:
	print(text.replace("[b]", "").replace("[/b]", ""))
	if _output != null:
		_output.append_text(text + "\n")



## Accounts that live on one server and never reach a backbone.
## Every check targets one property: **the server issues the credential**. A
## create-and-read-back test would pass against a client-asserted identity too.
func _test_local_profiles() -> void:
	_section("[b]local profiles[/b]")

	var path := "user://dot_auth_test_profiles.json"
	var keeper_path := "user://dot_auth_test_profile_client.dat"
	if not _profiles_store_checks(path):
		return

	var state: Dictionary = await _profiles_server_checks()
	_profiles_client_checks(keeper_path, state["issued"])
	(state["server"] as Node).queue_free()

	DirAccess.remove_absolute(path)
	DirAccess.remove_absolute(keeper_path)
	DirAccess.remove_absolute(str(state["path"]))
	_done()


## The store half of the local-profiles section; false when no profile could be made.
func _profiles_store_checks(path: String) -> bool:
	DirAccess.remove_absolute(path)

	var store := DotLocalProfiles.at(path)
	_check("store opens with no file", store.open().ok, null)

	var made := store.create("Ashley")
	_check("a profile is created", made.ok, made)

	if not made.ok:
		return false

	var id := str((made.value as Dictionary)["id"])
	var secret := str((made.value as Dictionary)["secret"])

	# The id has to be usable as a user_key unchanged, or a local profile cannot
	# file a profile or an avatar through the same stores a backbone one does.
	_check(
		"the id is a usable player key",
		id.length() == DotLocalProfiles.ID_LENGTH
			and DotAvatarKeyShape.is_usable(id),
		null
	)

	_check("the right secret verifies", store.verify(id, secret).ok, null)

	# THE check. If a wrong secret verified, the whole scheme is a name check
	# with extra steps.
	var wrong := store.verify(id, "not-the-secret")
	_check(
		"a wrong secret does not",
		not wrong.ok and wrong.code() == DotError.CODE_AUTH,
		null
	)

	# An unknown id and a wrong secret must be indistinguishable, or an attacker
	# can enumerate which ids exist before guessing anything else.
	var unknown := store.verify("AAAAAAAAAAAAAAAAAAAAAA", secret)
	_check(
		"an unknown id answers exactly like a wrong secret",
		not unknown.ok and unknown.code() == wrong.code(),
		null
	)

	var traversal := store.verify("../../secrets", secret)
	_check("a malformed id never reaches a lookup", not traversal.ok, null)

	# The secret is stored hashed. A file that held usable credentials for
	# everybody who ever played would be the worst thing on the server's disk.
	var raw := DotPaths.read_text(path)
	_check(
		"the file holds no usable secret",
		raw.ok and not str(raw.value).contains(secret),
		null
	)

	var dup := store.create("ashley")
	_check(
		"a duplicate name is refused, case-insensitively",
		not dup.ok,
		null
	)

	_profiles_persistence_checks(path, id, secret)
	return true


## Restart survival, the client path from config, and the profile cap.
func _profiles_persistence_checks(path: String, id: String, secret: String) -> void:
	# It must survive a restart, or it is a session and not an account.
	# The CLIENT half's path comes from the config, not the default.
	var client_config := DotAuthConfig.new()
	client_config.local_profile_client_path = path + ".client"
	var client_store := DotLocalProfileClient.for_config(client_config)
	_check(
		"the client profile store honours the configured path",
		client_store != null and client_store.path == path + ".client",
		DotResult.success(client_store)
	)

	var reopened := DotLocalProfiles.at(path)
	_check("it reopens from disk", reopened.open().ok, null)
	_check("and the profile is still there", reopened.verify(id, secret).ok, null)

	var capped := DotLocalProfiles.at(path)
	capped.max_profiles = 1
	capped.open()
	var over := capped.create("Somebody Else")
	_check(
		"the cap refuses a profile beyond it",
		not over.ok and over.code() == DotError.CODE_QUOTA,
		null
	)


## The through-the-auth-server half; returns the server, the issued credential and its file.
func _profiles_server_checks() -> Dictionary:
	var config := DotAuthConfig.new()
	config.strategy = DotAuthConfig.Strategy.LOCAL
	config.local_accounts_path = "user://dot_auth_profile_strategy.json"
	config.allow_guests = false
	config.allow_local_profiles = true
	config.local_profiles_path = "user://dot_auth_test_profiles_server.json"

	DirAccess.remove_absolute(config.local_profiles_path)

	var server := DotAuthServer.new()
	server.name = "LocalProfileAuthServer"
	server.config = config
	server.config_file = ""
	server.register_service = false
	add_child(server)
	server.start()

	_check(
		"the config switch builds a provider",
		server.local_profiles() != null,
		null
	)

	# MUTATED, never reassigned: a lambda captures by value, so reassigning leaves
	# the outer dictionary empty, while a Dictionary mutation is seen outside.
	var issued := {}
	server.local_profiles().profile_created.connect(
		func(new_id: String, new_secret: String, _name: String) -> void:
			issued["id"] = new_id
			issued["secret"] = new_secret
	)

	var signed_up := await server.authenticate(
		{"local_profile_new": {"name": "Robin"}}, "peer1"
	)
	_check("a visitor signs up", signed_up.ok, signed_up)

	if signed_up.ok:
		var identity: DotAuthIdentity = signed_up.value
		_check(
			"and is not a guest — the server issued this one",
			not identity.is_guest,
			null
		)
		_check(
			"with a namespaced uid of its own",
			identity.uid.begins_with("profile:"),
			null
		)
		_check("named as they asked", identity.display_name == "Robin", null)

	# The secret reaches the game through a signal, never through the identity —
	# an identity is relayed to every other player in the match.
	_check("the secret is handed over once", issued.has("secret"), null)
	_check(
		"and is not on the identity, which is broadcast",
		signed_up.ok
			and not JSON.stringify(
				(signed_up.value as DotAuthIdentity).to_dict()
			).contains(str(issued.get("secret", "no-secret-was-issued"))),
		null
	)

	await _profiles_returning_checks(server, issued, signed_up)
	return {"server": server, "issued": issued, "path": config.local_profiles_path}


## A returning join, a forged secret, and credentials naming no provider.
func _profiles_returning_checks(server: DotAuthServer, issued: Dictionary, signed_up: DotResult) -> void:
	var returning := await server.authenticate(
		{"local_profile": {"id": issued["id"], "secret": issued["secret"]}},
		"peer2"
	)
	_check("and works on the next join", returning.ok, returning)
	_check(
		"as the same player",
		returning.ok
			and signed_up.ok
			and (returning.value as DotAuthIdentity).uid
				== (signed_up.value as DotAuthIdentity).uid,
		null
	)

	# A stolen id with a made-up secret is the attack, and guests are off, so it
	# must not fall through into being admitted anyway.
	var forged := await server.authenticate(
		{"local_profile": {"id": issued["id"], "secret": "guessed"}}, "peer3"
	)
	_check("a forged secret is refused", not forged.ok, null)

	# A credential naming no provider still reaches the configured strategy.
	var other := await server.authenticate(
		{"username": "nobody", "password": "x"}, "peer4"
	)
	_check("other credentials still fall through", not other.ok, null)


## The client-side keeper half.
func _profiles_client_checks(keeper_path: String, issued: Dictionary) -> void:
	DirAccess.remove_absolute(keeper_path)

	var keeper := DotLocalProfileClient.at(keeper_path)
	keeper.open()

	_check(
		"a server never played is not a failure, just empty",
		keeper.credential_for("eu-west-1").is_empty(),
		null
	)

	keeper.remember("eu-west-1", str(issued["id"]), str(issued["secret"]), "Robin")

	_check(
		"a remembered profile comes back as a credential",
		keeper.credential_for("eu-west-1").has("local_profile"),
		null
	)

	# Keyed by server, which is what stops one server's credential being offered
	# to another — and what stops a server learning anything about a player's
	# identity anywhere else.
	_check(
		"and only for the server that issued it",
		keeper.credential_for("us-east-2").is_empty(),
		null
	)

	var reloaded := DotLocalProfileClient.at(keeper_path)
	reloaded.open()
	_check(
		"it survives a restart of the client",
		reloaded.credential_for("eu-west-1").has("local_profile"),
		null
	)

	keeper.forget("eu-west-1")
	_check("forgetting one works", not keeper.has_profile("eu-west-1"), null)


## The shape check dot-user-avatar applies to a key, restated for the assertion.
## dot-auth cannot call `DotAvatarKey.is_usable`; that two addons which never
## import each other agree on a key's shape is what is checked.
class DotAvatarKeyShape:
	static func is_usable(key: String) -> bool:
		if key.length() < 8 or key.length() > 64:
			return false

		for i in range(key.length()):
			var c := key.unicode_at(i)
			var ok := (
				(c >= 65 and c <= 90)
				or (c >= 97 and c <= 122)
				or (c >= 48 and c <= 57)
				or c == 45
				or c == 95
			)
			if not ok:
				return false

		return true




## RSA keypair via dot-core's Crypto wrapper.
## Named oddly to avoid colliding with a dot-cloud class; only a local helper.
func DotCloudKeys_generate() -> Dictionary:
	var crypto := Crypto.new()
	var key := crypto.generate_rsa(2048)
	if key == null:
		return {}
	return {
		"private": key.save_to_string(false),
		"public": key.save_to_string(true),
	}


## Index of [param needle] in [param haystack], or -1.
## PackedByteArray has no subsequence find(), and searching decoded text differs.
func _find_bytes(haystack: PackedByteArray, needle: PackedByteArray) -> int:
	if needle.is_empty() or needle.size() > haystack.size():
		return -1

	for i in range(haystack.size() - needle.size() + 1):
		var matched := true
		for j in range(needle.size()):
			if haystack[i + j] != needle[j]:
				matched = false
				break
		if matched:
			return i

	return -1


func _launcher_stub_serve(tcp: TCPServer, seen: Array[Dictionary], spent: Array) -> Callable:
	var serve := func() -> void:
		while tcp.is_connection_available():
			var peer := tcp.take_connection()
			var raw := ""
			var deadline := Time.get_ticks_msec() + 3000
			while Time.get_ticks_msec() < deadline:
				peer.poll()
				var n := peer.get_available_bytes()
				if n > 0:
					raw += peer.get_utf8_string(n)
				var split := raw.find("\r\n\r\n")
				if split >= 0:
					var length := 0
					for h in raw.substr(0, split).split("\r\n"):
						if h.to_lower().begins_with("content-length:"):
							length = int(h.substr(15).strip_edges())
					if raw.to_utf8_buffer().size() - split - 4 >= length:
						break
				OS.delay_msec(2)
			var head := raw.substr(0, raw.find("\r\n"))
			var body: Variant = JSON.parse_string(raw.substr(raw.find("\r\n\r\n") + 4))
			seen.append({"line": head, "body": body})
			var code := str((body as Dictionary).get("code", "")) if body is Dictionary else ""
			var status := 400
			var answer := {"ok": false, "code": "invalid_grant", "message": "This play session has expired. Press Play again."}
			if code == "tmc_gh_good" and not spent[0]:
				spent[0] = true
				status = 200
				answer = {"ok": true, "data": {"accessToken": "game-access", "refreshToken": "game-refresh",
					"expiresIn": 900, "user": {"id": "u-ada", "name": "Ada", "username": "ada"}, "appId": 7}}
			var text := JSON.stringify(answer)
			peer.put_data(("HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
				% [status, text.to_utf8_buffer().size(), text]).to_utf8_buffer())
			peer.disconnect_from_host()
	return serve


func _trust_stub_serve(tcp: TCPServer, keys: Dictionary, id: String, phase: Dictionary, seen: Array[Dictionary]) -> Callable:
	var serve := func() -> void:
		while tcp.is_connection_available():
			var peer := tcp.take_connection()
			var raw := ""
			var deadline := Time.get_ticks_msec() + 3000
			while Time.get_ticks_msec() < deadline:
				peer.poll()
				var n := peer.get_available_bytes()
				if n > 0:
					raw += peer.get_utf8_string(n)
				var split := raw.find("\r\n\r\n")
				if split >= 0:
					var length := 0
					for h in raw.substr(0, split).split("\r\n"):
						if h.to_lower().begins_with("content-length:"):
							length = int(h.substr(15).strip_edges())
					if raw.to_utf8_buffer().size() - split - 4 >= length:
						break
				OS.delay_msec(2)
			var head := raw.substr(0, raw.find("\r\n"))
			var text_in := raw.substr(raw.find("\r\n\r\n") + 4)
			var body: Variant = JSON.parse_string(text_in) if text_in != "" else null
			seen.append({"line": head, "body": body})
			var answer: Dictionary = {"ok": false, "error": {"code": "unknown_address", "message": "No listed server has that address."}}
			var status := 404
			if head.begins_with("GET /api/app/v1/auth/ticket-keys "):
				status = 200
				answer = {"ok": true, "data": {"issuer": "tmc-site", "keys": [
					{"kid": "k1", "alg": "RS256", "pem": str(keys["public"])},
					{"kid": "hs", "alg": "HS256", "pem": str(keys["public"])},
					{"kid": "bad", "alg": "RS256", "pem": str(keys["private"])},
				] + phase["extra"], "revoked": phase["revoked"], "refreshSec": phase["refresh"]}}
			elif head.begins_with("POST /api/app/v1/auth/ticket ") and body is Dictionary \
					and str(body.get("address", "")) == "play.example.com:6005":
				status = 200
				answer = {"ok": true, "data": {"ticket": "t-for-6005", "expiresIn": 120, "serverId": id}}
			var text := JSON.stringify(answer)
			peer.put_data(("HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
				% [status, text.to_utf8_buffer().size(), text]).to_utf8_buffer())
			peer.disconnect_from_host()
	return serve
