extends Control

## Exercises the parts of dot-auth that can be tested without a backbone.
##
## The device flow needs a live backbone and a human clicking Approve, so it is
## not covered here. Everything security-critical is:
##
## - ticket minting and offline verification;
## - audience scoping — a ticket for server A refused by server B;
## - replay refusal — the same ticket presented twice;
## - expiry, and clock-skew leeway;
## - tamper detection on the payload;
## - algorithm confusion — an HS256 token offered where RS256 is expected;
## - PKCE challenge derivation;
## - local accounts, with a wrong password and an unknown user;
## - the admin-source mapping from site groups to server flags;
## - token-store round trip through encryption;
## - one seat per account — a ticket refused while the player is on another
##   server, and every way a session ends, including over a real socket.
##
## [codeblock]
## godot --headless --path . res://examples/auth_demo.tscn
## [/codeblock]

const SERVER_A := "eu-west-1"
const SERVER_B := "us-east-2"

@onready var _output: RichTextLabel = $Output

var _passed := 0
var _failed := 0


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
	_test_admin_source()
	_test_token_store()
	await _test_providers()
	await _test_local_profiles()
	await _test_single_session(keys)

	_line("")
	_line("[b]%d passed, %d failed[/b]" % [_passed, _failed])
	_finish()


# --- Tickets ---------------------------------------------------------------

func _test_tickets(keys: Dictionary) -> void:
	_line("[b]connect tickets[/b]")

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


# --- PKCE ------------------------------------------------------------------

func _test_pkce() -> void:
	_line("[b]PKCE[/b]")

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


# --- Local accounts --------------------------------------------------------

func _test_local_accounts() -> void:
	_line("[b]local accounts[/b]")

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


# --- Admin source ----------------------------------------------------------

func _test_admin_source() -> void:
	_line("[b]admin mapping[/b]")

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


# --- Token store -----------------------------------------------------------

func _test_token_store() -> void:
	_line("[b]token store[/b]")

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

	# The refresh token must not be recoverable from the file. Compared as raw
	# bytes rather than decoded text: ciphertext is not valid UTF-8, and decoding
	# it would both spam the log and risk a replacement character hiding a
	# substring that really is there.
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
	_line("[b]custom auth providers[/b]")

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


# --- Helpers ---------------------------------------------------------------

## RSA keypair via dot-core's Crypto wrapper.
##
## Named oddly to avoid colliding with a dot-cloud class this project does not
## have; it is only a local helper.
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
##
## PackedByteArray has no find() for subsequences, and searching decoded text is
## not equivalent — see the caller.
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


func _finish() -> void:
	if DotPlatform.is_headless():
		await get_tree().process_frame
		get_tree().quit(1 if _failed > 0 else 0)


func _line(text: String) -> void:
	print(text.replace("[b]", "").replace("[/b]", ""))
	if _output != null:
		_output.append_text(text + "\n")


# --- Local profiles --------------------------------------------------------

## Accounts that live on one server and never reach a backbone.
##
## Every check here is about the property that makes them worth having rather than
## dangerous: **the server issues the credential**. A test that only proved "a
## profile can be created and read back" would pass just as happily against the
## design where the client asserts its own identity, which is the design this
## replaces.
func _test_local_profiles() -> void:
	_line("[b]local profiles[/b]")

	var path := "user://dot_auth_test_profiles.json"
	DirAccess.remove_absolute(path)

	var store := DotLocalProfiles.at(path)
	_check("store opens with no file", store.open().ok, null)

	var made := store.create("Ashley")
	_check("a profile is created", made.ok, made)

	if not made.ok:
		return

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

	# It must survive a restart, or it is a session and not an account.
	# The CLIENT half's path comes from the config, which nothing read until
	# for_config existed — every client kept its secrets at the default path
	# whatever the config said.
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

	# --- Through the auth server ------------------------------------------

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

	# MUTATED, never reassigned. A GDScript lambda captures by value, so
	# `issued = {...}` inside one rebinds the captured copy and the outer
	# dictionary stays empty — the signal looks as though it never fired.
	# Mutating works because a Dictionary is a reference.
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

	# --- The client half ---------------------------------------------------

	var keeper_path := "user://dot_auth_test_profile_client.dat"
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

	server.queue_free()

	DirAccess.remove_absolute(path)
	DirAccess.remove_absolute(keeper_path)
	DirAccess.remove_absolute(config.local_profiles_path)


## The shape check dot-user-avatar applies to a key, restated for the assertion.
##
## dot-auth does not depend on dot-user-avatar, so this cannot call
## `DotAvatarKey.is_usable` — and that is exactly the interoperation being checked:
## two addons that never import each other agree on what a player key looks like.
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


# --- Single session --------------------------------------------------------

## One account, one seat.
##
## The issuer is the only participant that sees every server, so the rule lives
## there, and every way a session can end is exercised: the server reporting the
## player gone, the player releasing it, and the lease running out. The roster
## path runs over a real socket through the issuer's own listener, because the
## endpoint is the one part of this a unit call cannot reach — and the family's
## record says the bug is always in the part nothing ran.
func _test_single_session(keys: Dictionary) -> void:
	_line("[b]single session[/b]")

	const PORT := 18787
	const KEY_A := "server-a-key-0123456789abcdef"

	var ada := DotAuthIdentity.new()
	ada.uid = "backbone:ada"
	ada.provider = "backbone"
	ada.provider_id = "ada"
	ada.display_name = "Ada"

	# --- Configuration invariants ------------------------------------------

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

	# --- The issuer --------------------------------------------------------

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

	# --- Over the socket ---------------------------------------------------

	if not listening:
		_line("  (port %d is in use; the socket half was not run)" % PORT)
		issuer.queue_free()
		_line("")
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
