@tool
## Base of [DotAuthServer]: local accounts, guests and requested display names.
## Path-based, no class_name: it exists to keep each script under the size budget.
extends "res://addons/dot_auth/server/dot_auth_server_trust.gd"

## Local accounts, for [constant DotAuthConfig.Strategy.LOCAL].
var _accounts: Dictionary = {}


## Checks a username and password against the local accounts file.
func _authenticate_local(credential: Dictionary) -> DotResult:
	var username := str(credential.get("username", "")).to_lower()
	var password := str(credential.get("password", ""))

	if username == "" or password == "":
		return DotResult.fail(
			DotError.CODE_AUTH, "A username and password are required."
		)

	if not _accounts.has(username):
		# The same message and the same work as a wrong password, so the response
		# does not reveal which usernames exist. The hash runs either way.
		DotHash.sha256_text(password)
		return DotResult.fail(
			DotError.CODE_AUTH, "Incorrect username or password."
		)

	var account: Dictionary = _accounts[username]
	var salt := str(account.get("salt", ""))
	var expected := str(account.get("hash", ""))
	var actual := hash_password(password, salt)

	if not DotHash.constant_time_equal_hex(actual, expected):
		return DotResult.fail(
			DotError.CODE_AUTH, "Incorrect username or password."
		)

	var identity := DotAuthIdentity.new()
	identity.provider = "local"
	identity.provider_id = username
	identity.uid = "local:%s" % username
	identity.username = username
	identity.display_name = str(account.get("display_name", username))
	identity.role = str(account.get("role", ""))
	identity.authenticated_at = int(Time.get_unix_time_from_system())

	if account.get("claims") is Dictionary:
		identity.claims = account["claims"]

	_apply_requested_name(identity, credential)

	DotLog.info(
		CHANNEL, "authenticated locally", {"user": identity.label()}
	)

	return DotResult.success(identity)


func _make_guest(credential: Dictionary) -> DotResult:
	var device_id := str(credential.get("device_id", ""))
	if device_id == "":
		# Random rather than derived: without a device id there is nothing stable
		# to derive from, and a shared constant would make every guest the same
		# person as far as mutes and kicks are concerned.
		device_id = DotHash.random_hex(8)

	var name := str(credential.get("name", ""))
	var identity := DotAuthIdentity.guest(
		DotHash.sha256_text(device_id).substr(0, 16), name
	)

	return DotResult.success(identity)


## Applies a client-requested display name, when the identity has none of its own.
## Only guests may name themselves: a signed-in player showing an arbitrary name is
## impersonation, and the account name is all a server can vouch for.
func _apply_requested_name(
	identity: DotAuthIdentity,
	credential: Dictionary
) -> void:
	var requested := str(credential.get("name", "")).strip_edges()
	if requested == "":
		return

	if not identity.is_guest:
		return

	identity.display_name = requested.substr(0, 64)



## Salted SHA-256 of a password.
## [b]Not adequate for a public account system[/b] (Godot ships no argon2 or bcrypt);
## it is for LAN and development. Real users belong on the backbone.
static func hash_password(password: String, salt: String) -> String:
	var out := salt + password
	# A few thousand rounds is not key stretching in any serious sense, but it
	# does make an offline attack against this file cost something.
	for _i in range(4096):
		out = DotHash.sha256_text(out)
	return out


func _load_accounts() -> DotResult:
	_accounts.clear()

	if not FileAccess.file_exists(config.local_accounts_path):
		DotLog.info(
			CHANNEL,
			"no local accounts file; nobody can sign in with LOCAL",
			{"path": config.local_accounts_path}
		)
		return DotResult.success(0)

	var read := DotPaths.read_json(config.local_accounts_path)
	if not read.ok:
		return read.wrap("Could not read the local accounts file.")

	var data: Variant = read.value
	if not (data is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE,
			"The accounts file must be a JSON object of username -> account."
		)

	for username in (data as Dictionary):
		var entry: Variant = (data as Dictionary)[username]
		if entry is Dictionary:
			_accounts[str(username).to_lower()] = entry

	DotLog.info(
		CHANNEL, "local accounts loaded", {"count": _accounts.size()}
	)

	return DotResult.success(_accounts.size())


## Adds or replaces a local account and writes the file.
##
## For an admin console command. Never expose it to unauthenticated clients.
func upsert_local_account(
	username: String,
	password: String,
	display_name: String = "",
	role: String = ""
) -> DotResult:
	var salt := DotHash.random_hex(16)

	_accounts[username.to_lower()] = {
		"salt": salt,
		"hash": hash_password(password, salt),
		"display_name": display_name if display_name != "" else username,
		"role": role,
	}

	var written := DotPaths.write_json(
		config.local_accounts_path, _accounts
	)
	if not written.ok:
		return written

	DotLog.info(CHANNEL, "local account saved", {"user": username})
	return DotResult.success(username)


func remove_local_account(username: String) -> DotResult:
	if not _accounts.erase(username.to_lower()):
		return DotResult.fail(
			DotError.CODE_INVALID, "No such account.", username
		)
	return DotPaths.write_json(config.local_accounts_path, _accounts)
