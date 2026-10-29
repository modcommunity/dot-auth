@tool
class_name DotLocalProfileClient
extends RefCounted

## The client half of [DotLocalProfiles]: the secrets this machine holds, keyed by SERVER.
##
## Keyed by server so one server's credential is never presented to another. Encrypted at rest with the token store's caveat: on web the key shares an origin with the ciphertext, so it is obfuscation there. Usage: docs/rationale.md.

const CLIENT_CHANNEL := "auth.local-profile.client"

## Where the secrets live.
var path: String = "user://local_profiles.dat"

## Encrypt the file. See the class documentation for what that means on web.
var encrypt: bool = true

var _entries: Dictionary = {}
var _opened: bool = false


static func at(p_path: String) -> DotLocalProfileClient:
	var s := DotLocalProfileClient.new()
	s.path = p_path
	return s


func open() -> DotResult:
	if _opened:
		return DotResult.success(_entries.size())

	_entries.clear()
	_opened = true

	if not FileAccess.file_exists(path):
		return DotResult.success(0)

	var read: DotResult = (
		DotPaths.read_encrypted(path, _passphrase())
		if encrypt
		else DotPaths.read_text(path)
	)

	if not read.ok:
		# An unreadable file counts as no file: the next join mints a new profile rather than refusing to start.
		DotLog.warn(
			CLIENT_CHANNEL,
			"could not read stored local profiles; starting empty",
			{"why": read.error.message if read.error != null else "unknown"}
		)

		return DotResult.success(0)

	var text := (
		(read.value as PackedByteArray).get_string_from_utf8()
		if read.value is PackedByteArray
		else str(read.value)
	)

	var parsed: Variant = JSON.parse_string(text)

	if parsed is Dictionary:
		var rows: Variant = (parsed as Dictionary).get("servers", {})

		if rows is Dictionary:
			_entries = rows as Dictionary

	return DotResult.success(_entries.size())


## The credential to present to [param server_id], or [code]{}[/code] if none (the normal first state, not an error).
func credential_for(server_id: String) -> Dictionary:
	if not _opened:
		open()

	var entry: Variant = _entries.get(server_id, null)

	if not (entry is Dictionary):
		return {}

	var row := entry as Dictionary
	var id := str(row.get("id", ""))
	var secret := str(row.get("secret", ""))

	if id == "" or secret == "":
		return {}

	return {"local_profile": {"id": id, "secret": secret}}


## The display name held for a server, for showing "continue as …".
func name_for(server_id: String) -> String:
	var entry: Variant = _entries.get(server_id, null)

	return str((entry as Dictionary).get("name", "")) if entry is Dictionary else ""


func has_profile(server_id: String) -> bool:
	return not credential_for(server_id).is_empty()


## Stores what a server just issued. Call this the moment a creation is answered.
func remember(
	server_id: String,
	id: String,
	secret: String,
	name: String = ""
) -> DotResult:
	if not _opened:
		open()

	if server_id.strip_edges() == "" or id == "" or secret == "":
		return DotResult.fail(
			DotError.CODE_INVALID, "A profile needs a server, an id and a secret."
		)

	_entries[server_id] = {
		"id": id,
		"secret": secret,
		"name": name,
		"saved_at": int(Time.get_unix_time_from_system()),
	}

	# Written immediately rather than on exit. The secret is shown once and can
	# never be recovered, so a process that is killed before flushing has lost
	# that profile permanently — this is the one write that cannot wait.
	return _save()


## Forgets one server's profile. The player stays on the server; they are a stranger
## to it next time.
func forget(server_id: String) -> DotResult:
	if not _entries.has(server_id):
		return DotResult.success(false)

	_entries.erase(server_id)

	return _save()


func forget_all() -> DotResult:
	_entries.clear()

	return _save()


func _save() -> DotResult:
	var text := JSON.stringify({"version": 1, "servers": _entries})

	if not encrypt:
		return DotPaths.write_text(path, text)

	return DotPaths.write_encrypted(path, text.to_utf8_buffer(), _passphrase())


## A per-installation passphrase: the unique id where there is one, a constant on web (where it would be pointless). Not typed by the player.
static func _passphrase() -> String:
	var machine := DotPlatform.unique_id()

	return DotHash.sha256_text(
		"dot-auth:local-profiles:%s" % (machine if machine != "" else "web")
	)


func describe() -> Dictionary:
	return {
		"path": path,
		"open": _opened,
		"servers": _entries.size(),
		"encrypted": encrypt,
	}


## The client store a [DotAuthConfig] describes, from [member DotAuthConfig.local_profile_client_path].
static func for_config(config: DotAuthConfig) -> DotLocalProfileClient:
	return DotLocalProfileClient.at(config.local_profile_client_path)
