@tool
class_name DotLocalProfileClient
extends RefCounted

## The client half of [DotLocalProfiles]: the secrets this machine holds, per server.
##
## A local profile is a credential the SERVER issued, so the client's whole job is
## to keep it and present it next time. That is small, and it is also the half that
## is easy to get subtly wrong in a way nobody notices for months — hence a class
## rather than a paragraph of advice.
##
## [codeblock]
## var keeper := DotLocalProfileClient.at("user://local_profiles.dat")
## keeper.open()
##
## # Joining. Ask with what we hold, or ask for a new one.
## var credential := keeper.credential_for(server_id)
## if credential.is_empty():
##     credential = {"local_profile_new": {"name": chosen_name}}
##
## # The server answers a creation with the secret, exactly once.
## keeper.remember(server_id, id, secret, name)
## [/codeblock]
##
## [b]Keyed by SERVER, and that is the point.[/b] One file holding one secret would
## mean presenting server A's credential to server B — which fails, so the player
## would silently be issued a new profile on every server they alternate between and
## lose the previous one's secret in the process. It is also the property that makes
## these safe at all: a server learns nothing about a player's identity anywhere
## else, because there is nothing shared to learn.
##
## [b]Encrypted at rest, with the same caveat the token store carries.[/b] On desktop
## and mobile this is real protection against another user on the machine. On web the
## key is derived inside the same origin as the ciphertext, so anyone with devtools
## can recover both — it is tamper-evidence and obfuscation there, and a local
## profile is worth roughly what a save file is worth, which is the right amount of
## effort to spend on it.

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
		# A file we cannot read is treated as no file, not as a failure to open.
		#
		# The realistic causes are a cleared browser origin, a copied user
		# directory, or an encryption setting that changed — and in every one of
		# them the player's next join should mint a new profile rather than
		# refuse to start the game over a save file.
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


## The credential to present to [param server_id], or [code]{}[/code] if none.
##
## Empty means "this machine has never played here" and the caller should offer to
## make one — which is why it is an empty dictionary rather than a failure: not
## having an account yet is the normal first state, not an error.
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


## A per-installation passphrase.
##
## [method OS.get_unique_id] where the platform has one, a constant where it does
## not — which is web, where it would be pointless anyway because the key and the
## ciphertext share an origin. Deliberately not a secret the player types: a prompt
## to unlock a save file is a prompt nobody wants, and the threat this addresses is
## a curious sibling rather than a determined attacker.
static func _passphrase() -> String:
	var machine := OS.get_unique_id()

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


## The client store a [DotAuthConfig] describes: its
## [member DotAuthConfig.local_profile_client_path]. That knob existed from the
## start and nothing read it, so every client kept its secrets at the default path
## whatever the config said.
static func for_config(config: DotAuthConfig) -> DotLocalProfileClient:
	return DotLocalProfileClient.at(config.local_profile_client_path)
