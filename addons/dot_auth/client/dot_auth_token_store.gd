class_name DotAuthTokenStore
extends RefCounted

## Persists the client's credential pair between runs.
##
## Holds the rotating refresh token, which is the thing that means "stay signed
## in". Losing it costs a re-login; leaking it is a full account takeover until it
## is rotated or revoked, so it is encrypted at rest where that means anything.
##
## [b]Honest limits of the encryption.[/b] The passphrase is derived from a
## per-install random salt stored beside the ciphertext plus a device-stable
## string. Against another user on the same machine reading the file, that works.
## Against the machine's own owner, or anything running as the same user, it does
## not — the key is right there. On web it is weaker still: everything lives in
## the same origin, so devtools recovers both halves.
##
## That is not a reason to skip it. It raises the cost of the common cases (a
## synced backup, a shared PC, a stray file in a support bundle) and makes
## tampering detectable. It is a reason not to claim more than it does.

const CHANNEL := "auth.store"

## Bumped when the stored shape changes.
const FORMAT_VERSION := 1

var path: String
var encrypt: bool

var _access_token: String = ""
var _refresh_token: String = ""
var _expires_at: int = 0
var _identity: DotAuthIdentity = null
var _loaded: bool = false


func _init(p_path: String, p_encrypt: bool = true) -> void:
	path = p_path
	encrypt = p_encrypt


# --- Access ----------------------------------------------------------------

func access_token() -> String:
	return _access_token


func refresh_token() -> String:
	return _refresh_token


func identity() -> DotAuthIdentity:
	return _identity


func has_credentials() -> bool:
	return _refresh_token != ""


## Whether the access token is usable for at least [param margin_sec] longer.
##
## Treating a token that expires in two seconds as valid produces a request that
## fails for a reason the caller has already ruled out.
func is_access_valid(margin_sec: float = 0.0) -> bool:
	if _access_token == "":
		return false
	if _expires_at <= 0:
		return true
	return int(Time.get_unix_time_from_system()) + int(margin_sec) < _expires_at


func expires_in() -> int:
	if _expires_at <= 0:
		return -1
	return maxi(0, _expires_at - int(Time.get_unix_time_from_system()))


# --- Mutation --------------------------------------------------------------

## Records a credential pair from the backbone's `TokenResponse`.
func set_tokens(
	access: String,
	refresh: String,
	expires_in_sec: int,
	p_identity: DotAuthIdentity = null
) -> DotResult:
	_access_token = access
	_refresh_token = refresh
	_expires_at = int(Time.get_unix_time_from_system()) + expires_in_sec
	if p_identity != null:
		_identity = p_identity

	return save()


## Forgets everything and deletes the file.
##
## Used on sign-out and on `token_reuse`, where the backbone has already
## invalidated the family and keeping a dead token would only produce confusing
## failures on the next launch.
func clear() -> void:
	_access_token = ""
	_refresh_token = ""
	_expires_at = 0
	_identity = null

	if FileAccess.file_exists(path):
		DirAccess.remove_absolute(path)
	var salt := _salt_path()
	if FileAccess.file_exists(salt):
		DirAccess.remove_absolute(salt)

	DotWeb.sync_filesystem()
	DotLog.debug(CHANNEL, "credentials cleared")


# --- Persistence -----------------------------------------------------------

func load_tokens() -> DotResult:
	_loaded = true

	if not FileAccess.file_exists(path):
		return DotResult.success(false)

	var read: DotResult
	if encrypt:
		read = DotPaths.read_encrypted(path, _passphrase())
	else:
		read = DotPaths.read_bytes(path)

	if not read.ok:
		# A store we cannot read is treated as no store: the overwhelmingly
		# common cause is a device-identity change, not an attack, and a player
		# who has to sign in again is a far better outcome than a launch that
		# refuses to proceed.
		DotLog.info(
			CHANNEL,
			"stored credentials could not be read; signing in again",
			{"why": read.error.code}
		)
		clear()
		return DotResult.success(false)

	var bytes: PackedByteArray = read.value
	var parsed: Variant = JSON.parse_string(bytes.get_string_from_utf8())

	if not (parsed is Dictionary):
		clear()
		return DotResult.success(false)

	var d := parsed as Dictionary

	if int(d.get("version", 0)) != FORMAT_VERSION:
		DotLog.info(CHANNEL, "credential format changed; signing in again")
		clear()
		return DotResult.success(false)

	_access_token = str(d.get("access_token", ""))
	_refresh_token = str(d.get("refresh_token", ""))
	_expires_at = int(d.get("expires_at", 0))

	if d.get("identity") is Dictionary:
		_identity = DotAuthIdentity.from_dict(d["identity"])

	DotLog.debug(
		CHANNEL,
		"credentials loaded",
		{
			"user": _identity.label() if _identity != null else "<unknown>",
			"access_valid": is_access_valid(),
		}
	)

	return DotResult.success(has_credentials())


func save() -> DotResult:
	var payload := {
		"version": FORMAT_VERSION,
		"access_token": _access_token,
		"refresh_token": _refresh_token,
		"expires_at": _expires_at,
	}

	if _identity != null:
		payload["identity"] = _identity.to_dict()

	var bytes := JSON.stringify(payload).to_utf8_buffer()

	if encrypt:
		return DotPaths.write_encrypted(path, bytes, _passphrase())
	return DotPaths.write_bytes(path, bytes)


func is_loaded() -> bool:
	return _loaded


# --- Key derivation --------------------------------------------------------

## Passphrase for the encrypted store.
##
## Two ingredients: a random per-install salt written next to the store, and a
## device-stable string. The salt means two installs never share a key even with
## identical device identity; the device string means copying the pair to another
## machine does not produce a readable store.
func _passphrase() -> String:
	return DotHash.sha256_text("dot-auth/v1|%s|%s" % [_salt(), _device_seed()])


func _salt_path() -> String:
	return path + ".salt"


func _salt() -> String:
	var salt_file := _salt_path()

	if FileAccess.file_exists(salt_file):
		var read := DotPaths.read_text(salt_file)
		if read.ok and str(read.value).length() >= 16:
			return str(read.value)

	var salt := DotHash.random_hex(32)
	DotPaths.write_text(salt_file, salt)
	return salt


## Something stable about this device.
##
## Deliberately coarse. A unique-id API that changes on OS update would lock
## players out of their own store on a routine upgrade, and the failure mode of
## being too stable here is only that the file is readable on a machine that can
## already read the salt sitting next to it.
func _device_seed() -> String:
	var parts := PackedStringArray()
	parts.append(OS.get_name())

	var uid := OS.get_unique_id()
	if uid != "":
		parts.append(uid)
	else:
		# Web and some sandboxes have no unique id. The salt still varies per
		# install, which is what actually separates two users on one machine.
		parts.append("no-device-id")

	return "|".join(parts)


func describe() -> Dictionary:
	return {
		"path": path,
		"encrypted": encrypt,
		"has_refresh": _refresh_token != "",
		"access_valid": is_access_valid(),
		"expires_in": expires_in(),
		"user": _identity.label() if _identity != null else "",
	}
