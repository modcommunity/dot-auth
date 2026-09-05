@tool
class_name DotLocalProfiles
extends RefCounted

## Accounts that live on ONE server and never reach a backbone.
##
## For the deployment that has no cloud and wants one anyway: a LAN server, a
## friends' server, a game shipped without accounts, a creator who would rather not
## depend on anybody's identity service. A visitor arrives, names themselves, and is
## the same player next week — with a profile and an avatar filed on that server's
## own disk.
##
## [b]The identity is a credential this server ISSUES, not something the client
## claims.[/b] That is the whole design, and every other option was worse:
##
## - [b]A name.[/b] What an offline mode does — the uuid is a hash of the
##   name — and the well-known consequence is that anyone who types your name is
##   you. Fine among six friends, indefensible on a public server.
## - [b]A machine id.[/b] [method device_hint] exists and is deliberately NOT the
##   identity. [method OS.get_unique_id] returns nothing at all on web and iOS, and
##   a browser is a first-class target here; it is also just a string the client
##   sends, so it is exactly as forgeable as a name while looking authoritative.
##   And it is stable across ACCOUNTS as well as installs, so two people sharing a
##   machine are one player.
## - [b]A password.[/b] Puts a login form in front of somebody who wanted to play,
##   and lands a password store on a game server. [method DotAuthServer.hash_password]
##   already says why that is not something to be proud of.
##
## So: on first join the server mints an id and a 32-byte secret, stores only a
## salted hash of the secret, and hands the secret to the client once. The client
## keeps it per server and presents it next time. A session cookie, essentially,
## and for the same reasons.
##
## [b]The secret is scoped to one server.[/b] A leak is that server's problem and
## nobody else's — the same property the whole platform rests on, and the reason
## this is not "a local account" in the sense of one that works everywhere.
##
## [codeblock]
## var profiles := DotLocalProfiles.at("user://local_profiles.json")
## profiles.open()
##
## var made := profiles.create("Ashley")          # first join
## # -> {"id": "sWrM4ym4beWFH0Nx1a", "secret": "…"}  send the secret to that client
##
## var who := profiles.verify(id, secret)         # every join after
## [/codeblock]
##
## [b]The id is usable as a `user_key` unchanged.[/b] 22 base64url characters, the
## same shape [DotUserScope] derives and [code]DotAvatarKey.is_usable[/code] accepts
## — so a local profile files a profile and an avatar through exactly the same store
## interfaces a backbone-backed one does, and nothing downstream branches on which
## kind of account it is.

const CHANNEL := "auth.local-profiles"

## Characters in an id. Matches [code]DotUserScope.ID_LENGTH[/code].
const ID_LENGTH := 22

## Bytes of secret. 256 bits, because it is a bearer credential.
const SECRET_BYTES := 32

## Rounds of hashing over the stored secret.
##
## The secret is 256 random bits, so this is not protecting a guessable password
## the way [method DotAuthServer.hash_password] is trying to — an offline attack on
## a full-entropy secret does not terminate. It is here so that a leaked file is not
## a list of usable credentials, and one round would do; a few thousand costs
## nothing on a join and closes the case where an operator lets somebody choose
## their own secret.
const HASH_ROUNDS := 4096

## Longest display name a profile may carry.
const MAX_NAME := 32

## Shortest. One character is a name; zero is a blank row nobody can tell apart.
const MIN_NAME := 2

## Where the file lives.
var path: String = "user://local_profiles.json"

## Refuse to create more than this many. 0 removes the limit.
##
## A server that lets an unauthenticated visitor write a row has handed the disk to
## the internet. The cap is the backstop; a rate limit on the connection is the
## first line, and [DotAuthServer] already has one.
var max_profiles: int = 5000

## Whether two profiles may share a display name.
##
## Off by default. The name is the only thing other players see, so two "Ashley"s
## is impersonation with extra steps — the exact problem issuing a secret was meant
## to solve, reintroduced at the layer people actually look at.
var allow_duplicate_names: bool = false

var _profiles: Dictionary = {}
var _by_name: Dictionary = {}
var _opened: bool = false
var _dirty: bool = false


static func at(p_path: String) -> DotLocalProfiles:
	var s := DotLocalProfiles.new()
	s.path = p_path
	return s


## A machine identifier, where the platform has one.
##
## [b]Never an identity — a hint.[/b] Empty on web and iOS, which are platforms
## this family targets, so anything that required it would simply not work there.
## It is also client-side, so a client can send whatever it likes. Stored on
## creation and compared on verify only to LOG that a profile moved machine, which
## is a useful thing for an operator to see and a terrible thing to enforce: people
## replace computers, and a browser clears its storage on its own schedule.
static func device_hint() -> String:
	var id := OS.get_unique_id()

	return DotHash.sha256_text(id).substr(0, 16) if id != "" else ""


func open() -> DotResult:
	if _opened:
		return DotResult.success(_profiles.size())

	_profiles.clear()
	_by_name.clear()

	if not FileAccess.file_exists(path):
		# Not a failure: the first server to run this has no file, and creating
		# one before anybody has a profile would leave an empty file behind for
		# a feature the operator may never switch on.
		_opened = true

		DotLog.info(CHANNEL, "no local profiles file yet", {"path": path})

		return DotResult.success(0)

	var read := DotPaths.read_json(path)

	if not read.ok:
		return read.wrap("Could not read the local profiles file.")

	var data: Variant = read.value

	if not (data is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE,
			"The local profiles file is not an object.",
			path
		)

	var rows: Variant = (data as Dictionary).get("profiles", [])

	if rows is Array:
		for entry in (rows as Array):
			if not (entry is Dictionary):
				continue

			var row := entry as Dictionary
			var id := str(row.get("id", ""))

			# A row with no id cannot be looked up and cannot be verified, so it
			# is dropped rather than kept and counted. Loudly: it means the file
			# was hand-edited, and the next write would silently discard it.
			if id == "" or not _is_usable_id(id):
				DotLog.warn(
					CHANNEL, "dropping a local profile with an unusable id"
				)
				continue

			_profiles[id] = row
			_remember_name(id, str(row.get("name", "")))

	_opened = true

	DotLog.info(
		CHANNEL, "local profiles loaded", {"count": _profiles.size()}
	)

	return DotResult.success(_profiles.size())


func is_open() -> bool:
	return _opened


func count() -> int:
	return _profiles.size()


# --- Creating --------------------------------------------------------------

## Mints a profile and returns [code]{"id": …, "secret": …}[/code].
##
## [b]The secret is returned exactly once and is never recoverable.[/b] Only its
## hash is stored, so a caller that drops it has locked that profile out for good —
## which is the correct trade, because the alternative is a server holding a list of
## usable credentials for everybody who ever played on it.
func create(name: String, hint: String = "") -> DotResult:
	if not _opened:
		var opened := open()
		if not opened.ok:
			return opened

	var clean := _clean_name(name)

	if not clean.ok:
		return clean

	var display: String = clean.value

	if not allow_duplicate_names and _by_name.has(display.to_lower()):
		return DotResult.fail(
			DotError.CODE_INVALID,
			"Somebody on this server already uses that name.",
			display
		)

	if max_profiles > 0 and _profiles.size() >= max_profiles:
		return DotResult.fail(
			DotError.CODE_QUOTA,
			"This server is not accepting new profiles.",
			"%d of %d" % [_profiles.size(), max_profiles]
		)

	var id := _mint_id()
	var secret := DotHash.random_token(SECRET_BYTES)
	var salt := DotHash.random_hex(16)

	_profiles[id] = {
		"id": id,
		"name": display,
		"salt": salt,
		"hash": _hash_secret(secret, salt),
		"device": hint,
		"created_at": int(Time.get_unix_time_from_system()),
		"seen_at": int(Time.get_unix_time_from_system()),
	}

	_remember_name(id, display)
	_dirty = true

	var saved := save()

	if not saved.ok:
		# Rolled back rather than returned: handing a client a secret for a
		# profile that is not on disk means it works until the process restarts
		# and then silently is not them any more.
		_profiles.erase(id)
		_forget_name(display)

		return saved.wrap("Could not store the new profile.")

	DotLog.info(CHANNEL, "local profile created", {"id": id, "name": display})

	return DotResult.success({"id": id, "secret": secret})


# --- Verifying -------------------------------------------------------------

## Checks a presented (id, secret) pair and returns the stored row.
##
## Constant-time on the secret, because the alternative leaks how many leading
## characters were right and turns guessing into a few hundred attempts per
## character rather than 2^256 overall.
func verify(id: String, secret: String, hint: String = "") -> DotResult:
	if not _opened:
		var opened := open()
		if not opened.ok:
			return opened

	# Structural first, so a malformed id never reaches a dictionary lookup that
	# a caller might later turn into a file path.
	if not _is_usable_id(id):
		return DotResult.fail(DotError.CODE_INVALID, "That is not a profile id.")

	var row: Variant = _profiles.get(id, null)

	# An unknown id and a wrong secret answer the SAME way. Distinguishing them
	# tells somebody enumerating ids which ones exist, which is the list they
	# would need before guessing anything else.
	if not (row is Dictionary):
		return DotResult.fail(
			DotError.CODE_AUTH, "That profile could not be verified."
		)

	var stored := row as Dictionary
	var want := str(stored.get("hash", ""))
	var salt := str(stored.get("salt", ""))

	if want == "" or not DotHash.constant_time_equal_hex(
		want, _hash_secret(secret, salt)
	):
		return DotResult.fail(
			DotError.CODE_AUTH, "That profile could not be verified."
		)

	var known := str(stored.get("device", ""))

	# Logged, never enforced. See device_hint(): people change machines and
	# browsers clear storage, so refusing here would lock players out of their
	# own profiles for doing something completely normal.
	if hint != "" and known != "" and hint != known:
		DotLog.info(
			CHANNEL,
			"a local profile signed in from a different device",
			{"id": id}
		)

	stored["seen_at"] = int(Time.get_unix_time_from_system())
	_dirty = true

	return DotResult.success(stored)


## Changes a profile's display name. Requires the secret, like every other write.
func rename(id: String, secret: String, name: String) -> DotResult:
	var found := verify(id, secret)

	if not found.ok:
		return found

	var clean := _clean_name(name)

	if not clean.ok:
		return clean

	var display: String = clean.value
	var row := found.value as Dictionary
	var was := str(row.get("name", ""))

	if display.to_lower() != was.to_lower():
		if not allow_duplicate_names and _by_name.has(display.to_lower()):
			return DotResult.fail(
				DotError.CODE_INVALID,
				"Somebody on this server already uses that name.",
				display
			)

		_forget_name(was)
		_remember_name(id, display)

	row["name"] = display
	_dirty = true

	return save()


## Forgets a profile. The caller decides whether an operator or the owner may.
##
## Deliberately does NOT require the secret: this is the endpoint a server console
## needs, and an operator removing an abusive player's profile does not have their
## credential. Anything reachable by a PLAYER must check the secret first.
func remove(id: String) -> DotResult:
	if not _profiles.has(id):
		return DotResult.success(false)

	_forget_name(str((_profiles[id] as Dictionary).get("name", "")))
	_profiles.erase(id)
	_dirty = true

	var saved := save()

	return saved if not saved.ok else DotResult.success(true)


# --- Storage ---------------------------------------------------------------

## Writes the file when anything has changed.
##
## Through [method DotPaths.write_json], which writes a temporary file and renames
## over the target — so an interrupted write loses the change rather than the whole
## file, which for a file holding every account on the server is the difference
## between a bad day and a lost one.
func save() -> DotResult:
	if not _dirty:
		return DotResult.success(false)

	var rows: Array = []

	for id in _profiles:
		rows.append(_profiles[id])

	var written := DotPaths.write_json(
		path, {"version": 1, "profiles": rows}, true
	)

	if not written.ok:
		return written.wrap("Could not write the local profiles file.")

	_dirty = false

	return DotResult.success(true)


func close() -> void:
	save()
	_opened = false


# --- Internals -------------------------------------------------------------

func _mint_id() -> String:
	# Loops because a collision, however unlikely at 132 bits, would overwrite
	# somebody's profile — and "however unlikely" is not a thing to reason about
	# when the check is one dictionary lookup.
	for _attempt in range(8):
		var id := DotHash.base64url_encode(
			DotHash.random_bytes(24)
		).substr(0, ID_LENGTH)

		if not _profiles.has(id):
			return id

	return DotHash.base64url_encode(DotHash.random_bytes(24)).substr(0, ID_LENGTH)


func _hash_secret(secret: String, salt: String) -> String:
	var out := salt + secret

	for _i in range(HASH_ROUNDS):
		out = DotHash.sha256_text(out)

	return out


## Base64url only, so an id can never become a path segment or a log injection.
##
## The same rule [code]DotAvatarKey.is_usable[/code] applies, restated rather than
## imported: dot-auth does not depend on dot-user-avatar, and the shared shape is
## what makes them interoperate without one.
static func _is_usable_id(id: String) -> bool:
	if id.length() < 8 or id.length() > 64:
		return false

	for i in range(id.length()):
		var c := id.unicode_at(i)
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


func _clean_name(name: String) -> DotResult:
	var clean := name.strip_edges()

	# Control characters are stripped rather than refused: they arrive from a
	# client's text field, they are invisible to whoever typed them, and a name
	# carrying a newline is a log-injection and a broken scoreboard row.
	var out := ""

	for i in range(clean.length()):
		var c := clean.unicode_at(i)
		if c >= 32 and c != 127:
			out += clean[i]

	out = out.strip_edges()

	if out.length() < MIN_NAME:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"That name is too short.",
			"at least %d characters" % MIN_NAME
		)

	return DotResult.success(out.substr(0, MAX_NAME))


func _remember_name(id: String, name: String) -> void:
	if name != "":
		_by_name[name.to_lower()] = id


func _forget_name(name: String) -> void:
	if name != "":
		_by_name.erase(name.to_lower())


func describe() -> Dictionary:
	return {
		"path": path,
		"open": _opened,
		"profiles": _profiles.size(),
		"max": max_profiles,
		"duplicate_names": allow_duplicate_names,
	}
