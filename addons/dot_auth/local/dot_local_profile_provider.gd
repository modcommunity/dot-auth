@tool
class_name DotLocalProfileProvider
extends DotAuthProvider

## Signs players in against [DotLocalProfiles] — accounts that never leave this
## server.
##
## A [DotAuthProvider], which is the extension point that already exists for exactly
## this ("a LAN token" is named in its own documentation), so a server gets local
## accounts by registering one object and nothing about the built-in strategies
## changes. In particular a server can offer local profiles AND backbone tickets at
## the same time: the provider claims only the credentials that name it, and
## everything else falls through to the configured strategy.
##
## [codeblock]
## var local := DotLocalProfileProvider.new()
## local.profiles = DotLocalProfiles.at("user://local_profiles.json")
## local.profile_created.connect(_send_secret_to_that_client)
## auth_server.add_provider(local)
## [/codeblock]
##
## Two credential shapes, and they are separate on purpose:
##
## [codeblock]
## {"local_profile": {"id": "sWrM…", "secret": "…"}}   returning player
## {"local_profile_new": {"name": "Ashley"}}           first join
## [/codeblock]
##
## Folding them into one — "create it if the id is unknown" — would turn every
## mistyped or expired credential into a brand new profile, so a player whose secret
## was lost would silently become a stranger with their own name taken.
##
## [b]The secret must reach that one client and nobody else.[/b] It is emitted on
## [signal profile_created] rather than put on the identity, because an identity is
## relayed: dot-server sends one to every player in the match so they can draw each
## other's names. A secret on it would be broadcast to the lobby. The signal fires
## synchronously inside [method DotAuthServer.authenticate], so the peer being
## admitted is unambiguous — send it over that peer's own channel and never a
## broadcast one.

const LOCAL_CHANNEL := "auth.local-profile"

## The uid namespace. Distinct from [constant DotAuthConfig.Strategy.LOCAL]'s
## `local:`, which keys on an operator-maintained USERNAME — two different kinds of
## account, and a uid collision between them is a ban applying to the wrong person.
const UID_PREFIX := "profile"

## Emitted when a profile is minted. [param secret] is shown exactly once.
##
## [b]Never log it, never broadcast it.[/b] See the class documentation.
signal profile_created(id: String, secret: String, name: String)

## Emitted when a returning player is recognised.
signal profile_recognised(id: String, name: String)

## The store. Required.
var profiles: DotLocalProfiles = null

## Whether a visitor may mint a profile, or only use one they already hold.
##
## Off is a real deployment: an operator who creates profiles from the console and
## runs a closed server. On is the one this exists for.
var allow_creation: bool = true


func _provider_name() -> String:
	return UID_PREFIX


func _handles(credential: Dictionary) -> bool:
	# Structural only, as the base class asks. The expensive part — hashing a
	# secret four thousand times — belongs in _authenticate, or it runs for every
	# login attempt including ones meant for another provider.
	return credential.has("local_profile") or credential.has("local_profile_new")


func _validate() -> DotResult:
	if profiles == null:
		return DotResult.fail(
			DotError.CODE_STATE,
			"DotLocalProfileProvider has no DotLocalProfiles store.",
			"assign `profiles` before registering it"
		)

	return profiles.open()


func _authenticate(credential: Dictionary) -> DotResult:
	if profiles == null:
		return DotResult.fail(
			DotError.CODE_STATE, "Local profiles are not configured."
		)

	var hint := str(credential.get("device_id", ""))

	if credential.has("local_profile"):
		return _sign_in(credential["local_profile"], hint)

	return _sign_up(credential.get("local_profile_new", {}), hint)


func _sign_in(raw: Variant, hint: String) -> DotResult:
	if not (raw is Dictionary):
		return DotResult.fail(
			DotError.CODE_INVALID, "That is not a profile credential."
		)

	var given := raw as Dictionary
	var id := str(given.get("id", ""))
	var secret := str(given.get("secret", ""))

	var found := profiles.verify(id, secret, hint)

	if not found.ok:
		return found

	var row := found.value as Dictionary
	var name := str(row.get("name", ""))

	profile_recognised.emit(id, name)

	return DotResult.success(_identity(id, name))


func _sign_up(raw: Variant, hint: String) -> DotResult:
	if not allow_creation:
		return DotResult.fail(
			DotError.CODE_FORBIDDEN,
			"This server is not taking new profiles.",
			"an operator creates them"
		)

	if not (raw is Dictionary):
		return DotResult.fail(
			DotError.CODE_INVALID, "That is not a profile request."
		)

	var made := profiles.create(str((raw as Dictionary).get("name", "")), hint)

	if not made.ok:
		return made

	var out := made.value as Dictionary
	var id := str(out["id"])
	var secret := str(out["secret"])

	# Read back rather than reusing the requested name: create() trims, strips
	# control characters and truncates, so the name the player is known by is the
	# stored one and the client must be told THAT, not what it asked for.
	var row := profiles.verify(id, secret)
	var name := (
		str((row.value as Dictionary).get("name", "")) if row.ok else ""
	)

	profile_created.emit(id, secret, name)

	DotLog.info(LOCAL_CHANNEL, "local profile signed up", {"id": id})

	return DotResult.success(_identity(id, name))


## Builds the identity a local profile presents.
##
## [b]`is_guest` is false.[/b] A guest is somebody the server could not identify;
## this player has a credential this server issued and will be the same person next
## week. It also governs whether a client may rename itself mid-join
## ([method DotAuthServer._apply_requested_name]) — and a local profile's name lives
## in the store, so letting a connect packet override it would make the name on the
## scoreboard and the name in the file disagree.
func _identity(id: String, name: String) -> DotAuthIdentity:
	var identity := DotAuthIdentity.new()

	identity.provider = UID_PREFIX
	identity.provider_id = id
	identity.uid = "%s:%s" % [UID_PREFIX, id]
	identity.display_name = name if name != "" else "Player"
	identity.username = name
	identity.is_guest = false
	identity.authenticated_at = int(Time.get_unix_time_from_system())

	# So a game can tell a local profile from a backbone account without parsing
	# the uid — the thing every caller would otherwise do, differently.
	identity.claims = {"local": true}

	return identity


func describe() -> Dictionary:
	var out := super.describe()

	out["store"] = profiles.describe() if profiles != null else null
	out["allow_creation"] = allow_creation

	return out
