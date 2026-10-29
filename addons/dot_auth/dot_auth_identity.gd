@tool
class_name DotAuthIdentity
extends Resource

## Who a player is: an identifier a server can ban, a name it can show, and claims it can check.

## Stable, globally unique identifier, namespaced by provider ([code]backbone:clx8f[/code], [code]local:admin[/code]).
##
## Bans and admin entries key on it, so it must never be reassigned or player-changeable; a display name emphatically is not one.
@export var uid: String = ""

## Which backend vouched for this identity: [code]backbone[/code],
## [code]local[/code], [code]guest[/code].
@export var provider: String = ""

## Provider-local identifier, without the namespace prefix.
@export var provider_id: String = ""

## Name to show in chat and the scoreboard.
##
## Untrusted and mutable. Never use it for authorisation, never use it as a key.
@export var display_name: String = ""

## Site username, when the provider has a distinct one.
@export var username: String = ""

@export var avatar_url: String = ""

## Site-wide role, e.g. [code]USER[/code], [code]MODERATOR[/code]. Advisory: site staff are not automatically server admins.
@export var role: String = ""

## Arbitrary claims from the backend (entitlements, groups, flags), which dot-server's admin source can map to permissions.
@export var claims: Dictionary = {}

## Unix seconds when this identity was established.
@export var authenticated_at: int = 0

## Unix seconds when it should be re-checked. 0 means no expiry.
@export var expires_at: int = 0

## True when the player was not authenticated at all; guests get a per-device id good within a session only.
@export var is_guest: bool = false


static func guest(device_id: String, name: String = "") -> DotAuthIdentity:
	var id := DotAuthIdentity.new()
	id.provider = "guest"
	id.provider_id = device_id
	id.uid = "guest:%s" % device_id
	id.display_name = name if name != "" else "Guest-%s" % device_id.substr(0, 6)
	id.is_guest = true
	id.authenticated_at = int(Time.get_unix_time_from_system())
	return id


## Builds an identity from the backbone's `SessionUserSchema` (field names mirror `~/types/app-api/contract.ts`); only [member uid] is validated.
static func from_backbone_user(d: Dictionary) -> DotResult:
	var provider_id := str(d.get("id", ""))
	if provider_id == "":
		return DotResult.fail(
			DotError.CODE_PARSE,
			"The backbone returned a user with no id.",
			JSON.stringify(d).substr(0, 200)
		)

	var id := DotAuthIdentity.new()
	id.provider = "backbone"
	id.provider_id = provider_id
	id.uid = "backbone:%s" % provider_id
	id.username = str(d.get("username", ""))
	id.display_name = str(d.get("name", ""))
	if id.display_name == "":
		id.display_name = id.username if id.username != "" else "Player"
	id.avatar_url = str(d.get("avatar", ""))
	id.role = str(d.get("role", ""))
	id.authenticated_at = int(Time.get_unix_time_from_system())

	return DotResult.success(id)


## Builds an identity from the backbone's scoped introspection answer `{key, name, username}`.
##
## No account id on purpose: the uid is `tmc:<key>`, stable for this player on this server and meaningless elsewhere. The key also goes in the `scoped_key` claim, which dot-user reads; a key derived here could never be resolved by the backbone.
static func from_scoped_user(d: Dictionary) -> DotResult:
	var key := str(d.get("key", ""))

	# The backbone's own key shape (`ScopeKeyRx`), checked because it becomes a uid,
	# a file name in a local profile store and a URL path segment.
	var rx := RegEx.create_from_string("^[A-Za-z0-9_-]{8,64}$")

	if rx.search(key) == null:
		return DotResult.fail(
			DotError.CODE_PARSE,
			"The backbone returned a player with no usable key.",
			JSON.stringify(d).substr(0, 200)
		)

	var id := DotAuthIdentity.new()
	id.provider = "tmc"
	id.provider_id = key
	id.uid = "tmc:%s" % key
	id.username = str(d.get("username", "")) if d.get("username") != null else ""
	id.display_name = str(d.get("name", "")) if d.get("name") != null else ""
	if id.display_name == "":
		id.display_name = id.username if id.username != "" else "Player"
	id.claims = {"scoped_key": key}
	id.authenticated_at = int(Time.get_unix_time_from_system())

	return DotResult.success(id)


static func from_dict(d: Dictionary) -> DotAuthIdentity:
	var id := DotAuthIdentity.new()
	id.uid = str(d.get("uid", ""))
	id.provider = str(d.get("provider", ""))
	id.provider_id = str(d.get("provider_id", ""))
	id.display_name = str(d.get("display_name", ""))
	id.username = str(d.get("username", ""))
	id.avatar_url = str(d.get("avatar_url", ""))
	id.role = str(d.get("role", ""))
	id.authenticated_at = int(d.get("authenticated_at", 0))
	id.expires_at = int(d.get("expires_at", 0))
	id.is_guest = bool(d.get("is_guest", false))
	if d.get("claims") is Dictionary:
		id.claims = d["claims"]
	return id


func to_dict() -> Dictionary:
	return {
		"uid": uid,
		"provider": provider,
		"provider_id": provider_id,
		"display_name": display_name,
		"username": username,
		"avatar_url": avatar_url,
		"role": role,
		"claims": claims,
		"authenticated_at": authenticated_at,
		"expires_at": expires_at,
		"is_guest": is_guest,
	}


func is_valid() -> bool:
	return uid != "" and provider != ""


func is_expired() -> bool:
	if expires_at <= 0:
		return false
	return int(Time.get_unix_time_from_system()) >= expires_at


## Whether a claim is present and truthy; normalises [code]true[/code], [code]1[/code] and [code]"true"[/code] across backends.
func has_claim(key: String) -> bool:
	if not claims.has(key):
		return false
	var v: Variant = claims[key]
	if v is bool:
		return v
	if v is int or v is float:
		return float(v) != 0.0
	if v is String:
		return ["1", "true", "yes", "on"].has((v as String).to_lower())
	if v is Array:
		return not (v as Array).is_empty()
	return v != null


func claim(key: String, default: Variant = null) -> Variant:
	return claims.get(key, default)


## Group memberships, from the [code]groups[/code] claim.
func groups() -> PackedStringArray:
	var out := PackedStringArray()
	var v: Variant = claims.get("groups", [])
	if v is Array:
		for g in (v as Array):
			out.append(str(g))
	elif v is PackedStringArray:
		out.append_array(v)
	return out


## A short label for logs and `status`; includes the uid because a display name is not unique and can change.
func label() -> String:
	return "%s <%s>" % [display_name, uid]


func _to_string() -> String:
	return "DotAuthIdentity(%s)" % label()
