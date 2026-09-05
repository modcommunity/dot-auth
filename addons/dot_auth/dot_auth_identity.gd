@tool
class_name DotAuthIdentity
extends Resource

## Who a player is, as far as this game is concerned.
##
## Produced by whichever backend authenticated them and consumed by dot-server for
## permissions, moderation and display. Deliberately small: a game server needs an
## identifier it can ban, a name it can show, and a set of claims it can check.
## Everything else belongs on the backbone.

## Stable, globally unique identifier.
##
## [b]The thing bans and admin entries key on[/b], so it must never be reassigned
## and must never be something a player can change. The backbone's user id
## qualifies; a display name emphatically does not.
##
## Namespaced by provider — [code]backbone:clx8f…[/code], [code]local:admin[/code],
## [code]guest:a3f9…[/code] — so two backends can never collide and a ban list
## makes sense when a server switches backends.
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

## Site-wide role, e.g. [code]USER[/code], [code]MODERATOR[/code], [code]ADMIN[/code].
##
## Advisory. A server decides its own permissions; site staff are not
## automatically server admins, and treating them as such would let anyone with a
## site role walk into every server running this addon.
@export var role: String = ""

## Arbitrary claims from the backend — entitlements, group memberships, flags.
##
## dot-server's admin source can map these to permissions, which is how "everyone
## in the site group 'moderators' gets kick rights here" is expressed without a
## per-server admin list.
@export var claims: Dictionary = {}

## Unix seconds when this identity was established.
@export var authenticated_at: int = 0

## Unix seconds when it should be re-checked. 0 means no expiry.
@export var expires_at: int = 0

## True when the player was not authenticated at all.
##
## Guests get a stable-per-device id so they can be muted or kicked within a
## session, but nothing that survives a reinstall.
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


## Builds an identity from the backbone's `SessionUserSchema`.
##
## Field names mirror `~/types/app-api/contract.ts` exactly. A drift there shows
## up here as an empty display name rather than a crash, which is why [member uid]
## is validated and the rest is not.
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


## Whether a claim is present and truthy.
##
## Claims arrive as JSON, so a flag can be [code]true[/code], [code]1[/code] or
## [code]"true"[/code] depending on the backend. Normalising here keeps every call
## site from having to know which.
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


## A short label for logs and the `status` command.
##
## Includes the uid because a display name is not unique and moderation notes that
## only record a name are useless the moment somebody changes theirs.
func label() -> String:
	return "%s <%s>" % [display_name, uid]


func _to_string() -> String:
	return "DotAuthIdentity(%s)" % label()
