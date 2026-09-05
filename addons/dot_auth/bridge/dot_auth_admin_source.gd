@tool
class_name DotAuthAdminSource
extends Resource

## Turns backbone identity into dot-server admin permissions.
##
## The bridge between "who is this player, according to the site" and "what may
## they do on this server". Without it, every server operator maintains a
## hand-edited list of user ids; with it, "everyone in the site group
## [code]moderators[/code] can kick here" is one mapping rule.
##
## [b]Deliberately duck-typed.[/b] dot-auth does not depend on dot-server and
## dot-server does not depend on dot-auth — either works alone. dot-server looks
## for an object with [method lookup] and calls it; this satisfies that contract
## without either addon importing the other's classes.
##
## [b]Site roles are not server roles.[/b] [member role_flags] is empty by
## default, and that is not an oversight: a site moderator is not automatically an
## admin on every community server running this addon, and shipping that default
## would hand anyone with a site role control of every server. Map roles only where
## the server operator and the site are the same people.

const CHANNEL := "auth.admin"

## Maps a site group name to permission flags granted on this server.
##
## Group names come from the identity's [code]groups[/code] claim, which the
## backbone populates.
##
## [codeblock]
## group_flags = {
##     "moderators": ["kick", "mute", "chat"],
##     "admins": ["kick", "ban", "changemap", "cvar"],
## }
## [/codeblock]
@export var group_flags: Dictionary = {}

## Maps a site-wide role to permission flags. Empty by default — see the class doc.
@export var role_flags: Dictionary = {}

## Maps an identity claim to flags, granted when the claim is truthy.
##
## For entitlement-style permissions: a supporter claim granting a reserved slot.
@export var claim_flags: Dictionary = {}

## Flags granted to every authenticated (non-guest) player.
##
## For servers where being signed in is itself a privilege — a reserved slot, or
## the ability to speak in chat.
@export var authenticated_flags: PackedStringArray = PackedStringArray()

## Explicit per-user grants, as [code]uid -> [flags][/code].
##
## Escape hatch for "this one person, on this one server". Keyed on
## [member DotAuthIdentity.uid], never on a display name.
@export var user_flags: Dictionary = {}

## Immunity by group, as [code]group -> level[/code].
##
## Higher immunity cannot be kicked, banned or muted by lower. The same rule every
## admin system converges on, because the problem is the same: without it two admins can kick each other in a
## loop and the server has no way to say who wins.
@export var group_immunity: Dictionary = {}

## Immunity granted to any authenticated player.
@export var base_immunity: int = 0


## Resolves an identity to admin permissions.
##
## The method dot-server calls. Returns a [DotResult] carrying
## [code]{flags: PackedStringArray, immunity: int, source: String}[/code], or a
## failure when this source has nothing to say — which is not an error, and
## dot-server treats it as "no permissions from here" and moves on to its other
## sources.
func lookup(identity: DotAuthIdentity) -> DotResult:
	if identity == null or not identity.is_valid():
		return DotResult.fail(
			DotError.CODE_INVALID, "No identity to look up."
		)

	# Guests get nothing, ever. A guest identity is a random per-device string, so
	# granting it permissions would mean granting them to anyone who asks.
	if identity.is_guest:
		return DotResult.fail(
			DotError.CODE_FORBIDDEN,
			"Guests have no permissions.",
			identity.uid
		)

	var flags := {}
	var immunity := base_immunity
	var reasons := PackedStringArray()

	for f in authenticated_flags:
		flags[f] = true
	if not authenticated_flags.is_empty():
		reasons.append("authenticated")

	var groups := identity.groups()
	for group in groups:
		if group_flags.has(group):
			for f in _as_flags(group_flags[group]):
				flags[f] = true
			reasons.append("group:%s" % group)

		if group_immunity.has(group):
			immunity = maxi(immunity, int(group_immunity[group]))

	if identity.role != "" and role_flags.has(identity.role):
		for f in _as_flags(role_flags[identity.role]):
			flags[f] = true
		reasons.append("role:%s" % identity.role)

	for claim_key in claim_flags:
		if identity.has_claim(str(claim_key)):
			for f in _as_flags(claim_flags[claim_key]):
				flags[f] = true
			reasons.append("claim:%s" % claim_key)

	if user_flags.has(identity.uid):
		for f in _as_flags(user_flags[identity.uid]):
			flags[f] = true
		reasons.append("user")

	if flags.is_empty():
		return DotResult.fail(
			DotError.CODE_FORBIDDEN,
			"No permissions for this player.",
			identity.uid
		)

	var out := PackedStringArray(flags.keys())
	out.sort()

	DotLog.debug(
		CHANNEL,
		"granted permissions",
		{
			"user": identity.label(),
			"flags": Array(out),
			"immunity": immunity,
			"via": ", ".join(reasons),
		}
	)

	return DotResult.success({
		"flags": out,
		"immunity": immunity,
		"source": "dot-auth (%s)" % ", ".join(reasons),
	})


## Name dot-server shows for this source in `admin_sources` output.
func source_name() -> String:
	return "dot-auth"


## Accepts a single flag string or a list, so config files can write either.
func _as_flags(value: Variant) -> PackedStringArray:
	if value is PackedStringArray:
		return value

	if value is Array:
		var out := PackedStringArray()
		for v in (value as Array):
			out.append(str(v))
		return out

	if value is String:
		# "kick,ban" and "kick ban" both read naturally in a JSON config.
		var s := value as String
		if s.contains(","):
			var out2 := PackedStringArray()
			for part in s.split(",", false):
				out2.append(part.strip_edges())
			return out2
		return PackedStringArray([s])

	return PackedStringArray()


## Loads the mapping from a JSON file, for operators who would rather not edit a
## [Resource] in the inspector.
func load_from_json(path: String) -> DotResult:
	var read := DotPaths.read_json(path)
	if not read.ok:
		return read

	var data: Variant = read.value
	if not (data is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE, "The admin mapping must be a JSON object."
		)

	var d := data as Dictionary

	if d.get("groups") is Dictionary:
		group_flags = d["groups"]
	if d.get("roles") is Dictionary:
		role_flags = d["roles"]
	if d.get("claims") is Dictionary:
		claim_flags = d["claims"]
	if d.get("users") is Dictionary:
		user_flags = d["users"]
	if d.get("immunity") is Dictionary:
		group_immunity = d["immunity"]
	if d.has("base_immunity"):
		base_immunity = int(d["base_immunity"])
	if d.get("authenticated") is Array:
		authenticated_flags = _as_flags(d["authenticated"])

	DotLog.info(
		CHANNEL,
		"admin mapping loaded",
		{
			"groups": group_flags.size(),
			"roles": role_flags.size(),
			"users": user_flags.size(),
		}
	)

	return DotResult.success(true)


func describe() -> Dictionary:
	return {
		"source": source_name(),
		"groups": group_flags.keys(),
		"roles": role_flags.keys(),
		"claims": claim_flags.keys(),
		"users": user_flags.size(),
		"authenticated_flags": Array(authenticated_flags),
	}
