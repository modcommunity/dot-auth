@tool
class_name DotAuthProvider
extends Resource

## A pluggable way to authenticate a player. Subclass it to add your own.
##
## The four built-in strategies on [DotAuthConfig] cover the backbone, first-party
## introspection, local accounts and guests. They do not cover a store or console
## platform, a chat service, a publisher's own account service, a LAN token, or a QA
## bypass — and a game that needs one of those should not have to fork dot-auth.
##
## A provider is consulted before the configured strategy, so it can either handle a
## credential entirely or decline and let the normal path run.
##
## [codeblock]
## class_name PlatformProvider extends DotAuthProvider
##
## func _provider_name() -> String: return "platform"
##
## func _handles(credential: Dictionary) -> bool:
##     return credential.has("platform_ticket")
##
## func _authenticate(credential: Dictionary) -> DotResult:
##     var res := await _verify_ticket(credential["platform_ticket"])
##     if not res.ok:
##         return res
##
##     var identity := DotAuthIdentity.new()
##     identity.provider = "platform"
##     identity.provider_id = res.value["account_id"]
##     identity.uid = "platform:%s" % identity.provider_id
##     identity.display_name = res.value["display_name"]
##     return DotResult.success(identity)
##
## # once, at startup
## auth_server.add_provider(PlatformProvider.new())
## [/codeblock]
##
## [b]Namespace your uids.[/b] [member DotAuthIdentity.uid] is what bans and admin
## entries key on, and two providers that both emit bare numeric ids will collide —
## two platforms' account ids are both digits, and a ban on one would silently
## apply to whoever holds the other. Prefix with your provider name, as the built-in
## ones do.

const CHANNEL := "auth.provider"

## Lower runs first. Providers are consulted in this order before the built-in
## strategy.
@export var priority: int = 100

## Whether this provider is currently usable.
@export var enabled: bool = true


# --- Subclass interface ----------------------------------------------------

## Short identifier, used in logs and as the [member DotAuthIdentity.provider].
func _provider_name() -> String:
	return "custom"


## Whether this provider recognises the credential.
##
## Keep it cheap and purely structural — "does this dictionary contain my field".
## The expensive check belongs in [method _authenticate]; a provider that does
## network work here runs it for every login attempt including ones meant for
## somebody else.
func _handles(_credential: Dictionary) -> bool:
	return false


## Resolves the credential to a [DotAuthIdentity].
##
## May be a coroutine. Return a failure to refuse the login; the server does
## [b]not[/b] fall through to another provider afterwards, because a provider that
## claimed a credential and then rejected it has made a decision.
func _authenticate(_credential: Dictionary) -> DotResult:
	return DotResult.fail(
		DotError.CODE_INTERNAL,
		"%s does not implement _authenticate()." % _provider_name()
	)


## Optional startup check. Return a failure to refuse to register.
##
## For a provider that needs an API key or a reachable service — better to fail at
## boot with a clear reason than on the first player's login.
func _validate() -> DotResult:
	return DotResult.success(true)


# --- Public API ------------------------------------------------------------

func provider_name() -> String:
	return _provider_name()


func handles(credential: Dictionary) -> bool:
	return enabled and _handles(credential)


func authenticate(credential: Dictionary) -> DotResult:
	var result: Variant = await _authenticate(credential)

	if not (result is DotResult):
		return DotResult.fail(
			DotError.CODE_INTERNAL,
			"%s returned something other than a DotResult." % _provider_name()
		)

	var typed := result as DotResult

	if typed.ok and not (typed.value is DotAuthIdentity):
		return DotResult.fail(
			DotError.CODE_INTERNAL,
			"%s succeeded but did not return a DotAuthIdentity." % _provider_name()
		)

	# A provider that forgets to namespace its uid is a collision waiting to happen,
	# and the collision looks like a ban applying to the wrong person. Caught here
	# rather than discovered in moderation.
	if typed.ok:
		var identity := typed.value as DotAuthIdentity
		if not identity.uid.contains(":"):
			DotLog.warn(
				CHANNEL,
				"provider returned an unnamespaced uid; prefix it with the "
				+ "provider name or it may collide with another provider's ids",
				{"provider": _provider_name(), "uid": identity.uid}
			)

	return typed


func validate() -> DotResult:
	return _validate()


func describe() -> Dictionary:
	return {
		"provider": _provider_name(),
		"priority": priority,
		"enabled": enabled,
	}
