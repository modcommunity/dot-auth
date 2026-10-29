@tool
class_name DotAuthProvider
extends Resource

## A pluggable way to authenticate a player. Subclass it and register it with [method DotAuthServer.add_provider].
##
## A provider is consulted before the configured strategy and either handles a credential or declines. Namespace your uids ("platform:123"): bans and admin entries key on [member DotAuthIdentity.uid], and bare numeric ids from two providers collide. Worked example: docs/rationale.md.

const CHANNEL := "auth.provider"

## Lower runs first. Providers are consulted in this order before the built-in
## strategy.
@export var priority: int = 100

## Whether this provider is currently usable.
@export var enabled: bool = true



## Short identifier, used in logs and as the [member DotAuthIdentity.provider].
func _provider_name() -> String:
	return "custom"


## Whether this provider recognises the credential. Keep it cheap and structural; the expensive check belongs in [method _authenticate].
func _handles(_credential: Dictionary) -> bool:
	return false


## Resolves the credential to a [DotAuthIdentity]; may be a coroutine.
##
## A failure refuses the login with no fall-through: a provider that claimed a credential owns the decision.
func _authenticate(_credential: Dictionary) -> DotResult:
	return DotResult.fail(
		DotError.CODE_INTERNAL,
		"%s does not implement _authenticate()." % _provider_name()
	)


## Optional startup check; return a failure to refuse to register (fail at boot, not on the first login).
func _validate() -> DotResult:
	return DotResult.success(true)



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
