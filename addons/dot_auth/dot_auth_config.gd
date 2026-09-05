@tool
class_name DotAuthConfig
extends DotConfig

## Everything configurable about authentication, on both sides.
##
## Layered like every [DotConfig]: exported defaults, then a JSON file, then
## [code]DOT_AUTH_*[/code] environment variables, then [code]--auth-*[/code]
## arguments. Secrets are refused from the environment and argv — see
## [method sensitive_keys].

## How a game server decides who a connecting client is.
enum Strategy {
	## The client presents a short-lived, server-scoped ticket signed by an
	## issuer the server trusts. The server verifies it offline against a public
	## key: no network call per join, and the player's account token never
	## reaches the game server. [b]The right choice for public servers.[/b]
	TICKET,
	## The client sends its backbone access token and the server calls
	## [code]/api/app/v1/me[/code] to resolve it.
	##
	## [b]Only for first-party servers.[/b] It hands the operator a live
	## credential for the player's whole site account, and adds a backbone round
	## trip to every join.
	INTROSPECT,
	## Accounts defined in a file on the server. No backbone involved.
	LOCAL,
	## Nobody is authenticated; everyone is a guest with a per-device id.
	ANONYMOUS,
}

@export_group("Backbone")

## Base URL of the website-city backbone.
@export var backbone_url: String = "https://themodcommunity.com"

## Client name shown on the backbone's device-approval screen.
##
## Untrusted by the backbone and purely a label, but the label is what the player
## reads before approving, so make it the game's actual name.
@export var client_name: String = "dot game"

@export var client_version: String = "0.1.0"

## Seconds between device-code polls when the backbone suggests nothing.
##
## The backbone returns an `interval` and a `slow_down` code; both are honoured
## over this. Polling faster than told is how a client gets its grant burned.
@export_range(1.0, 60.0, 1.0) var device_poll_interval_sec: float = 5.0

## Give up on an unapproved device login after this long.
##
## The backbone's own grant TTL is 10 minutes; going past it only produces
## `expired_token` responses.
@export_range(30.0, 1800.0, 30.0) var device_timeout_sec: float = 600.0

@export_group("Token storage")

## Where the client keeps its refresh token.
@export var token_store_path: String = "user://dot_auth_tokens.dat"

## Encrypt the token store.
##
## [b]On web this is obfuscation, not confidentiality.[/b] The key is derived
## inside the same origin as the ciphertext, so anyone with devtools can recover
## both. It still prevents casual inspection and detects tampering. On desktop and
## mobile it is real at-rest encryption against another user on the machine.
@export var encrypt_token_store: bool = true

## Refresh the access token this many seconds before it expires.
##
## Wide enough that a slow network does not produce a window where the token is
## live but every request fails.
@export_range(10.0, 3600.0, 10.0) var refresh_margin_sec: float = 300.0

@export_group("Server")

## How this server authenticates clients. See [enum Strategy].
@export var strategy: Strategy = Strategy.TICKET

## Identifier this server is known by, and the audience tickets must name.
##
## A ticket minted for [code]eu-west-1[/code] must not be accepted by
## [code]us-east-2[/code] — otherwise a ticket captured on one server is a login
## on every server, which is the whole thing tickets exist to prevent.
@export var server_id: String = ""

## PEM public key of the ticket issuer, for [constant Strategy.TICKET].
@export_multiline var ticket_public_key: String = ""

## Seconds a ticket stays valid after issue.
##
## Short on purpose: a ticket is only in flight between "the client asked for it"
## and "the client connected". Minutes, not hours.
@export_range(30, 3600, 30) var ticket_ttl_sec: int = 300

## Clock skew tolerated when checking ticket times.
@export_range(0, 600, 10) var ticket_leeway_sec: int = 60

## Remember spent ticket ids for this long, to refuse replays.
##
## Must exceed [member ticket_ttl_sec], otherwise a ticket outlives the memory of
## having been used and can be replayed in the gap.
@export_range(60, 7200, 60) var ticket_replay_memory_sec: int = 900

## Accept guests when authentication fails or is unavailable.
##
## Sensible for a casual server that would rather have players than identities.
## Turn off where bans need to mean something — a guest can always come back as a
## different guest.
@export var allow_guests: bool = false

## Path to the local accounts file, for [constant Strategy.LOCAL].
@export var local_accounts_path: String = "user://dot_auth_accounts.json"

## The issuer this server tells who is playing on it. Empty means it does not.
##
## What makes [member single_session] mean anything. The issuer sees every
## ticket, but a ticket is a player's [i]intention[/i] to connect and says nothing
## about whether they arrived or when they left. A server that reports its roster
## through [DotAuthSessionReporter] is what turns "asked for a ticket" into "is
## on this server right now" — and what releases its players when they leave, so
## they are not locked out of every other server until the lease runs out.
##
## The issuer's base URL, the same one clients ask for tickets. Needs
## [member session_report_key], which the publisher hands the operator alongside
## the public key.
@export var session_report_url: String = ""

## Secret this server presents to the issuer when reporting its roster.
##
## Per server, issued by the publisher, and refused from the environment and the
## command line like every other secret. Without it anyone could report any
## player as being on any server — which would lock them out of everywhere else
## for the length of the lease, on the strength of a POST.
@export var session_report_key: String = ""

## Seconds between roster reports to the issuer.
##
## Must fit inside the issuer's [member session_lease_sec] with room to lose a
## report or two, or players on this server drop out of the issuer's records
## between reports and the restriction goes quiet for everybody on it. Half the
## lease is the most this should be; the defaults are 60 against 300.
@export_range(5.0, 3600.0, 5.0) var session_report_interval_sec: float = 60.0

@export_group("Local profiles")

## Let visitors make an account that lives on THIS server and nowhere else.
##
## Independent of [member strategy], because it is a [DotAuthProvider] rather than a
## strategy — so a server can take backbone tickets and local profiles at the same
## time, and a player without a site account is not turned away from a game whose
## other players have one.
##
## [b]Different from [constant Strategy.LOCAL].[/b] That is an operator-maintained
## file of usernames and passwords, for a server with a known cast. This is
## self-service: a visitor names themselves, the server issues them a credential, and
## they are the same player next week — with a profile and an avatar filed under the
## same key a backbone-backed player would have. See [DotLocalProfiles].
@export var allow_local_profiles: bool = false

## Where local profiles are stored. Server side; contains hashed credentials.
@export var local_profiles_path: String = "user://dot_local_profiles.json"

## Refuse to create more than this many. 0 removes the limit.
##
## A server that lets an unauthenticated visitor write a row has handed its disk to
## whoever can reach the port. [member auth_attempts_per_minute] is the first line;
## this is the backstop.
@export_range(0, 1000000, 100) var max_local_profiles: int = 5000

## Let a visitor mint a profile, rather than only use one they already hold.
##
## Off means an operator creates them from the console — a closed server that still
## wants persistent identities without a backbone.
@export var local_profile_signup: bool = true

## Where a CLIENT keeps the secrets servers issued it, keyed by server.
##
## Not a server setting. It is here because a game configures one [DotAuthConfig] for
## both halves, and a client that stores this in the wrong place silently loses every
## local profile the player has ever made.
@export var local_profile_client_path: String = "user://dot_local_profiles.dat"

@export_group("Issuer")

## PEM private key used to mint tickets. Issuer only — never ship this in a game.
@export_multiline var issuer_private_key: String = ""

## Name written into the ticket's [code]iss[/code] claim.
@export var issuer_name: String = "dot-auth"

## Key id written into the ticket header, so verifiers can pick a key during
## rotation.
@export var issuer_key_id: String = "default"

## Refuse a ticket for one server while the player is on another.
##
## One account, one seat. A player on [code]eu-west-1[/code] who asks for a
## ticket to [code]us-east-2[/code] is told which server they are on and refused
## until they leave it, their server reports them gone, or the lease runs out. A
## ticket for the server they are [i]already[/i] on is always granted: a crashed
## client has to be able to reconnect.
##
## This lives on the issuer because the issuer is the only participant that sees
## every server. A game server knows its own roster and nothing about anybody
## else's, and asking servers to compare notes would mean operators trusting each
## other, which the ticket design exists to avoid.
##
## [b]Only as good as the reporting.[/b] A ticket begins a session; a roster
## report from the server confirms it and, later, ends it. A server that reports
## nothing holds its players for [member session_lease_sec] after their ticket
## and then lets go, whether or not they are still playing. See
## [member session_report_url].
@export var single_session: bool = false

## Seconds a session stays live without word from a server.
##
## The clock that runs between roster reports and the length a non-reporting
## server holds a player. Too short and a lost report frees everybody on a
## server; too long and a server that died keeps its players locked out of
## everywhere else. Must be at least [member ticket_ttl_sec] — a lease shorter
## than the ticket lets a player hold a live ticket for one server after the
## issuer has forgotten it, and get a second one for another.
@export_range(30, 86400, 30) var session_lease_sec: int = 300

@export_group("Integration API")

## Server-scoped integration token for the backbone's `/api/integration/v1/*` and
## `/api/content/server/integration/*` endpoints.
##
## Lets a dedicated server report its own player count, map and roster to its site
## listing. Scoped to one server by the backbone, so a leak cannot be pointed at
## somebody else's listing.
@export var integration_token: String = ""

## Seconds between stat reports to the backbone. 0 disables reporting.
@export_range(0.0, 3600.0, 5.0) var report_interval_sec: float = 60.0

## Also report the player roster, not just counts.
##
## Requires the `SERVER_USERS` scope, which the backbone keeps separate from
## `SERVER_STATS` deliberately: a player list is personal data about third
## parties. Leave off unless players expect to be listed publicly.
@export var report_roster: bool = false

@export_group("Rate limits")

## Authentication attempts per client per minute.
@export_range(1, 100, 1) var auth_attempts_per_minute: int = 10

## Backbone requests per minute from this process.
##
## A local ceiling that keeps a bug — a retry loop, a stuck poll — from getting
## the server's integration credential rate-limited or revoked.
@export_range(1, 6000, 10) var backbone_requests_per_minute: int = 120


func env_prefix() -> String:
	return "DOT_AUTH_"


func cli_prefix() -> String:
	return "--auth-"


func sensitive_keys() -> PackedStringArray:
	# A process's environment and argv are readable by other processes on most
	# systems and end up in `ps` output, crash dumps and pasted bug reports.
	# These belong in a file with restricted permissions.
	return PackedStringArray([
		"issuer_private_key",
		"integration_token",
		"session_report_key",
	])


func validate() -> DotResult:
	match strategy:
		Strategy.TICKET:
			if server_id == "":
				return DotResult.fail(
					DotError.CODE_INVALID,
					"TICKET authentication needs a server_id.",
					"tickets are scoped to one server; without an id this "
					+ "server would accept tickets minted for any other"
				)
			if ticket_public_key.strip_edges() == "":
				return DotResult.fail(
					DotError.CODE_INVALID,
					"TICKET authentication needs ticket_public_key."
				)

		Strategy.INTROSPECT:
			if backbone_url.strip_edges() == "":
				return DotResult.fail(
					DotError.CODE_INVALID,
					"INTROSPECT authentication needs a backbone_url."
				)

		Strategy.LOCAL:
			if local_accounts_path.strip_edges() == "":
				return DotResult.fail(
					DotError.CODE_INVALID,
					"LOCAL authentication needs local_accounts_path."
				)

	if ticket_replay_memory_sec <= ticket_ttl_sec:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"ticket_replay_memory_sec must exceed ticket_ttl_sec.",
			"otherwise a ticket outlives the record of having been spent, and "
			+ "can be replayed in the gap"
		)

	if single_session and session_lease_sec < ticket_ttl_sec:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"session_lease_sec must be at least ticket_ttl_sec.",
			"otherwise a player holds a live ticket for one server after the "
			+ "issuer has forgotten the session, and can be issued a second "
			+ "one for another"
		)

	if session_report_url.strip_edges() != "" \
		and session_report_key.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID,
			"session_report_url needs session_report_key.",
			"the issuer refuses an unsigned roster; reporting without a key "
			+ "would fail on every tick"
		)

	if session_report_url.strip_edges() != "" and server_id.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID,
			"session_report_url needs a server_id.",
			"a roster has to say which server it is the roster of"
		)

	return DotResult.success(null)


## Warns about settings that are legal but risky. Called at startup.
func warn_about_risky_settings() -> void:
	if strategy == Strategy.INTROSPECT:
		DotLog.warn(
			"auth",
			"INTROSPECT strategy: connecting players hand this server a live "
			+ "credential for their whole site account. Only run this on servers "
			+ "you operate.",
			{"strategy": "INTROSPECT"}
		)

	if strategy == Strategy.ANONYMOUS:
		DotLog.warn(
			"auth",
			"ANONYMOUS strategy: nobody is authenticated, so bans and admin "
			+ "entries cannot be tied to a person",
			{"strategy": "ANONYMOUS"}
		)

	if allow_guests and strategy != Strategy.ANONYMOUS:
		DotLog.warn(
			"auth",
			"allow_guests is on — a banned player can return as a guest",
			{"setting": "allow_guests"}
		)


func device_endpoint() -> String:
	return _api("/api/app/v1/auth/device")


func token_endpoint() -> String:
	return _api("/api/app/v1/auth/token")


func refresh_endpoint() -> String:
	return _api("/api/app/v1/auth/refresh")


func revoke_endpoint() -> String:
	return _api("/api/app/v1/auth/revoke")


func me_endpoint() -> String:
	return _api("/api/app/v1/me")


func server_stats_endpoint() -> String:
	return _api("/api/content/server/integration/stats")


func server_users_endpoint() -> String:
	return _api("/api/content/server/integration/users")


func integration_endpoint(path: String) -> String:
	return _api("/api/integration/v1/" + path.trim_prefix("/"))


## An endpoint on the app API, the surface a PLAYER's own token speaks to.
func app_endpoint(path: String) -> String:
	return _api("/api/app/v1/" + path.trim_prefix("/"))


func _api(path: String) -> String:
	return backbone_url.trim_suffix("/") + path
