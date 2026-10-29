@tool
class_name DotAuthConfig
extends DotConfig

## Everything configurable about authentication, on both sides, layered like every [DotConfig]; secrets are refused from environment and argv ([method sensitive_keys]).

## How a game server decides who a connecting client is.
enum Strategy {
	## The client presents a short-lived, server-scoped ticket signed by a trusted issuer,
	## verified offline against a public key: no per-join network call, and the account
	## token never reaches the game server. [b]The right choice for public servers.[/b]
	TICKET,
	## The client sends a single-use JOIN TOKEN minted for this server, which the server redeems at the backbone's `player/introspect`.
	##
	## First-party servers only, enforced by the client: it joins this way only when [member join_audience] is in its [member first_party_audiences], and never sends its access token. Adds a backbone round trip per join.
	INTROSPECT,
	## Accounts defined in a file on the server. No backbone involved.
	LOCAL,
	## Nobody is authenticated; everyone is a guest with a per-device id.
	ANONYMOUS,
}

@export_group("Backbone")

## Base URL of the website-city backbone (the site is `moddingcommunity.com`).
##
## The default is a real domain as a security property: an unregistered name any stranger could buy would receive the start of an authentication flow. Never read from a page's query string: it decides where a sign-in code is redeemed, so that would be a credential-forwarding link. Web clients get it from the build's JSON file.
@export var backbone_url: String = "https://moddingcommunity.com"

## The servers this client treats as FIRST-PARTY: the only ones it joins under [constant Strategy.INTROSPECT]. Empty means none (a ticket or a refusal instead).
##
## Entries are `server:<id>` or `app:<id>`, the [member join_audience] a server announces. The join token is redeemable only by the credential its audience names, so a server claiming another's audience gains nothing. Client-side: ship it in the build's config.
@export var first_party_audiences: PackedStringArray = PackedStringArray()

## Client name shown on the backbone's device-approval screen; a label the backbone does not trust but the player reads, so use the game's name.
@export var client_name: String = "dot game"

@export var client_version: String = "0.1.0"

## Seconds between device-code polls when the backbone suggests nothing; its `interval` and `slow_down` win, as polling faster burns the grant.
@export_range(1.0, 60.0, 1.0) var device_poll_interval_sec: float = 5.0

## Give up on an unapproved device login after this long (the backbone's grant TTL is 10 minutes).
@export_range(30.0, 1800.0, 30.0) var device_timeout_sec: float = 600.0

@export_group("Token storage")

## Where the client keeps its refresh token.
@export var token_store_path: String = "user://dot_auth_tokens.dat"

## Encrypt the token store. On web this is obfuscation only (the key shares the ciphertext's origin); elsewhere it is real at-rest encryption against other users.
@export var encrypt_token_store: bool = true

## Refresh the access token this many seconds before it expires, wide enough that a slow network never leaves a live token failing.
@export_range(10.0, 3600.0, 10.0) var refresh_margin_sec: float = 300.0

@export_group("Server")

## How this server authenticates clients. See [enum Strategy].
@export var strategy: Strategy = Strategy.TICKET

## Identifier this server is known by, and the audience tickets must name, so a ticket captured on one server is not a login on every server.
@export var server_id: String = ""

## The backbone audience this server announces for [constant Strategy.INTROSPECT]: `server:<id>` or `app:<id>`.
##
## Empty reads it from `GET /api/integration/v1/me` once [member DotAuthServer.backbone] is set. A wrong value only breaks joins (`wrong_audience`).
@export var join_audience: String = ""

## PEM public key of the ticket issuer, for [constant Strategy.TICKET]. When set it is
## the only key trusted, whatever [member ticket_public_keys] holds.
@export_multiline var ticket_public_key: String = ""

## Issuer public keys by key id (`kid`), filled at runtime by
## [method DotAuthServer.adopt_ticket_trust]. Not layered: it comes from the backbone only.
var ticket_public_keys: Dictionary = {}

## Let [constant Strategy.TICKET] start with no [member server_id] or key and adopt both
## later through [method DotAuthServer.adopt_ticket_trust]. Signed-in joins are refused
## until then; a ticket is never verified without an audience.
@export var adopt_ticket_trust: bool = false

## File the adopted server id and issuer keys are kept in, so a restart verifies
## tickets before the backbone answers. Bound to [member backbone_url]: a cache written
## for another backbone is ignored. Empty keeps nothing.
@export var ticket_trust_cache: String = ""

## Where a client asks for connect tickets; empty means the backbone's own issuer. The bearer token goes there, so it is layered like [member backbone_url], never from a query string.
@export var ticket_issuer_url: String = ""

## Seconds a ticket stays valid after issue; short on purpose, as it only spans "asked for" to "connected".
@export_range(30, 3600, 30) var ticket_ttl_sec: int = 300

## Clock skew tolerated when checking ticket times.
@export_range(0, 600, 10) var ticket_leeway_sec: int = 60

## Remember spent ticket ids this long to refuse replays; must exceed [member ticket_ttl_sec] or a ticket outlives the memory of its use.
@export_range(60, 7200, 60) var ticket_replay_memory_sec: int = 900

## Most spent ticket ids remembered; past it new tickets are refused until old ones
## expire, since forgetting one early would let it be replayed.
@export_range(1000, 1000000, 1000) var ticket_replay_max: int = 100000

## Refuse a ticket that is not bound to this connection's challenge nonce. Off while
## older clients, which ask for unbound tickets, are still about.
@export var require_ticket_binding: bool = false

## Accept guests when authentication fails or is unavailable. Turn off where bans must mean something: a guest can return as a different guest.
@export var allow_guests: bool = false

## Path to the local accounts file, for [constant Strategy.LOCAL].
@export var local_accounts_path: String = "user://dot_auth_accounts.json"

## The issuer this server tells who is playing on it; empty means it does not.
##
## It is what makes [member single_session] mean anything: a ticket is only an intention to connect. Same base URL clients ask for tickets; needs [member session_report_key].
@export var session_report_url: String = ""

## Secret this server presents to the issuer when reporting its roster; per server, file-only. Without it anyone could report any player onto any server and lock them out for the lease.
@export var session_report_key: String = ""

## Seconds between roster reports; at most half of the issuer's [member session_lease_sec] (defaults 60 against 300), or a lost report drops everyone from the issuer's records.
@export_range(5.0, 3600.0, 5.0) var session_report_interval_sec: float = 60.0

@export_group("Local profiles")

## Let visitors make an account that lives on THIS server only, via [DotLocalProfiles].
##
## Independent of [member strategy] (it is a [DotAuthProvider]), so backbone tickets and local profiles work together. Not [constant Strategy.LOCAL], an operator-maintained username and password file.
@export var allow_local_profiles: bool = false

## Where local profiles are stored. Server side; contains hashed credentials.
@export var local_profiles_path: String = "user://dot_local_profiles.json"

## Refuse to create more than this many; 0 removes the limit. The backstop behind [member auth_attempts_per_minute].
@export_range(0, 1000000, 100) var max_local_profiles: int = 5000

## Let a visitor mint a profile, rather than only use one they already hold; off means the operator creates them from the console.
@export var local_profile_signup: bool = true

## Where a CLIENT keeps the secrets servers issued it, keyed by server. Here because a game configures one [DotAuthConfig] for both halves; the wrong place silently loses every profile.
@export var local_profile_client_path: String = "user://dot_local_profiles.dat"

@export_group("Issuer")

## PEM private key that mints tickets. Issuer only, never ship this in a game.
@export_multiline var issuer_private_key: String = ""

## Name written into the ticket's [code]iss[/code] claim.
@export var issuer_name: String = "dot-auth"

## Key id written into the ticket header, so verifiers can pick a key during
## rotation.
@export var issuer_key_id: String = "default"

## Refuse a ticket for one server while the player is on another: one account, one seat.
##
## It lives on the issuer, the only participant that sees every server. Only as good as the reporting: an unreporting server holds its players for [member session_lease_sec]. A ticket for the server they are already on is always granted so a crashed client can reconnect. See [member session_report_url].
@export var single_session: bool = false

## Seconds a session stays live without word from a server; at least [member ticket_ttl_sec], or a player could hold a live ticket for one server and get a second for another.
@export_range(30, 86400, 30) var session_lease_sec: int = 300

@export_group("Integration API")

## Server-scoped integration token for the backbone's `/api/integration/v1/*` and `/api/content/server/integration/*` endpoints; a leak cannot be pointed at another listing.
@export var integration_token: String = ""

## Seconds between stat reports to the backbone. 0 disables reporting.
@export_range(0.0, 3600.0, 5.0) var report_interval_sec: float = 60.0

## Also report the player roster, not just counts. Needs the `SERVER_USERS` scope (personal data about third parties); leave off unless players expect to be listed.
@export var report_roster: bool = false

@export_group("Rate limits")

## Authentication attempts per client per minute.
@export_range(1, 100, 1) var auth_attempts_per_minute: int = 10

## Backbone requests per minute from this process, so a retry loop cannot get the integration credential rate-limited or revoked.
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


## The addon name [DotAddonConfig] turns into the folder `dot_auth`.
const CFG_ADDON := "dot-auth"


## Applies [param file_name] from `cfg/addons/dot_auth/`, then the operator's `cfg/server/addons/dot_auth/`.
## A flat [param legacy_dir]/[param file_name] is still read (one WARN) while no new copy exists.
## Secrets stay file-only: the environment and command line still refuse them.
func apply_cfg_file(file_name: String = "auth.yml", legacy_dir: String = "res://cfg") -> DotResult:
	return DotAddonConfig.apply_file(CFG_ADDON, file_name, legacy_dir, apply_dictionary)


## [method apply_cfg_file], then `DOT_AUTH_*`, `--auth-*` and validation: [method DotConfig.load_layered] for the yml layout.
func load_cfg(file_name: String = "auth.yml", legacy_dir: String = "res://cfg") -> DotResult:
	unknown_keys = PackedStringArray()
	var file_res := apply_cfg_file(file_name, legacy_dir)
	if not file_res.ok:
		return file_res
	apply_env()
	apply_cli()
	var valid := validate()
	if not valid.ok:
		return valid.wrap("Configuration is invalid.")
	return DotResult.success(self)


func validate() -> DotResult:
	match strategy:
		Strategy.TICKET:
			if adopt_ticket_trust:
				pass
			elif server_id == "":
				return DotResult.fail(
					DotError.CODE_INVALID,
					"TICKET authentication needs a server_id.",
					"tickets are scoped to one server; without an id this "
					+ "server would accept tickets minted for any other"
				)
			if ticket_public_key.strip_edges() == "" and not adopt_ticket_trust:
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

	var audiences := _validate_audiences()
	if not audiences.ok:
		return audiences

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


func _validate_audiences() -> DotResult:
	for entry in first_party_audiences:
		if not is_audience(entry):
			return DotResult.fail(
				DotError.CODE_INVALID,
				"first_party_audiences entries must look like server:<id> or app:<id>.",
				"got %s" % entry
			)

	if join_audience != "" and not is_audience(join_audience):
		return DotResult.fail(
			DotError.CODE_INVALID,
			"join_audience must look like server:<id> or app:<id>.",
			"got %s" % join_audience
		)
	return DotResult.success(null)


## Warns about settings that are legal but risky. Called at startup.
func warn_about_risky_settings() -> void:
	if strategy == Strategy.INTROSPECT:
		DotLog.warn(
			"auth",
			"INTROSPECT strategy: only clients that list this server in "
			+ "first_party_audiences will join, each with a single-use join token. "
			+ "Only run this on servers you operate.",
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


## Whether [param value] is a backbone integration target, `<kind>:<id>`.
static func is_audience(value: String) -> bool:
	var parts := value.split(":")
	if parts.size() != 2 or parts[0] == "" or not parts[1].is_valid_int():
		return false
	for ch in parts[0]:
		if not ((ch >= "a" and ch <= "z") or (ch >= "A" and ch <= "Z")):
			return false
	return int(parts[1]) > 0 and not parts[1].begins_with("0")


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
