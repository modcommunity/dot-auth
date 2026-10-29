@tool
## Base of [DotAuthServer]: the issuer-key trust (adopt, fetch, revoke, cache, look up a key by `kid`).
## Path-based, no class_name: it exists to keep each script under the size budget.
extends Node

const CHANNEL := "auth.server"

## A ticket named a key id this server does not hold: the issuer rotated its key.
## The host refetches the issuer's keys (from its own backbone, never the client).
signal ticket_key_wanted(kid: String)

@export_group("Configuration")

@export var config: DotAuthConfig = null

var _http: DotHttp = null

var _started: bool = false

## How often adopted issuer keys are refetched, and the least time between two fetches
## an unknown `kid` may cause.
const TICKET_KEYS_REFRESH_SEC := 900.0
const TICKET_KEYS_MIN_GAP_MSEC := 60_000

## "config" when auth.yml named the server id (it then wins over the site's).
var _server_id_source := ""
var _keys_fetched_msec := -TICKET_KEYS_MIN_GAP_MSEC
var _keys_fetching := false
## The site's `refreshSec`, clamped, so a revocation reaches this server in time.
var _keys_refresh_sec := TICKET_KEYS_REFRESH_SEC

## Key ids the issuer revoked: never trusted again, kept in the trust cache.
var _revoked_kids: Dictionary = {}


## True when tickets can be verified: a server id and at least one issuer key.
func ticket_trust_ready() -> bool:
	if config == null or config.server_id == "":
		return false
	return config.ticket_public_key.strip_edges() != "" \
		or not config.ticket_public_keys.is_empty()


## Adopts the server id and issuer keys ([code]{kid: pem}[/code]) the host fetched from
## its backbone. An explicit [member DotAuthConfig.server_id] or
## [member DotAuthConfig.ticket_public_key] wins; only public-key PEMs are taken.
func adopt_ticket_trust(server_id: String, keys: Dictionary) -> DotResult:
	if config == null:
		return DotResult.fail(DotError.CODE_STATE, "No configuration.")
	var ring := {}
	for kid in keys:
		var pem := str(keys[kid])
		if str(kid) == "" or not pem.contains("BEGIN PUBLIC KEY") or pem.contains("PRIVATE"):
			return DotResult.fail(
				DotError.CODE_INVALID, "Issuer keys must be public-key PEMs with a key id."
			)
		if not _revoked_kids.has(str(kid)):
			ring[str(kid)] = pem
	var sid := server_id.strip_edges()
	if sid != "" and not sid.is_valid_int():
		return DotResult.fail(DotError.CODE_INVALID, "A server id is a number.", sid)
	var pinned := _server_id_source == "config" or (not _started and config.server_id != "")
	if sid != "" and sid != config.server_id:
		if pinned:
			DotLog.warn(CHANNEL, "auth.yml's server_id differs from the site's; keeping auth.yml's", {
				"configured": config.server_id, "site": sid,
			})
		else:
			config.server_id = sid
	if not ring.is_empty():
		config.ticket_public_keys = ring
	for kid in _revoked_kids:
		config.ticket_public_keys.erase(kid)
	_save_ticket_trust_cache()
	DotLog.info(CHANNEL, "ticket trust adopted", {
		"server_id": config.server_id,
		"keys": ",".join(PackedStringArray(config.ticket_public_keys.keys())),
		"explicit_key": config.ticket_public_key.strip_edges() != "",
	})
	return DotResult.success(ticket_trust_ready())


## Fetches the issuer's public keys from this server's own backbone
## (`/api/app/v1/auth/ticket-keys`), never from a client. HTTPS unless loopback;
## at most once a minute unless [param force].
func refresh_ticket_keys(force: bool = false) -> DotResult:
	if config == null or _http == null:
		return DotResult.fail(DotError.CODE_STATE, "Not fetching issuer keys now.")
	if _keys_fetching:
		while _keys_fetching and is_inside_tree():
			await get_tree().process_frame
		return DotResult.success(ticket_trust_ready()) if not config.ticket_public_keys.is_empty() \
			else DotResult.fail(DotError.CODE_STATE, "The issuer's keys could not be fetched.")
	if not force and Time.get_ticks_msec() - _keys_fetched_msec < TICKET_KEYS_MIN_GAP_MSEC:
		return DotResult.fail(DotError.CODE_RATE_LIMITED, "Issuer keys were fetched recently.")
	var url := config.app_endpoint("auth/ticket-keys")
	if not _trusted_key_url(url):
		DotLog.error(CHANNEL, "refusing to fetch issuer keys over plain HTTP", {
			"url": url, "fix": "an https backbone_url, or issuer_public_key_file",
		})
		return DotResult.fail(DotError.CODE_FORBIDDEN, "Issuer keys need HTTPS.", url)
	_keys_fetching = true
	_keys_fetched_msec = Time.get_ticks_msec()
	var res: DotResult = await _http.get_json(url)
	_keys_fetching = false
	if not res.ok:
		DotLog.warn(CHANNEL, "could not fetch the issuer's keys", {
			"url": url, "why": res.error.message, "have": config.ticket_public_keys.size(),
		})
		return res
	revoke_ticket_keys(parse_ticket_revoked(res.value))
	_apply_keys_refresh(parse_ticket_refresh_sec(res.value))
	var ring := parse_ticket_keys(res.value)
	if ring.is_empty():
		DotLog.warn(CHANNEL, "the backbone publishes no ticket keys yet", {"url": url})
		return DotResult.fail(DotError.CODE_STATE, "The site publishes no ticket keys.")
	return adopt_ticket_trust("", ring)


## [code]{kid: pem}[/code] from a `ticket-keys` reply (enveloped or not), RS256 only.
static func parse_ticket_keys(reply: Variant) -> Dictionary:
	var ring := {}
	if not (reply is Dictionary):
		return ring
	var body: Dictionary = reply
	if body.get("data") is Dictionary:
		body = body["data"]
	var keys: Variant = body.get("keys")
	if not (keys is Array):
		return ring
	for k in keys:
		if k is Dictionary and str(k.get("alg", "")) == "RS256" and str(k.get("kid", "")) != "" \
				and str(k.get("pem", "")).contains("BEGIN PUBLIC KEY") \
				and not str(k.get("pem", "")).contains("PRIVATE"):
			ring[str(k["kid"])] = str(k["pem"])
	return ring


## Key ids a `ticket-keys` reply lists under `revoked`.
static func parse_ticket_revoked(reply: Variant) -> PackedStringArray:
	var out := PackedStringArray()
	var body: Variant = reply
	if body is Dictionary and (body as Dictionary).get("data") is Dictionary:
		body = body["data"]
	if body is Dictionary and (body as Dictionary).get("revoked") is Array:
		for kid in body["revoked"]:
			if kid is String and kid != "":
				out.append(kid)
	return out


## The `refreshSec` a `ticket-keys` reply asks for, or 0.
static func parse_ticket_refresh_sec(reply: Variant) -> float:
	var body: Variant = reply
	if body is Dictionary and (body as Dictionary).get("data") is Dictionary:
		body = body["data"]
	if body is Dictionary:
		return _number_of(body, "refreshSec")
	return 0.0


## Never trusts [param kids] again, now or after a restart (the trust cache keeps them).
func revoke_ticket_keys(kids: PackedStringArray) -> void:
	var added := PackedStringArray()
	for kid in kids:
		if not _revoked_kids.has(kid):
			_revoked_kids[kid] = true
			added.append(kid)
		config.ticket_public_keys.erase(kid)
	if added.is_empty():
		return
	DotLog.warn(CHANNEL, "issuer keys revoked", {"kids": ",".join(added)})
	_save_ticket_trust_cache()


func _apply_keys_refresh(sec: float) -> void:
	if sec <= 0.0:
		return
	_keys_refresh_sec = clampf(sec, 300.0, 6 * 3600.0)
	var t := get_node_or_null("TicketKeysRefresh") as Timer
	if t != null and not is_equal_approx(t.wait_time, _keys_refresh_sec):
		t.wait_time = _keys_refresh_sec


static func _trusted_key_url(url: String) -> bool:
	if url.begins_with("https://"):
		return true
	for local in ["http://127.0.0.1", "http://localhost", "http://[::1]"]:
		if url.begins_with(local + ":") or url.begins_with(local + "/"):
			return true
	return false


func _load_ticket_trust_cache() -> void:
	if config.ticket_trust_cache == "" or not FileAccess.file_exists(config.ticket_trust_cache):
		return
	var parsed: Variant = JSON.parse_string(FileAccess.get_file_as_string(config.ticket_trust_cache))
	if not (parsed is Dictionary) or str(parsed.get("backbone_url", "")) != config.backbone_url:
		return
	if parsed.get("revoked") is Array:
		for kid in parsed["revoked"]:
			if kid is String and kid != "":
				_revoked_kids[kid] = true
	var keys: Variant = parsed.get("keys")
	var adopted := adopt_ticket_trust(
		str(parsed.get("server_id", "")), keys if keys is Dictionary else {}
	)
	if not adopted.ok:
		DotLog.warn(CHANNEL, "ignoring a bad ticket trust cache", {
			"path": config.ticket_trust_cache, "why": adopted.error.message,
		})


func _save_ticket_trust_cache() -> void:
	if config.ticket_trust_cache == "" or not _started:
		return
	var f := FileAccess.open(config.ticket_trust_cache, FileAccess.WRITE)
	if f == null:
		DotLog.warn(CHANNEL, "could not write the ticket trust cache", {
			"path": config.ticket_trust_cache, "err": error_string(FileAccess.get_open_error()),
		})
		return
	f.store_string(JSON.stringify({
		"backbone_url": config.backbone_url,
		"server_id": config.server_id if _server_id_source != "config" else "",
		"keys": config.ticket_public_keys,
		"revoked": _revoked_kids.keys(),
	}, "\t"))
	f.close()
	DotWeb.sync_filesystem()


## The PEM to verify [param ticket] with: the explicit key, else the ring entry its
## `kid` names. An unknown kid asks the host for a refetch and refuses this join.
func _ticket_key_for(ticket: String) -> DotResult:
	if config.ticket_public_key.strip_edges() != "":
		return DotResult.success(config.ticket_public_key)
	var peeked := DotJwt.peek(ticket)
	if not peeked.ok:
		return DotResult.fail(DotError.CODE_AUTH, "This connect ticket is not valid.", "malformed")
	var kid := str((peeked.value["header"] as Dictionary).get("kid", ""))
	if _revoked_kids.has(kid):
		return DotResult.fail(
			DotError.CODE_FORBIDDEN, "This connect ticket is not valid.", "revoked key id"
		)
	if kid == "" and config.ticket_public_keys.size() == 1:
		return DotResult.success(config.ticket_public_keys.values()[0])
	if config.ticket_public_keys.has(kid):
		return DotResult.success(config.ticket_public_keys[kid])
	ticket_key_wanted.emit(kid)
	return DotResult.fail(
		DotError.CODE_STATE,
		"This server is updating its sign-in keys. Try again in a moment.",
		"unknown ticket key id %s" % kid.substr(0, 24)
	)


static func _number_of(d: Dictionary, key: String) -> float:
	var v: Variant = d.get(key, 0)
	return float(v) if (v is int or v is float) else 0.0
