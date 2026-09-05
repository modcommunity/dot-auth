@tool
class_name DotAuthIssuer
extends Node

## Mints connect tickets. The publisher runs one; game servers do not.
##
## The missing piece between "the backbone knows who you are" and "a community
## game server can find out without holding your account token". A client sends
## its backbone access token here — first-party, same trust as any of the
## publisher's own services — and gets back a [DotAuthTicket] scoped to one
## server, valid for minutes, verifiable offline by anyone with the public key.
##
## [b]Operationally.[/b] Run it headless next to whatever else the publisher
## hosts. It needs the private key and outbound access to the backbone, and it is
## the only component that needs either. Game-server operators get the public key
## and nothing else.
##
## [codeblock]
## godot --headless --path . res://examples/issuer.tscn -- \
##     --auth-issuer-private-key-file keys/issuer.key --auth-server-port 8787
## [/codeblock]
##
## [b]On the built-in HTTP server.[/b] [member listen_port] starts a small
## [TCPServer]-based endpoint so this runs standalone. It speaks enough HTTP/1.1
## for one JSON POST and is deliberately not a general web server — no TLS, no
## keep-alive, no chunked encoding. [b]Put it behind a reverse proxy in
## production[/b]; that is where TLS, real request limits and access logs belong.
## Leave the port at 0 and call [method issue_for_token] directly to embed it in
## something else.
##
## [b]On sessions.[/b] Because every ticket passes through here, this is the one
## place that can know a player is on some server already — and with
## [member DotAuthConfig.single_session] it refuses a ticket for a second one.
## A ticket opens a session; a server confirms and later closes it by reporting
## its roster to [code]POST /session[/code] with a key this issuer holds for it;
## a player closes their own with [code]POST /session/release[/code]; and a
## lease closes whatever nobody reported on. See [method report_sessions].

const CHANNEL := "auth.issuer"

## Emitted for every ticket minted, for audit logging.
signal ticket_issued(identity: DotAuthIdentity, server_id: String)

## Emitted when a request is refused, so abuse is visible.
signal request_refused(reason: String, address: String)

## Emitted when a ticket is refused because the player is on another server.
signal session_conflict(uid: String, held_server: String, wanted_server: String)

@export_group("Configuration")

@export var config: DotAuthConfig = null

@export var config_file: String = "user://dot_auth_issuer.json"

## Read the signing key from this file instead of [member DotAuthConfig.issuer_private_key].
##
## Preferred: a key in a file with restricted permissions beats a key in a config
## the process might dump into a log.
@export_global_file("*.key", "*.pem") var private_key_file: String = ""

@export_group("Listener")

## TCP port for the built-in endpoint. 0 disables it.
@export var listen_port: int = 0

@export var bind_address: String = "127.0.0.1"

## Server ids this issuer will mint tickets for. Empty allows any.
##
## Worth populating. An open issuer will mint a ticket naming any string a caller
## sends, and a server id nobody controls is a ticket nobody can misuse — but an
## allow-list also stops a typo'd id from producing tickets that silently never
## verify anywhere.
@export var allowed_server_ids: PackedStringArray = PackedStringArray()

## JSON file of [code]{"server id": "key"}[/code]: the servers allowed to report
## their rosters, and what each presents to prove it is itself.
##
## A file rather than an inspector field for the same reason the signing key is:
## these are secrets, and a scene is not where secrets go. One key per server,
## so a leaked key can be rotated for one operator without touching the rest, and
## so a report can only ever speak for the server whose key signed it. Add more at
## runtime with [method add_server_key].
@export_global_file("*.json") var session_keys_file: String = ""

@export_group("Limits")

## Tickets per access token per minute.
@export_range(1, 600, 1) var tickets_per_minute: int = 20

## Largest request body accepted, in bytes.
##
## A ticket request is a few dozen bytes. A roster report is a uid per player,
## and a full server's worth runs to about twenty kilobytes, which is what sets
## the default.
@export var max_request_bytes: int = 32768

## Seconds a connection may take to deliver a complete request.
##
## Bounds the whole request rather than the gaps between reads: a sender that
## dribbles one byte per second never looks idle, and would otherwise hold a slot
## indefinitely while staying under every per-read limit.
@export_range(1.0, 120.0, 1.0) var request_timeout_sec: float = 10.0

## Connections held at once. Further callers are refused with 503.
##
## Refusing beats queueing. Every held connection is polled every frame, so an
## unbounded list turns a handful of sockets nobody ever writes to into the
## issuer's frame budget.
@export_range(1, 4096, 1) var max_connections: int = 64

var _http: DotHttp = null
var _tcp: TCPServer = null
var _private_key: String = ""
var _limiter: DotRateLimiter = null
var _connections: Array[Dictionary] = []
var _issued_count: int = 0

## server id -> key, for roster reports.
var _server_keys: Dictionary = {}

## uid -> {"server": String, "until": float, "confirmed": bool}
##
## Where each player is, as far as this issuer knows. A session begins
## unconfirmed when a ticket is minted — the player has said where they are
## going — and becomes confirmed when that server reports them. The distinction
## matters for what a report may end: see [method report_sessions].
var _sessions: Dictionary = {}
var _last_session_sweep: float = 0.0
var _conflict_count: int = 0


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	var started := start()
	if not started.ok:
		DotLog.result(CHANNEL, "issuer start", started)
		set_process(false)


func start() -> DotResult:
	if config == null:
		config = DotAuthConfig.new()

	if config_file != "":
		config.apply_json_file(config_file)
	config.apply_env()
	config.apply_cli()

	# Read the key from a file when told to. Checked before the inline config
	# value so a deployment can leave the config in version control.
	if private_key_file != "":
		if not FileAccess.file_exists(private_key_file):
			return DotResult.fail(
				DotError.CODE_IO,
				"The signing key file does not exist.",
				private_key_file
			)
		_private_key = FileAccess.get_file_as_string(private_key_file)
	else:
		_private_key = config.issuer_private_key

	if _private_key.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID,
			"The issuer has no signing key.",
			"set private_key_file, or DotAuthConfig.issuer_private_key"
		)

	# Prove the key works now rather than on the first player's join.
	var probe := DotJwt.encode_rs256({"probe": 1}, _private_key)
	if not probe.ok:
		return probe.wrap("The signing key is unusable.")

	_http = DotHttp.new()
	_http.name = "IssuerHttp"
	_http.timeout_sec = 15.0
	add_child(_http)

	_limiter = DotRateLimiter.new(
		float(tickets_per_minute) / 60.0, float(tickets_per_minute)
	)

	if session_keys_file != "":
		var keys := _load_server_keys()
		if not keys.ok:
			return keys

	if config.single_session and _server_keys.is_empty():
		# Legal, and worth a line: the option works, but every hold is the lease
		# long and nothing ever ends one early.
		DotLog.warn(
			CHANNEL,
			"single_session is on but no server can report its roster — players "
			+ "are held for the lease after every ticket, whether or not they "
			+ "are still playing",
			{"lease": config.session_lease_sec}
		)

	if listen_port > 0:
		var listen := _start_listener()
		if not listen.ok:
			return listen

	DotLog.info(
		CHANNEL,
		"issuer ready",
		{
			"backbone": config.backbone_url,
			"port": listen_port if listen_port > 0 else "embedded",
			"ttl": config.ticket_ttl_sec,
			"servers": Array(allowed_server_ids) if not allowed_server_ids.is_empty() else "any",
			"single_session": config.single_session,
			"reporting_servers": _server_keys.size(),
		}
	)

	return DotResult.success(self)


# --- Issuing ---------------------------------------------------------------

## Validates a backbone access token and mints a ticket for [param server_id].
##
## The whole operation, without any HTTP of our own — call this directly to embed
## the issuer in an existing service.
func issue_for_token(
	access_token: String,
	server_id: String
) -> DotResult:
	if server_id.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID, "No server id."
		)

	if not allowed_server_ids.is_empty() and not allowed_server_ids.has(server_id):
		return DotResult.fail(
			DotError.CODE_FORBIDDEN,
			"This issuer does not serve that server.",
			server_id
		)

	var resolved := await _resolve_token(access_token)
	if not resolved.ok:
		return resolved

	return issue_for_identity(resolved.value, server_id)


## Mints a ticket for a player whose identity is already established.
##
## The half of [method issue_for_token] after the backbone has answered. Public
## so a service that already knows who is asking — the backbone itself, were the
## issuer folded into it — can mint without a second round trip, and so the
## session rules can be exercised without a backbone at all.
func issue_for_identity(
	identity: DotAuthIdentity,
	server_id: String
) -> DotResult:
	if identity == null or not identity.is_valid():
		return DotResult.fail(
			DotError.CODE_INVALID, "Cannot issue a ticket for an invalid identity."
		)

	if server_id.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID, "No server id."
		)

	if config.single_session:
		var held := session_of(identity.uid)
		if held != "" and held != server_id:
			_conflict_count += 1
			DotLog.info(
				CHANNEL,
				"ticket refused: the player is on another server",
				{"user": identity.label(), "on": held, "wanted": server_id}
			)
			session_conflict.emit(identity.uid, held, server_id)
			# The server is named so the player knows what to leave. It is
			# their own whereabouts; nothing about anybody else is disclosed.
			return DotResult.fail(
				DotError.CODE_FORBIDDEN,
				"You are already connected to %s. Leave it before joining "
				% held + "another server.",
				held
			)

	var ticket := DotAuthTicket.issue(
		identity,
		server_id,
		_private_key,
		config.issuer_name,
		config.ticket_ttl_sec,
		config.issuer_key_id
	)

	if not ticket.ok:
		return ticket

	_issued_count += 1

	# Tracked whether or not the rule is on, so turning it on later starts from
	# what is known rather than from nothing, and so describe() can answer.
	_hold_session(identity.uid, server_id, false)

	DotLog.info(
		CHANNEL,
		"ticket issued",
		{"user": identity.label(), "server": server_id}
	)

	ticket_issued.emit(identity, server_id)

	return DotResult.success({
		"ticket": ticket.value,
		"expiresIn": config.ticket_ttl_sec,
		"user": identity.to_dict(),
	})


## Turns a backbone access token into the identity behind it, or a refusal.
##
## Rate-limited per token, so one compromised account cannot exhaust the budget
## for everyone; the key is hashed so the token itself is not sitting in a
## dictionary.
func _resolve_token(access_token: String) -> DotResult:
	if access_token.strip_edges() == "":
		return DotResult.fail(DotError.CODE_AUTH, "No access token.")

	var key := DotHash.sha256_text(access_token).substr(0, 32)
	if not _limiter.allow(key):
		var err := DotError.make(
			DotError.CODE_RATE_LIMITED, "Too many ticket requests."
		)
		err.retry_after = _limiter.retry_after(key)
		return DotResult.failure(err)

	var res := await _http.get_json(
		config.me_endpoint(), {"Authorization": "Bearer %s" % access_token}
	)

	if not res.ok:
		# 401 from the backbone means the player's token is bad, which is a 401
		# from us too — not a 500. Anything else is our problem, not theirs.
		if res.error != null and res.error.http_status == 401:
			return DotResult.fail(
				DotError.CODE_AUTH, "That sign-in is no longer valid."
			)
		return res.wrap("Could not check the sign-in with the backbone.")

	var payload: Variant = res.value
	if not (payload is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE, "The backbone sent an unexpected response."
		)

	var d := payload as Dictionary
	var user: Variant = d.get("data", d)
	if user is Dictionary and (user as Dictionary).has("user"):
		user = (user as Dictionary)["user"]

	return DotAuthIdentity.from_backbone_user(
		user if user is Dictionary else {}
	)


# --- Sessions --------------------------------------------------------------

## Registers a server that may report its roster, and the key it presents.
func add_server_key(server_id: String, key: String) -> DotResult:
	if server_id.strip_edges() == "" or key.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID, "A server key needs a server id and a key."
		)
	if key.length() < 16:
		# A key an operator typed from memory is a key somebody can guess, and
		# guessing one lets them report any player as being anywhere.
		return DotResult.fail(
			DotError.CODE_INVALID,
			"A server key must be at least 16 characters.",
			server_id
		)
	_server_keys[server_id] = key
	return DotResult.success(server_id)


func remove_server_key(server_id: String) -> void:
	_server_keys.erase(server_id)


## Whether [param key] is the key held for [param server_id].
##
## An unknown server and a wrong key answer identically, and the comparison is
## constant-time either way, so a caller learns neither which servers report nor
## how much of a key it got right.
func authorize_server(server_id: String, key: String) -> bool:
	var expected := str(_server_keys.get(server_id, ""))
	var known := _server_keys.has(server_id)
	# Compared against something of the right shape even when unknown, so the
	# time taken does not say whether the id exists.
	var compare_to := expected if known else key
	var same := DotHash.constant_time_equal(
		key.to_utf8_buffer(), compare_to.to_utf8_buffer()
	)
	return known and same and key != ""


## Which server [param uid] is on, or [code]""[/code].
func session_of(uid: String) -> String:
	_sweep_sessions()
	var entry: Variant = _sessions.get(uid)
	if entry == null:
		return ""
	return str((entry as Dictionary)["server"])


## Every live session, uid -> server id. A copy.
func sessions() -> Dictionary:
	_sweep_sessions()
	var out := {}
	for uid in _sessions:
		out[uid] = str((_sessions[uid] as Dictionary)["server"])
	return out


## Takes a server's word for who is on it.
##
## [param uids] is the whole roster, not a change: everyone listed is on
## [param server_id] as of now, and every [i]confirmed[/i] session on that server
## not listed has ended. An empty roster is therefore how a server says it is
## empty, and what [DotAuthSessionReporter] sends on the way down.
##
## An unconfirmed session — a ticket minted, nobody arrived yet — is left alone
## by a report that omits it. The report is truthful (they are not there yet) and
## acting on it would let a player fetch tickets for two servers in the seconds
## between the first being minted and the first roster mentioning them. It lapses
## on its own if they never arrive.
##
## A listed player the issuer had on a [i]different[/i] server is moved. The
## report is the truth about where they are; whatever the record said, they got
## there somehow, and refusing to believe it would hold them on a server they
## have left.
func report_sessions(server_id: String, uids: PackedStringArray) -> DotResult:
	if server_id.strip_edges() == "":
		return DotResult.fail(DotError.CODE_INVALID, "No server id.")

	_sweep_sessions()

	var listed := {}
	for uid in uids:
		if uid.strip_edges() == "":
			continue
		listed[uid] = true
		_hold_session(uid, server_id, true)

	var ended: Array = []
	for uid in _sessions:
		var entry: Dictionary = _sessions[uid]
		if str(entry["server"]) != server_id or listed.has(uid):
			continue
		if bool(entry["confirmed"]):
			ended.append(uid)

	for uid in ended:
		_sessions.erase(uid)

	DotLog.debug(
		CHANNEL,
		"roster reported",
		{"server": server_id, "players": listed.size(), "ended": ended.size()}
	)

	return DotResult.success({"held": listed.size(), "ended": ended.size()})


## Ends [param uid]'s session, wherever it is. True if there was one.
##
## A player leaving is the common case and the one that does not wait for the
## server's next report. If they are in fact still playing, the next report puts
## them back.
func release_session(uid: String) -> bool:
	_sweep_sessions()
	return _sessions.erase(uid)


func _hold_session(uid: String, server_id: String, confirmed: bool) -> void:
	var until := Time.get_unix_time_from_system() + float(config.session_lease_sec)
	var existing: Variant = _sessions.get(uid)

	# A ticket for the server a confirmed player is already on — a reconnect —
	# extends the session and does not demote it to unconfirmed, or the next
	# roster to omit them for a moment would be unable to end it.
	if not confirmed and existing != null \
		and str((existing as Dictionary)["server"]) == server_id:
		confirmed = bool((existing as Dictionary)["confirmed"])

	_sessions[uid] = {
		"server": server_id,
		"until": until,
		"confirmed": confirmed,
	}


## Forgets sessions whose lease has run out. Cheap, so it runs on every read.
func _sweep_sessions() -> void:
	var now := Time.get_unix_time_from_system()
	if now - _last_session_sweep < 1.0:
		return
	_last_session_sweep = now

	var dead: Array = []
	for uid in _sessions:
		if float((_sessions[uid] as Dictionary)["until"]) <= now:
			dead.append(uid)

	for uid in dead:
		_sessions.erase(uid)


func _load_server_keys() -> DotResult:
	if not FileAccess.file_exists(session_keys_file):
		return DotResult.fail(
			DotError.CODE_IO,
			"The session keys file does not exist.",
			session_keys_file
		)

	var read := DotPaths.read_json(session_keys_file)
	if not read.ok:
		return read.wrap("Could not read the session keys file.")

	var data: Variant = read.value
	if not (data is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE,
			"The session keys file must be a JSON object of server id -> key.",
			session_keys_file
		)

	for server_id in (data as Dictionary):
		var added := add_server_key(str(server_id), str((data as Dictionary)[server_id]))
		if not added.ok:
			return added.wrap("The session keys file has a bad entry.")

	return DotResult.success(_server_keys.size())


# --- Built-in listener -----------------------------------------------------

func _start_listener() -> DotResult:
	if not DotPlatform.can_listen():
		return DotResult.fail(
			DotError.CODE_UNSUPPORTED,
			"This platform cannot listen for connections."
		)

	_tcp = TCPServer.new()
	var err := _tcp.listen(listen_port, bind_address)
	if err != OK:
		return DotResult.failure(
			DotError.from_engine(
				err, "listening on %s:%d" % [bind_address, listen_port]
			)
		)

	if bind_address != "127.0.0.1" and bind_address != "localhost":
		DotLog.warn(
			CHANNEL,
			"the issuer is listening on a public interface without TLS — put it "
			+ "behind a reverse proxy",
			{"bind": bind_address}
		)

	set_process(true)
	return DotResult.success(true)


func _process(_delta: float) -> void:
	if _tcp == null:
		return

	while _tcp.is_connection_available():
		var peer := _tcp.take_connection()
		if peer == null:
			continue

		if _connections.size() >= max_connections:
			_respond(peer, 503, {"error": "Too many connections."})
			continue

		_connections.append({
			"peer": peer,
			"buffer": PackedByteArray(),
			"address": peer.get_connected_host(),
			"opened_at": Time.get_ticks_msec(),
			"continued": false,
			"dispatched": false,
		})

	var still_open: Array[Dictionary] = []

	for conn in _connections:
		if _poll_connection(conn):
			still_open.append(conn)
		elif not bool(conn["dispatched"]):
			# A dispatched connection belongs to the coroutine handling it, which
			# writes the response and closes the socket itself. Closing it here
			# would cut the reply off mid-await.
			(conn["peer"] as StreamPeerTCP).disconnect_from_host()

	_connections = still_open


## Reads what has arrived and dispatches once a whole request is present.
##
## Returns false when the connection should leave the poll list — dropped,
## answered, or handed to [method _dispatch].
##
## HTTP requests are not delivered one-per-read. Parsing whatever a single poll
## happened to see treats a segment boundary as the end of the request, which is
## why the body has to be accumulated and measured against Content-Length rather
## than assumed complete.
func _poll_connection(conn: Dictionary) -> bool:
	var peer: StreamPeerTCP = conn["peer"]
	peer.poll()

	if peer.get_status() != StreamPeerTCP.STATUS_CONNECTED:
		return false

	var available := peer.get_available_bytes()
	if available > 0:
		var chunk := peer.get_data(available)
		if chunk[0] != OK:
			return false
		var buffer: PackedByteArray = conn["buffer"]
		buffer.append_array(chunk[1])
		conn["buffer"] = buffer

	var buffer_now: PackedByteArray = conn["buffer"]

	# The cap covers the accumulated request. Checking one read's worth says
	# nothing about the total: a sender that trickles bytes never trips a
	# per-read limit however much it eventually sends.
	if buffer_now.size() > max_request_bytes:
		_respond(peer, 413, {"error": "Request too large."})
		return false

	if Time.get_ticks_msec() - int(conn["opened_at"]) > int(request_timeout_sec * 1000.0):
		if not buffer_now.is_empty():
			_respond(peer, 408, {"error": "Request timed out."})
		return false

	var headers_end := _find_headers_end(buffer_now)
	if headers_end < 0:
		return true

	var head := buffer_now.slice(0, headers_end).get_string_from_utf8()
	var lines := head.split("\r\n")

	var request_line := lines[0].split(" ") if not lines.is_empty() else PackedStringArray()
	if request_line.size() < 2:
		_respond(peer, 400, {"error": "Malformed request."})
		return false

	var length_header := _header(lines, "content-length")
	var content_length := 0
	if length_header != "":
		if not length_header.is_valid_int():
			_respond(peer, 400, {"error": "Malformed Content-Length."})
			return false
		content_length = length_header.to_int()
		if content_length < 0:
			_respond(peer, 400, {"error": "Malformed Content-Length."})
			return false

	# Refuse an oversized body on its announced length rather than waiting to
	# accumulate it and refuse the same request having already paid for it.
	if headers_end + 4 + content_length > max_request_bytes:
		_respond(peer, 413, {"error": "Request too large."})
		return false

	# curl and every other client that sends this waits for the interim response
	# before writing the body — which for a body over ~1 KB is the default. Without
	# it the request only arrives after the client gives up waiting.
	if not bool(conn["continued"]) \
		and _header(lines, "expect").to_lower() == "100-continue":
		conn["continued"] = true
		peer.put_data("HTTP/1.1 100 Continue\r\n\r\n".to_utf8_buffer())

	if buffer_now.size() - (headers_end + 4) < content_length:
		return true

	var body := buffer_now.slice(
		headers_end + 4, headers_end + 4 + content_length
	).get_string_from_utf8()

	conn["dispatched"] = true
	_dispatch(conn, request_line[0], request_line[1], lines, body)
	return false


## Routes one complete request. Owns the socket from here on.
func _dispatch(
	conn: Dictionary,
	method: String,
	path: String,
	lines: PackedStringArray,
	body: String
) -> void:
	var peer: StreamPeerTCP = conn["peer"]
	var address: String = conn["address"]

	# Health check, so a load balancer has something to poll that does not mint
	# anything and does not need a credential.
	if method == "GET" and path.begins_with("/health"):
		_respond(peer, 200, {"ok": true, "issued": _issued_count})
		return

	if method != "POST":
		_respond(peer, 404, {"error": "Not found."})
		return

	var bearer := _header(lines, "authorization")

	if not bearer.to_lower().begins_with("bearer "):
		request_refused.emit("no bearer token", address)
		_respond(peer, 401, {"error": "Sign in first."})
		return

	var token := bearer.substr(7).strip_edges()

	var parsed: Variant = JSON.parse_string(body)
	if not (parsed is Dictionary):
		_respond(peer, 400, {"error": "Expected a JSON body."})
		return

	var request := parsed as Dictionary
	var server_id := str(request.get("serverId", ""))
	var res: DotResult = null

	if path.begins_with("/ticket"):
		res = await issue_for_token(token, server_id)
	elif path.begins_with("/session/release"):
		res = await _release_for_token(token)
	elif path.begins_with("/session"):
		res = _report_for_server(token, server_id, request, address)
	else:
		_respond(peer, 404, {"error": "Not found."})
		return

	if not res.ok:
		request_refused.emit(res.error.message, address)
		_respond(
			peer,
			_status_for(res.error),
			{"error": res.error.message, "code": res.error.code}
		)
		return

	_respond(peer, 200, res.value)


## [code]POST /session[/code]: a server's roster, under its own key.
##
## The bearer is the server's key rather than a player's token. Rate-limited
## under the server's name so a stuck reporter cannot crowd out tickets, and
## refused before the roster is looked at when the key is wrong.
func _report_for_server(
	key: String,
	server_id: String,
	request: Dictionary,
	address: String
) -> DotResult:
	if server_id.strip_edges() == "":
		return DotResult.fail(DotError.CODE_INVALID, "No server id.")

	if not _limiter.allow("server:" + server_id):
		var err := DotError.make(
			DotError.CODE_RATE_LIMITED, "Too many roster reports."
		)
		err.retry_after = _limiter.retry_after("server:" + server_id)
		return DotResult.failure(err)

	if not authorize_server(server_id, key):
		DotLog.warn(
			CHANNEL,
			"a roster report presented a key this issuer does not hold",
			{"server": server_id, "from": address}
		)
		return DotResult.fail(
			DotError.CODE_AUTH, "That server key is not recognised."
		)

	var users: Variant = request.get("users", [])
	if not (users is Array):
		return DotResult.fail(
			DotError.CODE_INVALID, "'users' must be a list of uids."
		)

	var uids := PackedStringArray()
	for u in (users as Array):
		uids.append(str(u))

	return report_sessions(server_id, uids)


## [code]POST /session/release[/code]: a player ending their own session.
##
## Resolved through the backbone like a ticket request, so the only session a
## token can end is the one belonging to the account behind it.
func _release_for_token(access_token: String) -> DotResult:
	var resolved := await _resolve_token(access_token)
	if not resolved.ok:
		return resolved

	var identity: DotAuthIdentity = resolved.value
	var had := release_session(identity.uid)

	DotLog.info(
		CHANNEL,
		"session released by the player",
		{"user": identity.label(), "had_one": had}
	)

	return DotResult.success({"released": had})


## Index of the CRLFCRLF ending the headers, or -1 while they are still arriving.
##
## Scanned over the bytes rather than a decoded string: a body split mid-UTF-8
## decodes to a replacement character, which would shift every later offset and
## desynchronise the Content-Length arithmetic.
static func _find_headers_end(buffer: PackedByteArray) -> int:
	for i in range(0, maxi(0, buffer.size() - 3)):
		if buffer[i] == 13 and buffer[i + 1] == 10 \
			and buffer[i + 2] == 13 and buffer[i + 3] == 10:
			return i
	return -1


## First value for [param name], matched case-insensitively as HTTP requires.
static func _header(lines: PackedStringArray, name: String) -> String:
	var prefix := name.to_lower() + ":"
	for i in range(1, lines.size()):
		if lines[i].to_lower().begins_with(prefix):
			return lines[i].substr(prefix.length()).strip_edges()
	return ""


func _status_for(error: DotError) -> int:
	match error.code:
		DotError.CODE_AUTH: return 401
		DotError.CODE_FORBIDDEN: return 403
		DotError.CODE_RATE_LIMITED: return 429
		DotError.CODE_INVALID: return 400
		_: return 502


func _respond(peer: StreamPeerTCP, status: int, body: Dictionary) -> void:
	var text := JSON.stringify(body)
	var bytes := text.to_utf8_buffer()

	var response := "HTTP/1.1 %d %s\r\n" % [status, _reason(status)]
	response += "Content-Type: application/json\r\n"
	response += "Content-Length: %d\r\n" % bytes.size()
	# No keep-alive: this is a single-shot endpoint and pipelining would need
	# real request framing this does not implement.
	response += "Connection: close\r\n"
	response += "\r\n"

	peer.put_data(response.to_utf8_buffer())
	peer.put_data(bytes)
	peer.disconnect_from_host()


static func _reason(status: int) -> String:
	match status:
		200: return "OK"
		400: return "Bad Request"
		401: return "Unauthorized"
		403: return "Forbidden"
		404: return "Not Found"
		408: return "Request Timeout"
		413: return "Payload Too Large"
		429: return "Too Many Requests"
		502: return "Bad Gateway"
		503: return "Service Unavailable"
		_: return "Error"


func describe() -> Dictionary:
	return {
		"listening": _tcp != null,
		"port": listen_port,
		"issued": _issued_count,
		"connections": _connections.size(),
		"ttl": config.ticket_ttl_sec if config != null else 0,
		"servers": Array(allowed_server_ids),
		"single_session": config.single_session if config != null else false,
		"sessions": sessions().size(),
		"conflicts": _conflict_count,
		"reporting_servers": _server_keys.keys(),
	}
