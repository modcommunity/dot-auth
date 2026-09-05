extends Node

## Runs a standalone ticket issuer.
##
## The publisher hosts one of these. It is the only component that holds the
## signing key or talks to the backbone with a player's token; game-server
## operators get the public key and nothing else.
##
## [codeblock]
## godot --headless --path . res://examples/issuer.tscn -- \
##     --auth-backbone-url https://themodcommunity.com
##
## # Exit on its own after a while, for a smoke test or a sweep:
## godot --headless --path . res://examples/issuer.tscn -- --seconds 5
## [/codeblock]
##
## Generates a keypair on first run and writes it next to the config, which is fine
## for a trial and not fine for production — see the warning it prints.

const KEY_DIR := "user://issuer_keys"

## How long to stay up, from `--seconds N`. Zero, the default, means forever.
##
## This is a daemon rather than a self-test, so it is the one example in the
## family that never exits — which means a blanket "run every example" sweep
## stalls here, as one did. A sweep can now bound it instead of relying on
## SIGTERM, which a headless Godot does not turn into a close request that a
## Node can act on.
var _seconds := 0.0

var _issuer: DotAuthIssuer


func _ready() -> void:
	DotLog.set_level(DotLog.Level.INFO)
	DotLog.timestamps = true

	var argv := OS.get_cmdline_user_args()
	var seconds_at := argv.find("--seconds")
	if seconds_at >= 0 and seconds_at + 1 < argv.size():
		_seconds = maxf(0.0, argv[seconds_at + 1].to_float())

	var private_path := KEY_DIR.path_join("issuer.key")
	var public_path := KEY_DIR.path_join("issuer.pub")

	if not FileAccess.file_exists(private_path):
		print("No signing key found; generating one.")
		var pair := DotCloudSignature_generate()
		if pair.is_empty():
			push_error("Could not generate a keypair.")
			get_tree().quit(1)
			return

		DotPaths.write_text(private_path, str(pair["private"]))
		DotPaths.write_text(public_path, str(pair["public"]))

		print("")
		print("Wrote %s" % private_path)
		print("Wrote %s" % public_path)
		print("")
		print("Give the PUBLIC key to every game server operator. They set it as")
		print("DotAuthConfig.ticket_public_key. Keep the private key here.")
		print("")

	var config := DotAuthConfig.new()
	config.apply_env()
	config.apply_cli()

	_issuer = DotAuthIssuer.new()
	_issuer.name = "Issuer"
	_issuer.config = config
	_issuer.config_file = "user://dot_auth_issuer.json"
	_issuer.private_key_file = ProjectSettings.globalize_path(private_path)
	_issuer.listen_port = 8787
	_issuer.bind_address = "127.0.0.1"

	# Populate this in a real deployment: an issuer that mints tickets naming any
	# string a caller sends will happily produce tickets no server verifies, and a
	# typo'd server id is then a login failure with nothing to point at.
	_issuer.allowed_server_ids = PackedStringArray()

	# Servers that report their rosters, for `single_session`. A JSON object of
	# server id -> key next to the signing key; absent means nobody reports and
	# the rule, if on, works on the lease alone.
	var keys_path := KEY_DIR.path_join("session_keys.json")
	if FileAccess.file_exists(keys_path):
		_issuer.session_keys_file = ProjectSettings.globalize_path(keys_path)

	_issuer.session_conflict.connect(
		func(uid: String, held: String, wanted: String) -> void:
			print("held: %s is on %s, refused %s" % [uid, held, wanted])
	)

	_issuer.ticket_issued.connect(
		func(identity: DotAuthIdentity, server_id: String) -> void:
			print("issued: %s -> %s" % [identity.label(), server_id])
	)

	_issuer.request_refused.connect(
		func(reason: String, address: String) -> void:
			print("refused: %s (%s)" % [reason, address])
	)

	add_child(_issuer)

	# The issuer starts itself in _ready(); this only reports the outcome.
	await get_tree().process_frame

	print("")
	print("Issuer listening on http://127.0.0.1:8787")
	print("  POST /ticket           {\"serverId\": \"...\"}  with Authorization: Bearer <access token>")
	print("  POST /session          {\"serverId\": \"...\", \"users\": [uid, ...]}  with Bearer <server key>")
	print("  POST /session/release  {}  with Authorization: Bearer <access token>")
	print("  GET  /health")
	print("")
	print("Put a reverse proxy in front of this before exposing it. It has no TLS.")

	if _seconds > 0.0:
		print("Exiting in %.0f seconds (--seconds)." % _seconds)
		await get_tree().create_timer(_seconds).timeout
		_shut_down("--seconds elapsed")


func _shut_down(reason: String) -> void:
	print("Issuer shutting down: %s" % reason)
	get_tree().quit(0)


## Local RSA keypair helper.
func DotCloudSignature_generate() -> Dictionary:
	var crypto := Crypto.new()
	var key := crypto.generate_rsa(3072)
	if key == null:
		return {}
	return {
		"private": key.save_to_string(false),
		"public": key.save_to_string(true),
	}
