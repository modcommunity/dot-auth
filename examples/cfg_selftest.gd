extends Node

## The yml layout of dot-auth's settings: the new path, the flat shim and the operator's layer.
##
## [codeblock]
## timeout 120 godot --headless --path . res://examples/cfg_selftest.tscn
## [/codeblock]

const FOLDER := "dot_auth"
const FILE := "auth.yml"
const LEGACY := "user://dot_auth_cfg_selftest_legacy"

var _passed := 0
var _failed := 0


func _ready() -> void:
	DotLog.set_level(DotLog.Level.ERROR)
	_run.call_deferred()


func _run() -> void:
	print("dot-auth cfg self-test")
	var addon_dir := "user://cfg/addons/" + FOLDER
	var server_dir := "user://cfg/server/" + FOLDER
	_clean(addon_dir, server_dir)
	DotCfgLegacy.reset()

	_write(LEGACY.path_join(FILE), "strategy: 1\nrefresh_margin_sec: 100.0\nclient_name: old\n")
	var config := DotAuthConfig.new()
	var res := config.load_cfg(FILE, LEGACY)
	_check(res.ok and config.refresh_margin_sec == 100.0, "only the flat file: it is still read")
	_check(DotCfgLegacy.warned_count() == 1, "and warned once")
	DotAuthConfig.new().load_cfg(FILE, LEGACY)
	_check(DotCfgLegacy.warned_count() == 1, "a second load does not warn again")

	_write(addon_dir.path_join(FILE), "strategy: 1\nrefresh_margin_sec: 200.0\n")
	config = DotAuthConfig.new()
	res = config.load_cfg(FILE, LEGACY)
	_check(res.ok and config.refresh_margin_sec == 200.0, "the new path wins over the flat file")
	_check(config.client_name == DotAuthConfig.new().client_name, "and the two are never merged")

	_write(server_dir.path_join(FILE), "strategy: 1\nrefresh_margin_sec: 300.0\nissuer_private_key: from-file\n")
	config = DotAuthConfig.new()
	res = config.load_cfg(FILE, LEGACY)
	_check(res.ok and config.refresh_margin_sec == 300.0, "the operator's server layer wins")
	_check(config.issuer_private_key == "from-file", "a secret in a file is read")
	OS.set_environment("DOT_AUTH_INTEGRATION_TOKEN", "from-env")
	config = DotAuthConfig.new()
	config.load_cfg(FILE, LEGACY)
	_check(config.integration_token == "", "and the environment cannot set one")
	OS.unset_environment("DOT_AUTH_INTEGRATION_TOKEN")

	_clean(addon_dir, server_dir)
	DotCfgLegacy.reset()
	print("%d passed, %d failed" % [_passed, _failed])
	get_tree().quit(1 if _failed > 0 else 0)


func _clean(addon_dir: String, server_dir: String) -> void:
	DotPaths.remove_tree(addon_dir)
	DotPaths.remove_tree(server_dir)
	DotPaths.remove_tree(LEGACY)


func _write(path: String, text: String) -> void:
	DirAccess.make_dir_recursive_absolute(path.get_base_dir())
	var f := FileAccess.open(path, FileAccess.WRITE)
	f.store_string(text)
	f.close()


func _check(condition: bool, what: String) -> void:
	if condition:
		_passed += 1
		print("   ok   ", what)
	else:
		_failed += 1
		print("  FAIL  ", what)
