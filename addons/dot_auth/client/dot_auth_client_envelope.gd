@tool
## Base of [DotAuthClient]: reading the backbone's response envelopes.
## Path-based, no class_name: it exists to keep each script under the size budget.
extends Node


## The app API's `{ok, data}` envelope, whatever `data` is.
##
## [method _unwrap] knows the sign-in shapes; a stats or a scope-key reply is
## a plain object it would refuse for lacking a token, which is not a failure.
func _unwrap_any(response: Variant) -> DotResult:
	if not (response is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE, "The backbone sent an unexpected response."
		)
	var d := response as Dictionary
	if d.has("data"):
		return DotResult.success(d["data"])
	return DotResult.success(d)


## The app API's own error, when it sent one: flat `{ok: false, code, message, retryAfter?}`
## as website-city sends it, or the nested `{error: {code, message}}` shape. Keeps the
## site's code and message instead of the fallback text.
func _app_refusal(res: DotResult, fallback: String) -> DotResult:
	if res.ok or res.error == null:
		return res

	var parsed: Variant = _envelope_of(res.error.detail)
	if parsed is Dictionary and (parsed as Dictionary).get("code") is String:
		var flat: Dictionary = parsed
		var err_flat := DotError.make(
			res.error.code, str(flat.get("message", fallback)), str(flat["code"])
		)
		err_flat.http_status = res.error.http_status
		err_flat.retry_after = float(flat["retryAfter"]) if flat.get("retryAfter") != null \
			else res.error.retry_after
		return DotResult.failure(err_flat)

	if parsed is Dictionary and (parsed as Dictionary).get("error") is Dictionary:
		var body: Dictionary = (parsed as Dictionary)["error"]
		var err := DotError.make(
			res.error.code, str(body.get("message", fallback)), str(body.get("code", ""))
		)
		err.http_status = res.error.http_status
		err.retry_after = res.error.retry_after
		return DotResult.failure(err)

	return res.wrap(fallback)


## Unwraps the backbone's `{ok: true, data: …}` success envelope.
func _unwrap(response: Variant) -> DotResult:
	if not (response is Dictionary):
		return DotResult.fail(
			DotError.CODE_PARSE, "The backbone sent an unexpected response."
		)

	var d := response as Dictionary

	if d.has("data"):
		var data: Variant = d["data"]
		if data is Dictionary:
			return DotResult.success(data)

	# Some endpoints answer with the payload directly. Accepting both keeps a
	# contract change from breaking sign-in outright.
	if d.has("accessToken") or d.has("deviceCode") or d.has("user"):
		return DotResult.success(d)

	return DotResult.fail(
		DotError.CODE_PARSE,
		"The backbone sent no data.",
		JSON.stringify(d).substr(0, 200)
	)


## The backbone's error `code` from a failed request, or [code]""[/code].
##
## Its handler puts the machine-readable code in the JSON body even for non-2xx
## responses, and [DotHttp] keeps that body as the error's detail — so the code is
## recoverable without a second request.
func _envelope_code(res: DotResult) -> String:
	if res.ok:
		return ""
	if res.error == null or res.error.detail == "":
		return ""

	var parsed: Variant = _envelope_of(res.error.detail)
	if not (parsed is Dictionary):
		return ""

	return str((parsed as Dictionary).get("code", ""))


## A refusal's body as a Dictionary, or null, without the engine's own ERROR line.
## A transport failure or a proxy's HTML page is text, and `JSON.parse_string` prints an
## unsuppressible ERROR for each before answering null.
static func _envelope_of(detail: String) -> Variant:
	if not detail.strip_edges().begins_with("{"):
		return null
	var json := JSON.new()
	if json.parse(detail) != OK:
		return null
	return json.data
