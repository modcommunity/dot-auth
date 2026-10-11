extends RefCounted

## dot-auth's API level. The rule for bumping it is on [DotAddonApi].
##
## LEVEL rises by one for anything a game could call that did not exist before. OLDEST is
## raised to LEVEL when something a game could have called is removed or changes meaning,
## because every pack built before that no longer compiles against this addon.

# 1: everything before this file existed (an absent file reads as 1).
# 2: DotAuthSessionReporter.report_offline_now(), follow_server() and offline_timeout_sec;
#    DotAuthServer.session_reporter and create_session_reporter (the auth server builds the
#    reporter itself when session_report_url is set).
const LEVEL := 2
const OLDEST := 1
