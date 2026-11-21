# ow-juice-kit: Juice Shop with ObsidianWatch request-body capture

Run on the machine that hosts Juice Shop and the ObsidianWatch agent (agent built with the app-server profile,
receiver on 127.0.0.1:4318). The management server can be elsewhere.

Files (keep together):
- ow-juice.sh           setup | start | attack | status | logs | stop | clean | check
- ow-payload.js         ObsidianWatch Node helper (unchanged from samples/app/node)
- ow-security.js       ObsidianWatch security helper (sample, adapted to the newer OTel logs SDK)
- ow-juice-preload.js   starts OpenTelemetry, hooks Juice Shop's body parsers, and reports security events
- ow-juice-requests.py  traffic script, new "bodies" phase

Security tab (Tier 2): the preload reports auth.login (POST /rest/user/login: 2xx success, else failure),
authz.deny (401/403 on other routes) and input.rejected (500 on a SQL-injection-looking query, heuristic).
start prints "ok security events enabled". OW_SECURITY_EVENTS=0 turns them off, OW_SECURITY_CONSOLE=1 echoes them
in the Juice Shop log (./ow-juice.sh logs).

Steps: ./ow-juice.sh setup   (copies the two .js files into ~/ow-testapps/otel-node)
       ./ow-juice.sh start   (must print: "ok request-body capture hooked ...")
       ./ow-juice.sh attack  then python3 ow-juice-requests.py bodies
Re-run setup once (it installs the OTel logs packages), then stop and start.
Then in the console (Security tab fills within a minute or two): Routes -> POST /rest/user/login shows email, password, remember (needs review).
Open Review, mask, save, wait up to 5 minutes (agent config pull), send traffic again, open Review for samples.
password / token / card style names are always masked. OW_BODY_CAPTURE=0 starts without body capture.
