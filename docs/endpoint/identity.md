# Agent identity, enrollment and tunnel integrity (spec WS-A, A1 to A4)

Status: **implemented end to end** (servers, Linux/Windows/macOS agents, network probe, Agent builder).
There is **no shared API key** anywhere: an agent without a valid certificate is refused on every route
except enrollment. Existing agents built with an API key must be rebuilt and reinstalled.

Verified end to end on Linux with the real binaries (backend, management, agent, PostgreSQL): enrollment with
a token, ingest with the certificate, install-key registration through the backend, live-response tunnel,
a response action through the tunnel, collect-file download, the old API key refused, forged identity headers
refused, and revocation closing the tunnel at once and refusing ingest within 20 s.

## How it works

1. **Agent builder.** Each build mints a fresh enrollment token (lifetime 1 h to 90 days, default 30 days;
   host limit, default 500) and embeds it with the backend URL and the CA. Tokens are stored only as a
   SHA-256 hash and listed, with the hosts that used them, in **Platform settings → Agent enrollment**,
   where they can be revoked. Tokens can also be created there by hand (network probe, dev builds).
2. **Enrollment.** On install (or first start if the server was unreachable) the agent creates its key pair
   locally and calls `POST /api/v1/enroll` on the backend with the token and a CSR. The backend spends one
   use of the token and its agent CA issues a 30-day client certificate for a new random agent id
   (`ag-` + 32 hex, in the CN and a URI SAN `urn:obsidianwatch:agent:<id>`). Names in the CSR are ignored.
   Clones of one image enroll separately and get one id each.
3. **Storage.** Certificate and key are kept in one bundle: `/var/lib/obsidianwatch/identity/agent-identity.json`
   (root, 0600, directory 0700) on Linux and macOS, and `C:\ProgramData\ObsidianWatch\identity\agent-identity.dpapi`
   on Windows, encrypted with the machine DPAPI key (useless on another computer) and limited to SYSTEM and
   Administrators. The macOS Keychain is not used: without cgo the only way in is the `security` tool, which
   takes the secret on its command line where other users can read it.
4. **Renewal.** At half life (plus up to an hour of jitter) the agent calls `POST /api/v1/enroll/renew` with
   its current certificate and a new CSR and gets a new certificate for the same id. A certificate that
   expired while the host was off is replaced by enrolling again with the built-in token, if it is still valid.
5. **Everything else** uses the certificate and goes to the backend URL only: events, location, application
   telemetry, the live-response tunnel, install-key registration and the uninstall check. The backend verifies
   the certificate and passes tunnel and install-key calls to the management API with the agent id in headers
   signed with a key derived from `OW_SECRET_KEY` (valid 60 s). Management accepts nothing else from agents.

The agent CA is created by the backend on first start (`agent-ca` volume, key 0600: **back it up**). Its
public certificate is published to the `agent_ca` table.

## Enforcement (A2)

- Every agent route requires a valid, unrevoked certificate from the agent CA; deployment-CA client
  certificates and the old `X-API-Key` are refused.
- A batch, location update, app batch or agent-config request whose `agent_id` differs from the
  certificate's id is refused (403), including any single event inside a batch that names another agent.
- Install-key registration and the uninstall check only act on the calling agent's own key.
- A certificate never opens the fleet-wide query routes (`GET /api/v1/events`, `/agents`, `/metrics`).
- No extra port: the tunnel rides the backend port. Browser-facing ports never ask for client certificates.

## Tunnel integrity (A3)

- One tunnel per agent. A second connection is refused (409) while a tunnel is live, logged, and raised as
  a High alert "Live Response tunnel takeover refused". The only exception is the same certificate
  reconnecting (an agent restart), which replaces its own stale entry.
- Response-action and hunt results are accepted only from the tunnel of the agent that was asked.

## Lifecycle (A4)

- Revoke an identity in **Agent enrollment → Enrolled agents** (reason required, audited). The tunnel closes at
  once; both servers reload the revoked set every 15 s, so ingest refuses the certificate within about 20 s.
  A revoked agent does not enroll again on its own; it keeps queueing locally until reinstalled.
- Revoke the token of a build as well if the file may be reused, because a host whose revoked certificate also
  expired could otherwise enroll again with a still-valid token.
- A reimaged host enrolls again with a fresh build and gets a new id; revoke the old one.

## Tests

- `backend/internal/api/identity_gate_test.go`, `agent_tunnel_proxy_test.go`: real TLS listener; random ids per
  clone, token rules, forged agent_id in batch and event, foreign CA, deployment-CA certificate, the fleet key
  refused everywhere, revocation, renewal, tunnel and install-key pass-through with signed identity.
- `management/backend/internal/api/agent_tunnel_identity_test.go`, `handlers_agent_keys_test.go`: forwarded
  identity (valid, wrong key, forged, replayed after 60 s, revoked, claim mismatch, no `OW_SECRET_KEY`),
  one tunnel per agent, results only from the asked agent, revocation closing a live tunnel, install-key
  routes refusing the fleet key and other agents.
- `agents/*/internal/identity`: enroll, persist (0600), reload without enrolling again, renew, revoked agents
  not re-enrolling, bad or missing token, expired certificate re-enrolling, the TLS hook.

Not run here: the Windows and macOS agents (cross-compiled; DPAPI and the file store are unit-tested on Linux only
for the file path), and the network probe end to end (its SNMP and SQLite dependencies are not vendored here;
the identity and forwarder packages were built and tested).

## Rollout

1. Deploy the new servers (`docker compose up -d --build`). `AGENT_API_KEY` is no longer required.
2. Rebuild every agent in the Agent builder and reinstall. Old agents are refused and show as offline.
3. Back up the `agent-ca` volume.
