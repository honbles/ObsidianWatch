# Agent identity, enrollment and tunnel integrity (spec WS-A, A1 to A4)

Status: **server side implemented and tested**. The agents do not enroll yet (spec step 3); until they do,
both servers run in `mixed` mode and existing agents keep working with the fleet key.

## How it works

1. An admin creates an enrollment token in **Platform settings → Agent enrollment**: label, lifetime
   (1 h to 90 days) and maximum number of hosts. The token is shown once and stored only as a SHA-256 hash.
   Tokens can be revoked.
2. On first boot the agent generates its key pair locally and calls `POST /api/v1/enroll` on the ingest
   backend with `{token, csr, hostname, os, agent_version}`. No fleet key is involved.
3. The backend spends one use of the token (atomically), and its agent CA issues a client certificate for a
   **new random agent_id** (`ag-` + 32 hex). The id is in the subject CN and in a URI SAN
   `urn:obsidianwatch:agent:<id>`; names asked for in the CSR are ignored. Every enrollment creates a new
   identity, so clones of one image that enroll at first boot get one identity each.
4. Certificates last 30 days by default (`cert_ttl`). The response carries `renew_after` (half life); the
   agent calls `POST /api/v1/enroll/renew` with its current certificate and a new CSR to get a new
   certificate for the same id.

The agent CA is created by the ingest backend on first start (`agent-ca/agent-ca.{crt,key}`, key 0600,
`agent-ca` volume in docker-compose: **back it up**). Its public certificate is published to the
`agent_ca` table, which is how the management server verifies tunnel certificates without the CA key.

## Enforcement (A2)

| Mode (`backend: auth.agent_identity.mode`, `management: server.agent_tunnel_auth`) | No certificate | With certificate |
|---|---|---|
| `legacy` | fleet key, as before | not used |
| `mixed` (default) | fleet key accepted for non-enrolled ids | verified, bound to its id |
| `enforced` | refused (enrollment endpoint only) | verified, bound to its id |

In every mode except `legacy`:

- A batch, location update, app batch or agent-config request whose `agent_id` differs from the certificate's
  id is refused with 403, including any single event inside a batch that names another agent.
- An enrolled id (`ag-…`) is refused when it arrives with the fleet key, so the shared key cannot speak for an
  enrolled agent.
- A certificate never opens the fleet-wide query routes (`GET /api/v1/events`, `/agents`, `/metrics`).
- Enrollment with the fleet key instead of a token is off unless `allow_fleet_key_enrollment: true`
  (a migration aid for existing installs).

Tunnel certificates are presented on a separate management listener, `server.agent_listen_addr` (`:8445`
in docker-compose). It asks for, but does not require, a client certificate, and the handshake proves the
agent holds the key. The main listener and the nginx UI never ask, so browsers are not prompted.

## Tunnel integrity (A3)

- One tunnel per agent. A second connection is refused (409) while a tunnel is live, logged, and raised as
  a High alert "Live Response tunnel takeover refused". The only exception is the same certificate
  reconnecting (an agent restart), which replaces its own stale entry.
- Response-action and hunt results are accepted only from the tunnel of the agent that was asked; a result
  frame for another agent's token is dropped and logged.

Note for fleet-key (legacy) agents: a reconnect within the 75 s heartbeat window of a dead connection is now
refused once and succeeds on the agent's next retry.

## Lifecycle (A4)

- Revoke an identity in **Agent enrollment → Enrolled agents** (reason required, audited). The tunnel closes at
  once; both servers reload the revoked set every 15 s, so ingest refuses the certificate within about 20 s.
- A reimaged host enrolls again with a fresh token and gets a new id; revoke the old one.

## Tests (Phase 0 gate)

- `backend/internal/api/identity_gate_test.go` runs a real TLS listener: random ids per clone, token rules
  (expired, revoked, used up, never issued, weak CSR does not spend a use), forged agent_id in batch and in an
  event, foreign CA, enforced mode without certificate, mixed mode, revocation, renewal.
- `management/backend/internal/api/agent_tunnel_identity_test.go`: tunnel identity by certificate, claim
  mismatch, foreign CA, revoked id, fleet key with an enrolled id, one tunnel per agent, results only from the
  asked agent, revocation closing a live tunnel.

Not tested here: Postgres-backed store functions (no database in this environment) and real agents (they
do not enroll yet).

## Still to do

- Agents: enroll at first boot, keep the key at 0600 / DPAPI / Keychain, renew at half life, connect the
  tunnel to `:8445` with the certificate (spec step 3).
- Agent builder: embed backend URL, CA and an enrollment token instead of the fleet key.
- Admin approval as an alternative to a fresh token for reimaged hosts.
- Switch both servers to `enforced` once the fleet has enrolled.
