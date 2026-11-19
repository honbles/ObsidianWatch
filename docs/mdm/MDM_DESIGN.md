# ObsidianWatch Device Management (MDM-lite): design proposal

Status: proposal for review. Nothing here is built yet. Nothing in this document has been run on a real host.

## 1. Two things first

### 1.1 Threat hunting and offline hosts

You are right. Today a live fleet hunt asks only the agents that are online and records every offline host as `offline: agent was offline; not asked` (`management/backend/internal/api/hunt.go`). The host never gets the question. Response actions already behave better: isolate, block and the rest are stored as `queued` when the host is offline and applied on reconnect (`response_actions.go`).

Proposal: give hunts the same queue.

| Setting | Behaviour |
|---|---|
| Offline hosts | `skip` (today), or `wait` |
| Wait window | 1 h, 24 h, 7 d, or until done |
| On reconnect | The agent receives the hunt, runs it, and the result is stored with `late: true` and the real run time |
| Result view | Per-host state: answered, queued, expired, skipped. One CSV for all of them |
| Safety | A queued hunt is read-only and has a hard expiry. Query actions only, never response actions |

Why it matters: the hosts you most want to hunt on (a laptop that went quiet after an alert) are the ones most likely to be offline.

### 1.2 What "MDM" means here

This is not a replacement for Intune, Jamf or Workspace ONE. We have no Apple MDM enrollment (APNs, Apple Business Manager) and no Windows MDM enrollment. We have an agent that runs as SYSTEM/root. That is enough for a useful set of **policy enforcement and device control** features on Windows and Linux, and a smaller set on macOS. This document says which is which, so we do not promise what the platform will not allow.

The line to hold: **MDM controls what a device is allowed to do. It does not decide whether something is malware.** It works with no internet and no signatures, which also answers the earlier "prevention without lookups" problem for the cases below.

## 2. Model: policies and commands

Two different things, handled differently.

| | Policy | Command |
|---|---|---|
| Example | Bluetooth off, USB storage read-only, server lockdown | Wipe, lock now, reboot, rotate local admin password |
| Lifetime | Continuous, until removed or expired | One shot |
| Offline | Stored on the agent, enforced with no server contact | Queued on the server, delivered on reconnect, with an expiry |
| State | Desired state, reconciled every 60 s | Pending, delivered, done, failed, expired |
| Reuse | New `mdm_policies` table plus agent `mdm` module | The existing action broker and offline queue |

A policy is declarative:

```
id, name, version
scope:      hosts | tags | os
settings:   { bluetooth: "off", usb_storage: "read_only", ... }
mode:       audit | enforce        (audit reports what it would change, changes nothing)
expires_at: optional
signature:  server key, verified by the agent before applying
```

The agent:

1. Verifies the signature, stores the policy on disk, and enforces it with no server contact.
2. Reconciles every 60 s, so a user who switches Bluetooth back on loses within a minute.
3. Reports per setting: `compliant`, `drifted`, `applied`, `failed`, `unsupported`. This feeds the Health board and the Compliance tab we already have.
4. Never touches its own server channel, its own files, or the protected paths (the same guards the block feature uses).

## 3. Capability catalogue

Feasibility: **High** = the OS gives us a supported mechanism from a SYSTEM/root agent. **Medium** = works with caveats. **Low** = needs Apple MDM, an entitlement or an enrolled device.

### 3.1 Server lockdown ("freeze")

What you described: only the processes and connections present now may continue, and nothing new may start or connect. For servers whose job rarely changes (jump hosts, DB servers, domain controllers, appliances).

Flow, in three steps so it cannot brick a host:

1. **Learn.** Snapshot running processes (path, SHA-256, signer) and established connections plus listening ports. Optionally keep learning for N days so cron jobs and patch runs are captured.
2. **Audit.** Enforcement logic runs in report-only mode. Everything it would have blocked is listed. The admin reviews and adds or removes entries.
3. **Enforce**, with a mandatory expiry (default 24 h), so a forgotten lockdown always ends.

| | Windows | Linux | macOS |
|---|---|---|---|
| New process control | WDAC or AppLocker policy generated from the snapshot (publisher or hash rules). Audit mode first, then enforce. | `fanotify` exec permission events (`FAN_OPEN_EXEC_PERM`) in the agent: allow if hash is in the set, else deny. Alternative: `fapolicyd` if installed. | Endpoint Security needs an Apple entitlement. Without it: kill-on-start loop only, which is detective, not preventive. |
| New connections | Windows Filtering Platform: block new outbound and inbound, allow established flows | `nftables`: `ct state established,related accept`, new connections dropped, allowlist for DNS, NTP and our manager | `pf` with state tracking |
| Feasibility | High (WDAC needs the right edition and a reboot for some rules) | High (Medium on kernels without fanotify perm support) | Low |

Rules that must hold:

- The agent, its manager channel, DNS, NTP and the OS update path are always allowed.
- Existing connections survive because stateful firewalls only evaluate new flows.
- A child of an allowed process is allowed only if its binary is in the set. This is what stops `bash` spawned from a web shell.
- Break-glass: a local one-time token (generated at enrolment, held offline by the admin) lifts lockdown from the console with no network.
- Dead-man switch: if enforce was applied and the agent cannot reach the manager for N hours, it releases itself. Configurable. For high-assurance hosts the admin can instead pick "stay locked".
- Every blocked attempt becomes an event, so lockdown doubles as a detection source: anything the host tries to do that it never did before is, by definition, interesting.

### 3.2 Peripherals and radios

| Control | Windows | Linux | macOS |
|---|---|---|---|
| Bluetooth off | Disable the radio device via PnP and stop `bthserv`. Policy re-applies if the user re-enables. High | `rfkill block bluetooth` and optionally blacklist `btusb`. High | `blueutil` is third party. Native control needs MDM. Low |
| USB storage: block or read-only | `USBSTOR` start type and the `WriteProtect` policy. High | `usbguard` rules or `modprobe` blacklist of `usb-storage`. High | Low |
| USB allowlist by vendor and product id | Device installation restriction policy. High | `usbguard`. High | Low |
| Wi-Fi off, or SSID allowlist | `netsh wlan` filters. Medium | `nmcli`/`rfkill`. High | Low |
| Camera and microphone off | PnP disable of the device class. Medium (privacy review needed) | Module blacklist. Medium | Low |
| Thunderbolt/DMA | Kernel DMA protection check. Medium | `boltctl`. Medium | Low |
| Optical drives, printers | Device class disable. Medium | Rules. Medium | Low |
| Screen capture and clipboard | Not reliably controllable. Do not offer | No | No |

The agent already reports which USB devices appear. A policy plus those events gives "block unknown, alert on attempt, allow the finance team's approved keys".

### 3.3 Remote wipe and lost mode (commands)

Wipe is the most dangerous feature we could build, so it gets the strictest handling.

| Tier | What it does | Feasibility |
|---|---|---|
| **Lock now** | Lock the session, optionally disable local logon for non-admins | High |
| **Lost mode** | Isolate the network except our manager, lock, show a message and contact number, report location and IP every minute | High (uses isolate, which exists) |
| **Selective wipe** | Delete org data: quarantine store, agent config, cached credentials, designated folders. Leaves the OS and personal files | High |
| **Crypto-erase** | Destroy the disk encryption key or key slot (BitLocker protector removal, LUKS header erase). Data becomes unreadable instantly | Medium. Requires encryption to already be on. Irreversible |
| **Full device reset** | Windows: the RemoteWipe MDM bridge class from a SYSTEM context. macOS: `eraseinstall` on Apple Silicon needs a bootstrap token. Linux: no standard reset | Windows Medium, macOS Low, Linux not offered. **Needs a real-device test before we trust it** |

Safeguards (all required):

- Admin only. Two-person approval for crypto-erase and full reset: a second admin must confirm.
- Typed confirmation of the hostname. A short cooling-off delay (default 10 minutes) with a visible Cancel.
- Offline devices: the command queues with an expiry. When the device returns it applies, unless the admin cancelled.
- **Dead-man wipe for lost devices**: "if this host has not checked in for N days, perform selective wipe." Off by default, opt-in per policy.
- Full audit trail, including who approved it. Wipe cannot be hidden from the audit log.
- Never available on hosts tagged `server` unless explicitly overridden.

### 3.4 Network behaviour

- Always-on VPN requirement: when off-network, block non-VPN traffic (leak protection).
- DNS pinning to our resolver; block DNS-over-HTTPS to unknown resolvers.
- Block mobile hotspot and tethering adapters.
- Block listed remote-access tools (AnyDesk, TeamViewer, and so on) by process and by network. The Application Monitoring and block-process work already covers the process half.
- Block inbound on workstations except from management ranges.

### 3.5 Software control

- Allow or deny lists by name, path, hash or publisher (extends `block_process`, which is currently per-host and manual).
- Forced uninstall of listed software, with a report.
- Browser extension allowlist (Chrome and Edge policy keys, Firefox policies). High.
- Block package managers or script engines on locked hosts, for example PowerShell constrained language mode. Medium.

### 3.6 Baseline and drift

Define a baseline once (firewall on, Defender on, SMBv1 off, screen lock at 10 minutes, no guest account, auditing on). The agent checks every 60 s. `audit` mode reports drift, `enforce` repairs it. This is the natural home for the Compliance tab we already have, and it gives every other policy a consistent reporting path.

### 3.7 Identity and access on the device

- **Local admin control**: remove unexpected local administrators, report them, and rotate a managed local admin password (LAPS-style, stored encrypted on the server, revealed with an audit entry).
- **Just-in-time elevation**: grant local admin for 1 hour, then revoke automatically.
- **Logon hours**: deny interactive logon outside business hours for named groups.
- **Idle logoff** and session limits for servers.

### 3.8 Disk encryption and patching

- Report BitLocker/LUKS/FileVault status. Enforce on Windows (BitLocker with escrow of the recovery key to the server, encrypted). Linux: report only, enabling LUKS on a live system is not safe to automate.
- Patch window control: force updates in a window, schedule a reboot, optionally restrict a host to management traffic until a critical patch is applied.

### 3.9 Location-aware rules

We already collect location. Rule: "if a laptop tagged `finance` reports a country outside the allowed list, isolate and raise an alert." Medium, because IP-based location is wrong often enough that the default action should be alert plus admin approval, not automatic isolation.

## 4. Fit with what exists

| Need | Existing piece to reuse |
|---|---|
| Deliver commands, offline queue | Action broker and the `queued` status in `response_actions.go` |
| Isolate, block, quarantine | `isolate`, `block_process`, `quarantine_file` in all three agents |
| Report state | Health board components (`/health` `components` list) |
| Compliance view | Compliance tab (`tabs_compliance.jsx`) |
| Admin-only, audit | `adminOnly`, `WriteAudit` |
| Run privileged work | `response` package prerequisites pattern (`systemd-run` when sandboxed) |

New pieces: `mdm_policies` and `mdm_policy_status` tables, `/api/v1/mdm/*`, a policy signer, an agent `mdm` package per OS (reconciler plus per-setting drivers), and a Policies UI (list, edit, scope, audit/enforce toggle, per-host status).

## 5. Safety rules (non-negotiable)

1. Every policy starts in **audit** mode. Moving to **enforce** is a separate, deliberate step.
2. Risky policies (lockdown, wipe, network restrictions) have an **expiry** and a **local break-glass**.
3. The agent never blocks its own channel, DNS to the manager, or itself.
4. Policies are **signed**. An agent ignores an unsigned or stale-version policy.
5. A **canary** step: apply to one host or a tagged group first, and promote only after status is clean.
6. Everything is **audited**: who, what, scope, mode, result.
7. Roll back by removing the policy: each driver must restore the previous value it recorded.

## 6. What we should be honest about

- On macOS most of this is Low without Apple MDM enrollment or Endpoint Security entitlements. We should ship Windows and Linux first and say so.
- Lockdown on Windows depends on WDAC edition support. On Linux it depends on `fanotify` permission events. Both need testing on real hosts, including how they interact with package updates.
- Full device reset and crypto-erase have never been tried on a real host. They need a lab machine before any customer sees the button.
- Nothing here stops a determined attacker who already has SYSTEM. It stops mistakes, insiders with ordinary rights, opportunistic malware, and "plug in a USB stick" risks. It narrows the surface; it is not an EPP.

## 7. Suggested phasing

| Phase | Scope | Why this order |
|---|---|---|
| 0 | Hunt offline queue (section 1.1) | Small, uses the existing queue, fixes a real gap |
| 1 | Policy engine, signing, audit/enforce, status reporting. Drivers: Bluetooth, USB storage, Wi-Fi, baseline checks | Proves the framework with low-risk settings |
| 2 | Software allow/deny, network rules, local admin control, JIT elevation | Builds on phase 1 and on existing block and isolate code |
| 3 | Server lockdown: learn, audit, enforce, break-glass | Highest value, needs the framework and real-host testing |
| 4 | Lost mode, selective wipe, then crypto-erase and full reset with two-person approval | Most dangerous, last, and only after a lab test |

## 8. Decisions needed from you

1. Start with the hunt offline queue (phase 0) and phase 1, or go straight at server lockdown?
2. Should lockdown's dead-man default be **release** (safer for availability) or **stay locked** (safer for security)? I recommend release, configurable per host.
3. Do you want full device reset at all, or stop at selective wipe and crypto-erase?
4. Is macOS in scope for this, given most controls are Low without Apple MDM?
5. Policy scope: by host and tag only, or also by AD/Entra group?
