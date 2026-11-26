# Response actions

All actions run from **Response** (`/response`): pick hosts, pick an action, give a reason, review, run.
Every action is stored with who asked, why and the outcome, and written to the audit log. Admin role only.
Isolation and release queue for offline hosts; every other action needs the host's live tunnel.

| Group | Action | What it does | Hosts |
|---|---|---|---|
| Network | Isolate | Blocks all traffic except the ObsidianWatch servers. Optional duration. Tells the user with a desktop pop-up (and the block page for plain-HTTP sites) unless isolated silently. | many, queues |
| | Release isolation | Restores networking, removes the block page and puts DNS settings back. | many, queues |
| | Block IP address / Unblock | Drops all traffic to and from one address without isolating. Survives restarts. Server addresses, loopback, multicast and link-local are refused. | many |
| | Blocked IPs | Lists blocked addresses. | many |
| Processes | Kill process | One process (optionally with children), PID-reuse guard. | one |
| | Block / Unblock program, Blocked programs | As before. | many |
| Files | Quarantine file | Moves the file into the host's vault with its SHA-256. | many |
| | Delete file | Permanent delete. Optional expected SHA-256: deleted only if the content still matches. OS paths, the agent and its data are refused. | many |
| | Restore from vault | Puts a quarantined file back. | one |
| | Delete from vault | Permanently destroys a quarantined file. | one |
| | File details | Size, mode, modified time, SHA-256. Read-only. | many |
| | Collect file | Copy of a file up to 2 MB. Stored with the action; never included in lists; download is admin-only and audited (`GET /api/v1/response/actions/{id}/file`). | one |
| | Quarantine vault | Lists the vault. | many |
| Accounts | Disable account | Locks a local account and ends its processes. Linux also expires it (stops SSH key logins). Root/uid 0, system accounts and the last enabled Windows local administrator are refused. Domain accounts must be disabled in the directory. | many |
| | Enable account | Unlocks it. | many |

## Block page during isolation

While a host is isolated the agent runs a DNS sink and a small web server on loopback. Every name resolves
to 127.0.0.1 except the ObsidianWatch server names (resolved before isolation and cached), and every web
request gets a page with the ObsidianWatch logo: "This device has been isolated from the network. Please
contact your administrator or IT help desk." The operating systems' captive-portal checks land on it too,
so Windows and macOS show their "sign in to network" prompt with the page.

- Linux: NAT redirects IPv4 DNS (to 127.0.0.1:15353) and HTTP (to 127.0.0.1:18080), loaded together with
  the isolation rules (nftables, or iptables as fallback). IPv6 DNS stays blocked. **Tested on a real kernel
  in a network namespace for both nftables and iptables.**
- Windows: adapters that are up point their DNS at 127.0.0.1 (previous static servers are recorded; DHCP
  adapters are reset to DHCP on release). The page listens on 127.0.0.1:80 and the sink on 127.0.0.1:53.
- macOS: every enabled network service's DNS points at 127.0.0.1 (restored on release); page on
  127.0.0.1:80, sink on 127.0.0.1:53. pf already skips loopback.

Limits: HTTPS sites cannot show the page without a certificate warning, so they fail straight away
instead of hanging (browsers that fall back to http:// show the page). If port 80 or 53 is already in use
on Windows or macOS (IIS, a DNS server on a domain controller), the page or the DNS change is skipped and
the action result says so; isolation itself is unaffected. Turn the page off per action with "Show the
contact your administrator page" unchecked (`no_block_page`).

