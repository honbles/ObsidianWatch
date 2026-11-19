#!/usr/bin/env python3
"""Summarise what the agent's receiver decoded from a real SDK application (see verify.sh)."""
import json
import sys

d = json.load(open(sys.argv[1]))
b = d.get("batch") or {}
st = d["stats"]
print("\nreceiver counters:", st)
inst = b.get("instances") or []
print("\ninstances (identity should be 'verified' with a pid and exe):")
for i in inst:
    print("  %-16s env=%-6s identity=%-9s pid=%s exe=%s lang=%s sdk=%s" % (i.get("service"), i.get("environment"), i.get("identity"), i.get("pid"), i.get("exe"), i.get("language"), i.get("sdk")))
print("\nroutes (RED per route):")
for r in sorted(b.get("routes") or [], key=lambda x: x.get("route", "")):
    print("  %-6s %-22s calls=%s errors=%s 5xx=%s 401/403=%s" % (r.get("method"), r.get("route"), r.get("calls"), r.get("errors"), r.get("status_5xx"), r.get("status_401_403")))
cl = b.get("clients") or []
print("\nper-client failure counters (feed A01/A09/A13):")
for c in cl:
    print("  %-6s %-14s client=%-10s peer=%-10s exc=%-16s failures=%s 401/403=%s 5xx=%s 429=%s" % (c.get("method"), c.get("route"), c.get("client_ip"), c.get("peer_ip"), c.get("exc_type"), c.get("failures"), c.get("status_401_403"), c.get("status_5xx"), c.get("status_429")))
ev = d.get("events") or []
by = {}
for e in ev:
    n = ((json.loads(e["raw"]) if isinstance(e.get("raw"), str) else e.get("raw")) or {}).get("app", {}).get("event.name", e.get("event_type"))
    by[n] = by.get(n, 0) + 1
print("\nsecurity events emitted into the agent channel:", by)
print("sampled traces kept:", len(b.get("traces") or []))
