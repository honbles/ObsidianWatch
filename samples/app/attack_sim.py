#!/usr/bin/env python3
"""Attack simulation for the ObsidianWatch sample apps (Python, Node, Java, .NET all expose the same routes).

Everything goes to a sample app on YOUR OWN machine (default http://127.0.0.1:5001). The script refuses
non-loopback targets. It exercises the Application rules:

  normal      ordinary traffic so the service has a baseline
  bruteforce  25 failed logins from one client                 -> APP-A01 (login failure burst)
  injection   6 SQL-injection-looking searches                  -> APP-A09 (injection attempts)
  burst       200 quick requests                                -> APP-A13 (rate-limit abuse) when the app limits
  exec        makes the app run a shell command                 -> APP-H01 (shell under a service); with the
                                                                   injection phase this is the APP-X02 chain
Usage:  python3 attack_sim.py [--base http://127.0.0.1:5001] [phase ...]     (default: all phases in order)
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PHASES = ["normal", "bruteforce", "injection", "burst", "exec"]


def call(base, method, path, body=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # connection refused, timeout
        return "ERR %s" % e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:5001")
    ap.add_argument("phases", nargs="*", default=PHASES)
    a = ap.parse_args()
    host = urllib.parse.urlparse(a.base).hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("refusing to attack %r: this script only targets a sample app on this machine" % a.base)
    for ph in a.phases:
        if ph not in PHASES:
            sys.exit("unknown phase %r (choose from %s)" % (ph, ", ".join(PHASES)))
    b = a.base
    for ph in a.phases:
        codes = []
        if ph == "normal":
            for i in range(30):
                codes.append(call(b, "GET", "/orders/%d" % (i + 1)))
                codes.append(call(b, "GET", "/search?q=widget"))
            codes.append(call(b, "POST", "/login", {"user": "alice", "password": "correct-horse"}))
        elif ph == "bruteforce":
            for i in range(25):
                codes.append(call(b, "POST", "/login", {"user": "alice", "password": "guess%d" % i}))
        elif ph == "injection":
            for q in ["' OR '1'='1", "1; DROP TABLE users--", "admin'--", "' UNION SELECT null--", "x' OR 1=1 --", "' OR ''='"]:
                codes.append(call(b, "GET", "/search?q=" + urllib.parse.quote(q)))
        elif ph == "burst":
            for i in range(200):
                codes.append(call(b, "GET", "/orders/1"))
        elif ph == "exec":
            codes.append(call(b, "GET", "/debug/exec?cmd=" + urllib.parse.quote("id; uname -a")))
        summary = {}
        for c in codes:
            summary[c] = summary.get(c, 0) + 1
        print("%-10s %s" % (ph, summary))
        time.sleep(1)


if __name__ == "__main__":
    main()
