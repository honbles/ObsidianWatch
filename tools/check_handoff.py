#!/usr/bin/env python3
"""Ownership / merge-safety checker for the parallel Network and Application builds.

  python3 tools/check_handoff.py APP|NET <baseline_dir> <work_dir>

Exit 0 = mergeable. Exit 1 = violations (listed). Baseline is the foundation
snapshot (Batch Z2) extracted to a directory; work is the side's tree.
"""
import os, re, sys, difflib

SIDE = (sys.argv[1] if len(sys.argv) > 1 else "").upper()
if SIDE not in ("APP", "NET") or len(sys.argv) != 4:
    sys.exit(__doc__)
BASE, WORK = sys.argv[2], sys.argv[3]
OTHER = "NET" if SIDE == "APP" else "APP"
P = SIDE.lower()                       # file prefix: app / net
IDPREFIX = "App" if SIDE == "APP" else "Net"

MG = r"management/backend/internal"
BE = r"backend/internal"
FE = r"management/frontend/src"
OWNED = {
 "APP": [
  rf"^{MG}/(api|store)/app_[^/]*\.go$", rf"^{BE}/(api|store)/app_[^/]*\.go$",
  rf"^{MG}/store/migrations/0(6\d|7\d)_app_[^/]*\.sql$", rf"^{BE}/store/migrations/0(3\d|4\d)_app_[^/]*\.sql$",
  r"^agents/(linux|windows|macos)/internal/(otel|ebpf|app)/", r"^agents/(linux|windows|macos)/internal/config/config_app\.go$",
  rf"^{FE}/pages/app/", rf"^{FE}/components/app/", rf"^{FE}/api/app\.js$",
  r"^docs/app/", r"^samples/app/", r"^MANIFEST_APP\.md$",
 ],
 "NET": [
  rf"^{MG}/(api|store)/(net|probe|network)_[^/]*\.go$", rf"^{BE}/(api|store)/(net|probe|network)_[^/]*\.go$",
  rf"^{MG}/store/migrations/0(4[4-9]|5\d)_net_[^/]*\.sql$", rf"^{BE}/store/migrations/0(1\d|2\d)_net_[^/]*\.sql$",
  r"^agents/network/", rf"^{FE}/pages/network/", rf"^{FE}/pages/NetworkProbes\.jsx$",
  rf"^{FE}/components/network/", rf"^{FE}/api/network\.js$", r"^docs/network/", r"^MANIFEST_NET\.md$",
 ],
}
# Shared files editable only inside this side's marker blocks.
SHARED = [
 f"{MG}/api/server.go", f"{MG}/api/sig_registry.go", f"{MG}/api/agent_builder.go", f"{MG}/api/detection_engine.go",
 f"{MG}/api/entity_kinds.go", f"{BE}/api/server.go",
 f"{FE}/App.jsx", f"{FE}/components/Navbar.jsx", f"{FE}/pages/AgentBuilder.jsx", f"{FE}/components/shared/entityRoutes.js",
] + [f"agents/{o}/{p}" for o in ("linux","windows","macos") for p in ("cmd/agent/main.go","internal/config/config.go")]
# Dependency manifests: allowed, but reported so the merger re-resolves them.
DEPFILES = {"go.mod","go.sum","package.json","package-lock.json"}
SKIP_DIRS = {"node_modules","dist",".git","__pycache__"}
errors, notes = [], []

def walk(root):
    out = {}
    for d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x not in SKIP_DIRS]
        for f in fs:
            if f.endswith(".zip"): continue
            full = os.path.join(d, f)
            out[os.path.relpath(full, root).replace(os.sep, "/")] = full
    return out

def read(p):
    with open(p, "rb") as fh: return fh.read()

def strip_own(text, tag):
    """Remove lines from [TAG-*-BEGIN] to [TAG-*-END] (inclusive of markers' interior, keep markers)."""
    out, inside = [], False
    for ln in text.splitlines():
        if re.search(rf"\[{tag}-[A-Z-]*BEGIN\]", ln):
            inside = True; out.append(ln); continue
        if inside and re.search(rf"\[{tag}-[A-Z-]*END\]", ln):
            inside = False; out.append(ln); continue
        if not inside: out.append(ln)
    if inside: out.append("<<UNCLOSED>>")
    return out

def owned(rel): return any(re.search(p, rel) for p in OWNED[SIDE])
def owned_by_other(rel): return any(re.search(p, rel) for p in OWNED[OTHER])

base, work = walk(BASE), walk(WORK)
changed = sorted(set(base) | set(work))
for rel in changed:
    b, w = base.get(rel), work.get(rel)
    if b and w and read(b) == read(w): continue
    kind = "added" if not b else "deleted" if not w else "modified"
    name = os.path.basename(rel)
    if name in DEPFILES:
        notes.append(f"dependency manifest {kind}: {rel}"); continue
    if owned(rel):
        if kind == "deleted": errors.append(f"deleted an owned stub/file (do not delete): {rel}")
        continue
    if rel in SHARED:
        if kind == "deleted": errors.append(f"deleted shared file {rel}"); continue
        bt, wt = read(b).decode("utf8","replace"), read(w).decode("utf8","replace")
        for mk in set(re.findall(r"\[((?:NET|APP)-[A-Z-]*?)-BEGIN\]", bt)):
            if f"[{mk}-BEGIN]" not in wt or f"[{mk}-END]" not in wt:
                errors.append(f"{rel}: marker [{mk}-BEGIN/END] was removed")
        a, c = strip_own(bt, SIDE), strip_own(wt, SIDE)
        if "<<UNCLOSED>>" in c: errors.append(f"{rel}: unclosed [{SIDE}-…-BEGIN] block")
        if a != c:
            diff = [l for l in difflib.unified_diff(a, c, lineterm="", n=0) if l[:1] in "+-" and l[:3] not in ("+++","---")]
            errors.append(f"{rel}: edited outside {SIDE} marker blocks, e.g. {diff[0][:100]!r} ({len(diff)} changed lines)")
        else:
            notes.append(f"shared file edited inside {SIDE} markers: {rel}")
        continue
    why = "owned by the other build" if owned_by_other(rel) else "foundation or unowned file"
    errors.append(f"{kind} {rel}: {why}")

# migrations: unique filenames across both migration dirs
names = {}
for rel in work:
    if re.search(r"store/migrations/\d+_.*\.sql$", rel):
        names.setdefault(os.path.basename(rel), []).append(rel)
for n, rs in names.items():
    if len(rs) > 1: errors.append(f"migration filename not unique across dirs: {n} -> {rs}")
for rel in work:
    if re.search(r"store/migrations/\d+_.*\.sql$", rel) and rel not in base:
        txt = read(work[rel]).decode("utf8","replace")
        for m in re.finditer(r"CREATE\s+(?:UNIQUE\s+)?(TABLE|INDEX)\s+(?!IF NOT EXISTS)", txt, re.I):
            errors.append(f"{rel}: CREATE {m.group(1)} without IF NOT EXISTS (migrations must be idempotent)")

# Go identifier collisions: package api / store are shared, so new top-level names need a prefix.
decl = re.compile(r"^(?:func\s+(\w+)\s*\(|type\s+(\w+)\s|var\s+(\w+)\s|const\s+(\w+)\s)", re.M)
for rel in work:
    if not rel.endswith(".go") or not re.search(r"internal/(api|store)/[^/]+\.go$", rel): continue
    if rel in base or not owned(rel): continue
    for m in decl.finditer(read(work[rel]).decode("utf8","replace")):
        nm = next(g for g in m.groups() if g)
        ok = re.match(rf"^(?:{P}|{IDPREFIX}|{P.capitalize()}|Test{IDPREFIX}|Benchmark{IDPREFIX}|register{IDPREFIX})", nm, re.I) or nm in ("init",)
        if nm.startswith(("Test","Benchmark")): ok = nm[4:].lower().startswith(P) if nm.startswith("Test") else nm[9:].lower().startswith(P)
        if not ok and not (SIDE=="NET" and re.match(r"^(probe|network|Probe|Network)", nm)):
            errors.append(f"{rel}: top-level name {nm!r} must start with {P!r}/{IDPREFIX!r} (package is shared)")

# frontend exports must not shadow shared names; manifest required
if not any(os.path.exists(os.path.join(WORK, f"MANIFEST_{SIDE}.md")) for _ in [0]):
    errors.append(f"MANIFEST_{SIDE}.md missing (see HANDOFF contract section 8)")
# no new files left in the other side's folders even if untouched baseline stubs
for rel in work:
    if rel not in base and owned_by_other(rel): errors.append(f"new file in the other build's area: {rel}")

print(f"== {SIDE} handoff check: {len(changed)} paths compared ==")
for n in notes: print("note:", n)
for e in errors: print("VIOLATION:", e)
print("RESULT:", "FAIL" if errors else "OK")
sys.exit(1 if errors else 0)
