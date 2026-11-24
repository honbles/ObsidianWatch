//go:build linux

package collector

// A1 (FP reduction): package-verified tagging for process events.
//
// After an exec we resolve the owning dpkg package of the running binary and
// compare the file's MD5 with the one recorded in /var/lib/dpkg/info/*.md5sums
// (dpkg's own format, which is why MD5 is used here). Only the entry for this
// exact path is compared, so missing docs/man pages elsewhere in the same
// package cannot affect the result.
//
// The SIEM uses pkg_verified to DOWNGRADE hash-IOC hits, never to drop them: a
// root attacker can edit the dpkg database.
//
// Semantics of the emitted fields:
//   pkg_verified=true   file is owned by a package and matches its recorded MD5
//   pkg_verified=false  dpkg is present and the file is unowned or modified
//   (field absent)      unknown: no dpkg, deleted binary, too large, rate limited
// On rpm hosts (no dpkg database) the owning package and the recorded file
// digest come from `rpm -qf`; hosts with neither package manager emit no field.

import (
	"bufio"
	"context"
	"crypto/md5" //nolint:gosec // dpkg md5sums format, integrity check only
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var dpkgInfoDir = "/var/lib/dpkg/info"

const (
	pkgMaxPerSec    = 50
	pkgCacheMax     = 4096
	pkgIndexRecheck = 60 * time.Second
)

type pkgEntry struct{ pkg, md5 string }

type pkgIndex struct {
	entries   map[string]pkgEntry // "/abs/path" -> owner + md5
	available bool
	built     time.Time
	dirMTime  time.Time
}

type pkgVerdict struct {
	verified, known bool
	pkg             string
}

var (
	pkgMu       sync.Mutex
	pkgIdx      *pkgIndex
	pkgCache    = map[string]pkgVerdict{}
	pkgWinStart time.Time
	pkgWinCount int
)

// loadDpkgIndex reads every *.md5sums file in dir. A missing dir yields an
// index with available=false (package manager absent => unknown).
func loadDpkgIndex(dir string) (*pkgIndex, error) {
	idx := &pkgIndex{entries: map[string]pkgEntry{}, built: time.Now()}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return idx, nil
	}
	idx.dirMTime = st.ModTime()
	names, err := os.ReadDir(dir)
	if err != nil {
		return idx, err
	}
	for _, de := range names {
		n := de.Name()
		if !strings.HasSuffix(n, ".md5sums") {
			continue
		}
		pkg := strings.TrimSuffix(n, ".md5sums")
		if i := strings.IndexByte(pkg, ':'); i >= 0 {
			pkg = pkg[:i] // strip :arch
		}
		f, err := os.Open(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			parts := strings.SplitN(sc.Text(), "  ", 2)
			if len(parts) != 2 || len(parts[0]) != 32 {
				continue
			}
			idx.entries["/"+strings.TrimPrefix(parts[1], "/")] = pkgEntry{pkg: pkg, md5: strings.ToLower(parts[0])}
		}
		f.Close()
	}
	idx.available = true
	return idx, nil
}

// pkgPathCandidates returns the path plus its merged-/usr aliases
// (/bin <-> /usr/bin, ...), since dpkg may record either spelling.
func pkgPathCandidates(p string) []string {
	out := []string{p}
	for _, pair := range [][2]string{
		{"/usr/bin/", "/bin/"}, {"/usr/sbin/", "/sbin/"}, {"/usr/lib/", "/lib/"},
		{"/bin/", "/usr/bin/"}, {"/sbin/", "/usr/sbin/"}, {"/lib/", "/usr/lib/"},
	} {
		if strings.HasPrefix(p, pair[0]) {
			out = append(out, pair[1]+strings.TrimPrefix(p, pair[0]))
		}
	}
	return out
}

func (i *pkgIndex) lookup(path string) (pkgEntry, bool) {
	for _, c := range pkgPathCandidates(path) {
		if e, ok := i.entries[c]; ok {
			return e, true
		}
	}
	return pkgEntry{}, false
}

func currentPkgIndex() *pkgIndex {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	if pkgIdx != nil && time.Since(pkgIdx.built) < pkgIndexRecheck {
		return pkgIdx
	}
	if pkgIdx != nil {
		if st, err := os.Stat(dpkgInfoDir); err == nil && st.ModTime().Equal(pkgIdx.dirMTime) {
			pkgIdx.built = time.Now()
			return pkgIdx
		}
	}
	if idx, _ := loadDpkgIndex(dpkgInfoDir); idx != nil {
		pkgIdx = idx
		pkgCache = map[string]pkgVerdict{} // package set changed
	}
	return pkgIdx
}

// pkgVerify reports whether the running binary of pid (resolved path exePath)
// is a package-verified file. known=false means "unknown", not "unverified".
func pkgVerify(pid int, exePath, sha256hex string) (verified, known bool, pkg string) {
	if exePath == "" || strings.HasSuffix(exePath, " (deleted)") {
		return false, false, ""
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false, false, ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > exeHashMaxSize {
		return false, false, ""
	}
	key := fmt.Sprintf("%s|%d|%d|%d", exePath, inodeOf(st), st.Size(), st.ModTime().UnixNano())

	pkgMu.Lock()
	if v, ok := pkgCache[key]; ok {
		pkgMu.Unlock()
		return v.verified, v.known, v.pkg
	}
	now := time.Now()
	if now.Sub(pkgWinStart) >= time.Second {
		pkgWinStart, pkgWinCount = now, 0
	}
	if pkgWinCount >= pkgMaxPerSec {
		pkgMu.Unlock()
		return false, false, "" // rate limited: unknown
	}
	pkgWinCount++
	pkgMu.Unlock()

	idx := currentPkgIndex()
	if idx == nil || !idx.available {
		// No dpkg database: try rpm.
		rv, rknown, rpkg := rpmVerify(exePath, sha256hex, f)
		if !rknown {
			return false, false, ""
		}
		v := pkgVerdict{verified: rv, known: true, pkg: rpkg}
		pkgMu.Lock()
		if len(pkgCache) >= pkgCacheMax {
			pkgCache = map[string]pkgVerdict{}
		}
		pkgCache[key] = v
		pkgMu.Unlock()
		return v.verified, v.known, v.pkg
	}
	var v pkgVerdict
	if ent, ok := idx.lookup(exePath); !ok {
		v = pkgVerdict{verified: false, known: true}
	} else {
		h := md5.New() //nolint:gosec
		if _, err := io.Copy(h, f); err != nil {
			return false, false, ""
		}
		v = pkgVerdict{verified: hex.EncodeToString(h.Sum(nil)) == ent.md5, known: true, pkg: ent.pkg}
	}
	pkgMu.Lock()
	if len(pkgCache) >= pkgCacheMax {
		pkgCache = map[string]pkgVerdict{}
	}
	pkgCache[key] = v
	pkgMu.Unlock()
	return v.verified, v.known, v.pkg
}

// ── rpm ──────────────────────────────────────────────────────────────────────

type rpmFile struct{ digest, pkg string }

const rpmQueryTimeout = 3 * time.Second

// parseRPMDigests parses `rpm -qf --qf "[%{FILENAMES}\t%{FILEDIGESTS}\t%{NAME}\n]"`.
func parseRPMDigests(out string) map[string]rpmFile {
	m := map[string]rpmFile{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == "" {
			continue
		}
		m[f[0]] = rpmFile{digest: strings.ToLower(f[1]), pkg: f[2]}
	}
	return m
}

// rpmVerify checks the running binary against the digest rpm recorded for the
// package that owns it. known=false when rpm is absent, errors or times out.
func rpmVerify(exePath, sha256hex string, f *os.File) (verified, known bool, pkg string) {
	rpm, err := exec.LookPath("rpm")
	if err != nil {
		return false, false, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpmQueryTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, rpm, "-qf", "--qf", `[%{FILENAMES}\t%{FILEDIGESTS}\t%{NAME}\n]`, "--", exePath).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ctx.Err() == nil && ee.ExitCode() == 1 {
			return false, true, "" // "not owned by any package"
		}
		return false, false, ""
	}
	files := parseRPMDigests(string(out))
	var rf rpmFile
	found := false
	for _, c := range pkgPathCandidates(exePath) {
		if r, ok := files[c]; ok {
			rf, found = r, true
			break
		}
	}
	if !found {
		return false, true, ""
	}
	switch len(rf.digest) {
	case 64:
		return rf.digest == strings.ToLower(sha256hex), true, rf.pkg
	case 32:
		h := md5.New() //nolint:gosec
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return false, false, ""
		}
		if _, err := io.Copy(h, f); err != nil {
			return false, false, ""
		}
		return hex.EncodeToString(h.Sum(nil)) == rf.digest, true, rf.pkg
	}
	return false, false, "" // unsupported digest algorithm (e.g. sha512): unknown
}
