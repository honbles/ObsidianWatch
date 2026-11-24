package response

// actions_more.go - file, network and account response actions:
//
//	delete_file         permanently delete a file (optionally only if its SHA-256 still matches)
//	delete_quarantined  permanently delete a file held in the quarantine vault
//	file_info           size, times, mode and SHA-256 of a file (read-only)
//	collect_file        fetch a small file for analysis (read-only, up to 2 MiB)
//	block_ip            drop all traffic to and from an address (survives restarts)
//	unblock_ip          lift such a block
//	list_blocked_ips    addresses currently blocked
//	disable_user        lock a local account and end its processes
//	enable_user         unlock it again
//
// The platform parts are applyIPBlocks, disableUser and enableUser
// (extra_<os>.go).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxCollectBytes = 2 << 20

// checkFileTarget applies the rules shared by quarantine and delete: an
// absolute path to a regular file outside the OS, the agent's own data and
// the agent binary.
func (h *Handler) checkFileTarget(path, verb string) (string, os.FileInfo, *Result) {
	if path == "" || !filepath.IsAbs(path) {
		return "", nil, &Result{Message: "an absolute file path is required"}
	}
	path = filepath.Clean(path)
	if protectedPath(path) {
		return "", nil, &Result{Message: "refusing to " + verb + " an operating-system file (" + path + "); that would damage the host"}
	}
	if strings.HasPrefix(strings.ToLower(path), strings.ToLower(h.dir)+string(filepath.Separator)) {
		return "", nil, &Result{Message: "refusing to " + verb + " the agent's own data"}
	}
	if exe, err := os.Executable(); err == nil && strings.EqualFold(exe, path) {
		return "", nil, &Result{Message: "refusing to " + verb + " the ObsidianWatch agent binary"}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return "", nil, &Result{Message: err.Error()}
	}
	if !fi.Mode().IsRegular() {
		return "", nil, &Result{Message: "not a regular file (symlinks and directories are not handled)"}
	}
	return path, fi, nil
}

// FileFacts describes a file for the server.
type FileFacts struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	Modified time.Time `json:"modified"`
	SHA256   string    `json:"sha256,omitempty"`
	Content  string    `json:"content_b64,omitempty"`
	Deleted  bool      `json:"deleted,omitempty"`
}

func (h *Handler) deleteFile(p Params) Result {
	path, fi, bad := h.checkFileTarget(p.Path, "delete")
	if bad != nil {
		return *bad
	}
	want := strings.ToLower(strings.TrimSpace(p.SHA256))
	if want != "" && !sha256Re.MatchString(want) {
		return Result{Message: "sha256 must be 64 hex characters"}
	}
	sum, size, err := hashFile(path)
	if err != nil {
		return Result{Message: "cannot read file: " + err.Error()}
	}
	if want != "" && sum != want {
		return Result{Message: fmt.Sprintf("not deleted: the file's SHA-256 is %s, not the expected %s (it changed or is a different file)", sum, want)}
	}
	if err := os.Remove(path); err != nil {
		return Result{Message: "delete failed: " + err.Error()}
	}
	h.logger.Warn("response: file deleted", "path", path, "sha256", sum)
	return Result{OK: true, Message: "deleted " + path, Data: FileFacts{Path: path, Size: size, Mode: fi.Mode().String(), Modified: fi.ModTime().UTC(), SHA256: sum, Deleted: true}}
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (h *Handler) deleteQuarantined(id string) Result {
	if id == "" || strings.ContainsAny(id, `/\.`) {
		return Result{Message: "quarantine id required"}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := filepath.Join(h.vaultDir(), id+".json")
	b, err := os.ReadFile(rec)
	if err != nil {
		return Result{Message: "no such quarantined file"}
	}
	var it QItem
	_ = json.Unmarshal(b, &it)
	if err := os.Remove(filepath.Join(h.vaultDir(), id+".quar")); err != nil && !os.IsNotExist(err) {
		return Result{Message: "delete failed: " + err.Error()}
	}
	_ = os.Remove(rec)
	h.logger.Warn("response: quarantined file deleted", "orig", it.Orig, "sha256", it.SHA256)
	return Result{OK: true, Message: "permanently deleted the quarantined copy of " + it.Orig, Data: it}
}

func (h *Handler) fileInfo(path string, collect bool) Result {
	if path == "" || !filepath.IsAbs(path) {
		return Result{Message: "an absolute file path is required"}
	}
	path = filepath.Clean(path)
	if strings.HasPrefix(strings.ToLower(path), strings.ToLower(h.dir)+string(filepath.Separator)) {
		return Result{Message: "the agent's own data cannot be read remotely"}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return Result{Message: err.Error()}
	}
	f := FileFacts{Path: path, Size: fi.Size(), Mode: fi.Mode().String(), Modified: fi.ModTime().UTC()}
	if !fi.Mode().IsRegular() {
		if collect {
			return Result{Message: "not a regular file"}
		}
		return Result{OK: true, Message: "not a regular file; no hash", Data: f}
	}
	if collect && fi.Size() > maxCollectBytes {
		return Result{Message: fmt.Sprintf("file is %d bytes; collect is limited to %d", fi.Size(), maxCollectBytes)}
	}
	if fi.Size() <= maxQuarantineBytes {
		fh, err := os.Open(path)
		if err != nil {
			return Result{Message: "cannot read file: " + err.Error()}
		}
		defer fh.Close()
		hs := sha256.New()
		var r io.Reader = fh
		var buf []byte
		if collect {
			data, err := io.ReadAll(io.LimitReader(fh, maxCollectBytes+1))
			if err != nil {
				return Result{Message: "cannot read file: " + err.Error()}
			}
			if len(data) > maxCollectBytes {
				return Result{Message: "file grew past the collect limit while being read"}
			}
			buf = data
			hs.Write(data)
		} else if _, err := io.Copy(hs, r); err != nil {
			return Result{Message: "cannot read file: " + err.Error()}
		}
		f.SHA256 = hex.EncodeToString(hs.Sum(nil))
		if collect {
			f.Content = base64.StdEncoding.EncodeToString(buf)
			f.Size = int64(len(buf))
			h.logger.Warn("response: file collected", "path", path, "sha256", f.SHA256, "bytes", len(buf))
		}
	}
	return Result{OK: true, Data: f}
}

// ── IP blocks ─────────────────────────────────────────────────────────────────

func (h *Handler) ipBlockPath() string { return filepath.Join(h.dir, "ip_blocks.json") }

// BlockedIP is one blocked address.
type BlockedIP struct {
	IP string    `json:"ip"`
	At time.Time `json:"at"`
}

func (h *Handler) loadIPBlocks() []BlockedIP {
	var out []BlockedIP
	if b, err := os.ReadFile(h.ipBlockPath()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func (h *Handler) saveIPBlocks(l []BlockedIP) error {
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(l)
	tmp := h.ipBlockPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.ipBlockPath())
}

func ipList(l []BlockedIP) []netip.Addr {
	var out []netip.Addr
	for _, b := range l {
		if a, err := netip.ParseAddr(b.IP); err == nil {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// blockableIP refuses addresses whose block would cut the agent off or make
// no sense.
func (h *Handler) blockableIP(s string) (netip.Addr, string) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, "a single IPv4 or IPv6 address is required"
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return netip.Addr{}, "loopback, unspecified, multicast and link-local addresses cannot be blocked"
	}
	st := h.loadIso()
	for _, x := range st.Allow {
		if x == a.String() {
			return netip.Addr{}, "that is the ObsidianWatch server address; blocking it would cut the agent off"
		}
	}
	for _, ips := range st.HostIPs {
		for _, x := range ips {
			if x == a.String() {
				return netip.Addr{}, "that is the ObsidianWatch server address; blocking it would cut the agent off"
			}
		}
	}
	for _, host := range h.hosts {
		if x, err := netip.ParseAddr(host); err == nil && x.Unmap() == a {
			return netip.Addr{}, "that is the ObsidianWatch server address; blocking it would cut the agent off"
		}
	}
	return a, ""
}

const maxIPBlocks = 1000

func (h *Handler) blockIP(s string) Result {
	a, why := h.blockableIP(s)
	if why != "" {
		return Result{Message: why}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.loadIPBlocks()
	for _, b := range l {
		if b.IP == a.String() {
			return Result{OK: true, Message: a.String() + " is already blocked", Data: l}
		}
	}
	if len(l) >= maxIPBlocks {
		return Result{Message: fmt.Sprintf("at most %d addresses can be blocked", maxIPBlocks)}
	}
	next := append(l, BlockedIP{IP: a.String(), At: time.Now().UTC()})
	if err := applyIPBlocks(ipList(next)); err != nil {
		return Result{Message: "block failed: " + err.Error()}
	}
	if err := h.saveIPBlocks(next); err != nil {
		h.logger.Warn("response: cannot persist ip blocks", "err", err)
	}
	h.logger.Warn("response: ip blocked", "ip", a.String())
	return Result{OK: true, Message: "all traffic to and from " + a.String() + " is blocked", Data: next}
}

func (h *Handler) unblockIP(s string) Result {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return Result{Message: "a single IPv4 or IPv6 address is required"}
	}
	a = a.Unmap()
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.loadIPBlocks()
	var next []BlockedIP
	found := false
	for _, b := range l {
		if b.IP == a.String() {
			found = true
			continue
		}
		next = append(next, b)
	}
	if !found {
		return Result{Message: a.String() + " is not blocked"}
	}
	if err := applyIPBlocks(ipList(next)); err != nil {
		return Result{Message: "unblock failed: " + err.Error()}
	}
	_ = h.saveIPBlocks(next)
	h.logger.Warn("response: ip unblocked", "ip", a.String())
	return Result{OK: true, Message: a.String() + " is no longer blocked", Data: next}
}

// reapplyIPBlocks restores persisted blocks after an agent or host restart.
func (h *Handler) reapplyIPBlocks() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l := h.loadIPBlocks(); len(l) > 0 {
		if err := applyIPBlocks(ipList(l)); err != nil {
			h.logger.Error("response: re-apply ip blocks failed", "err", err)
		}
	}
}

// ── accounts ──────────────────────────────────────────────────────────────────

var userRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@ -]{0,63}$`)

// protectedAccounts are never disabled: losing them breaks the host or the
// agent rather than containing an intruder.
var protectedAccounts = map[string]bool{
	"root": true, "system": true, "localsystem": true, "localservice": true, "networkservice": true,
	"trustedinstaller": true, "daemon": true, "nobody": true, "_obsidianwatch": true, "obsidianwatch": true,
}

func checkUser(u string) (string, string) {
	u = strings.TrimSpace(u)
	if !userRe.MatchString(u) || strings.Contains(u, "..") {
		return "", "a local account name is required (letters, digits, . _ @ - and spaces)"
	}
	if protectedAccounts[strings.ToLower(u)] {
		return "", "refusing to disable " + u + "; it is a system account"
	}
	return u, ""
}

func (h *Handler) disableUserAction(u string) Result {
	name, why := checkUser(u)
	if why != "" {
		return Result{Message: why}
	}
	msg, err := disableUser(name)
	if err != nil {
		return Result{Message: "disable failed: " + err.Error()}
	}
	h.logger.Warn("response: account disabled", "user", name)
	return Result{OK: true, Message: msg}
}

func (h *Handler) enableUserAction(u string) Result {
	name, why := checkUser(u)
	if why != "" {
		return Result{Message: why}
	}
	msg, err := enableUser(name)
	if err != nil {
		return Result{Message: "enable failed: " + err.Error()}
	}
	h.logger.Warn("response: account enabled", "user", name)
	return Result{OK: true, Message: msg}
}
