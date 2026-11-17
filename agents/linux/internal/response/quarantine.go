package response

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxQuarantineBytes = 512 << 20

// QItem is one quarantined file.
type QItem struct {
	ID     string    `json:"id"`
	Orig   string    `json:"orig_path"`
	SHA256 string    `json:"sha256"`
	Size   int64     `json:"size"`
	Mode   uint32    `json:"mode"`
	At     time.Time `json:"at"`
}

func (h *Handler) listQuarantine() []QItem {
	var out []QItem
	ents, _ := os.ReadDir(h.vaultDir())
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(h.vaultDir(), e.Name()))
		if err != nil {
			continue
		}
		var it QItem
		if json.Unmarshal(b, &it) == nil && it.ID != "" {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	hs := sha256.New()
	n, err := io.Copy(hs, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hs.Sum(nil)), n, nil
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// cross-device: copy then remove
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}

// systemPrefixes are operating-system locations that are never quarantined:
// moving a system binary would break the host rather than contain a threat.
var systemPrefixes = []string{
	"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/boot/", "/etc/",
	"/system/", "/library/apple/", "/usr/libexec/",
	`c:\windows\`, `c:\program files\windowsapps\`,
}

func protectedPath(p string) bool {
	l := strings.ToLower(p)
	if filepath.Separator == '\\' {
		l = strings.ReplaceAll(l, "/", `\`)
	}
	for _, pre := range systemPrefixes {
		if strings.HasPrefix(l, pre) {
			return true
		}
	}
	return false
}

func (h *Handler) quarantine(path string) Result {
	if path == "" || !filepath.IsAbs(path) {
		return Result{Message: "an absolute file path is required"}
	}
	path = filepath.Clean(path)
	if protectedPath(path) {
		return Result{Message: "refusing to quarantine an operating-system file (" + path + "); that would damage the host"}
	}
	if strings.HasPrefix(strings.ToLower(path), strings.ToLower(h.dir)+string(filepath.Separator)) {
		return Result{Message: "refusing to quarantine the agent's own data"}
	}
	if exe, err := os.Executable(); err == nil && strings.EqualFold(exe, path) {
		return Result{Message: "refusing to quarantine the ObsidianWatch agent binary"}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return Result{Message: err.Error()}
	}
	if !fi.Mode().IsRegular() {
		return Result{Message: "not a regular file (symlinks and directories are not quarantined)"}
	}
	if fi.Size() > maxQuarantineBytes {
		return Result{Message: fmt.Sprintf("file is %d MB; limit is %d MB", fi.Size()>>20, maxQuarantineBytes>>20)}
	}
	sum, size, err := hashFile(path)
	if err != nil {
		return Result{Message: "cannot read file: " + err.Error()}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := os.MkdirAll(h.vaultDir(), 0o700); err != nil {
		return Result{Message: err.Error()}
	}
	var idb [8]byte
	_, _ = rand.Read(idb[:])
	id := hex.EncodeToString(idb[:])
	dst := filepath.Join(h.vaultDir(), id+".quar")
	if err := moveFile(path, dst); err != nil {
		return Result{Message: "cannot move file into the vault: " + err.Error()}
	}
	_ = os.Chmod(dst, 0o000) // not readable/executable by anyone but root
	it := QItem{ID: id, Orig: path, SHA256: sum, Size: size, Mode: uint32(fi.Mode().Perm()), At: time.Now().UTC()}
	mb, _ := json.Marshal(it)
	if err := os.WriteFile(filepath.Join(h.vaultDir(), id+".json"), mb, 0o600); err != nil {
		_ = os.Chmod(dst, os.FileMode(it.Mode))
		_ = moveFile(dst, path)
		return Result{Message: "cannot write quarantine record: " + err.Error()}
	}
	h.logger.Warn("response: file quarantined", "path", path, "sha256", sum)
	return Result{OK: true, Message: "quarantined " + path, Data: it}
}

func (h *Handler) restore(id string) Result {
	if id == "" || strings.ContainsAny(id, `/\.`) {
		return Result{Message: "quarantine id required"}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(h.vaultDir(), id+".json"))
	if err != nil {
		return Result{Message: "no such quarantined file"}
	}
	var it QItem
	if err := json.Unmarshal(b, &it); err != nil {
		return Result{Message: "corrupt quarantine record"}
	}
	if _, err := os.Lstat(it.Orig); err == nil {
		return Result{Message: it.Orig + " already exists; refusing to overwrite"}
	}
	src := filepath.Join(h.vaultDir(), id+".quar")
	_ = os.Chmod(src, 0o600)
	if err := os.MkdirAll(filepath.Dir(it.Orig), 0o755); err != nil {
		return Result{Message: err.Error()}
	}
	if err := moveFile(src, it.Orig); err != nil {
		_ = os.Chmod(src, 0o000)
		return Result{Message: "restore failed: " + err.Error()}
	}
	_ = os.Chmod(it.Orig, os.FileMode(it.Mode))
	_ = os.Remove(filepath.Join(h.vaultDir(), id+".json"))
	h.logger.Warn("response: file restored", "path", it.Orig)
	return Result{OK: true, Message: "restored " + it.Orig}
}
