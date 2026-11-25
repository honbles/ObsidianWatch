package ebpf

// vcs_linux.go - which commit a discovered process runs. Read without running
// anything: the image labels of its container (identity_linux.go), else a git
// checkout the process runs from (its working directory or the directory of its
// executable, and up to four parents), read through /proc/<pid>/ so it works
// inside containers too.

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/linux-agent/internal/otel"
)

// VCSInfo is the build provenance of one process.
type VCSInfo struct {
	Revision, Repo, Branch, Source string
}

type vcsCache struct {
	mu sync.Mutex
	m  map[string]VCSInfo // pid:start
}

func newVCSCache() *vcsCache { return &vcsCache{m: map[string]VCSInfo{}} }

// lookup returns the provenance of a process, cached for the life of the process.
func (c *vcsCache) lookup(root string, pid int, start time.Time, exe string, ci ContainerInfo) VCSInfo {
	key := strconv.Itoa(pid) + ":" + start.String()
	c.mu.Lock()
	if v, ok := c.m[key]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()
	v := VCSInfo{}
	if rev := otel.CleanRevision(ci.Revision); rev != "" {
		v = VCSInfo{Revision: rev, Repo: otel.CleanRepoURL(ci.Source), Source: "oci"}
	} else {
		proc := filepath.Join(root, strconv.Itoa(pid))
		dirs := []string{filepath.Join(proc, "cwd")}
		if exe != "" {
			dirs = append(dirs, filepath.Join(proc, "root", filepath.Dir(exe)))
		}
		for _, d := range dirs {
			if g, ok := findGit(d); ok {
				v = g
				break
			}
		}
	}
	c.mu.Lock()
	if len(c.m) > 5000 {
		c.m = map[string]VCSInfo{}
	}
	c.m[key] = v
	c.mu.Unlock()
	return v
}

// findGit looks for a .git directory in dir and up to four parents.
func findGit(dir string) (VCSInfo, bool) {
	for i := 0; i < 5; i++ {
		gd := filepath.Join(dir, ".git")
		if fi, err := os.Stat(gd); err == nil && fi.IsDir() {
			return readGit(gd)
		}
		parent := filepath.Join(dir, "..")
		if parent == dir {
			break
		}
		dir = parent
	}
	return VCSInfo{}, false
}

// readGit reads HEAD, the branch ref (loose or packed) and the origin URL.
func readGit(gd string) (VCSInfo, bool) {
	head, err := readSmall(filepath.Join(gd, "HEAD"))
	if err != nil {
		return VCSInfo{}, false
	}
	head = strings.TrimSpace(head)
	v := VCSInfo{Source: "git"}
	if ref, ok := strings.CutPrefix(head, "ref: "); ok {
		v.Branch = strings.TrimPrefix(ref, "refs/heads/")
		if !strings.HasPrefix(ref, "refs/") || strings.Contains(ref, "..") {
			return VCSInfo{}, false
		}
		if b, err := readSmall(filepath.Join(gd, filepath.FromSlash(ref))); err == nil {
			v.Revision = otel.CleanRevision(strings.TrimSpace(b))
		} else if p, err := readSmall(filepath.Join(gd, "packed-refs")); err == nil {
			for _, line := range strings.Split(p, "\n") {
				if f := strings.Fields(line); len(f) == 2 && f[1] == ref {
					v.Revision = otel.CleanRevision(f[0])
				}
			}
		}
	} else {
		v.Revision = otel.CleanRevision(head) // detached HEAD
	}
	if v.Revision == "" {
		return VCSInfo{}, false
	}
	if f, err := os.Open(filepath.Join(gd, "config")); err == nil {
		sc := bufio.NewScanner(f)
		inOrigin := false
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "[") {
				inOrigin = line == `[remote "origin"]`
				continue
			}
			if inOrigin {
				if k, val, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "url" {
					v.Repo = otel.CleanRepoURL(strings.TrimSpace(val))
				}
			}
		}
		f.Close()
	}
	return v, true
}

func readSmall(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b := make([]byte, 64<<10)
	n, _ := f.Read(b)
	return string(b[:n]), nil
}
