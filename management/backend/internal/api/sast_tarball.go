package api

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// SA-02: download one tarball per repo/ref instead of one contents-API call
// per file (300+ requests, rate-limit burn). Only files in `want` (already
// filtered/capped by the caller) are written, with the same path-safety
// rules as the per-file path (SA-03). Returns the number of files written.
// maxTarballUncompressed caps total bytes read from a repo tarball stream.
const maxTarballUncompressed = 2 << 30

func fetchGitHubTarballFiles(ctx context.Context, token, owner, repo, ref, repoDir string, want map[string]bool) (int, error) {
	u := fmt.Sprintf("https://api.github.com/repos/%s/%s/tarball", neturl.PathEscape(owner), neturl.PathEscape(repo))
	if ref != "" && ref != "HEAD" && ref != "unknown" {
		u += "/" + neturl.PathEscape(ref)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req) // Go drops Authorization on the cross-host redirect to codeload
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("tarball HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(io.LimitReader(resp.Body, 512<<20)) // 512 MB compressed cap
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	// A 512 MB gzip can expand to hundreds of GB (decompression bomb); the
	// 5-minute client timeout alone still lets that burn CPU and disk I/O.
	tr := tar.NewReader(io.LimitReader(gz, maxTarballUncompressed))
	written := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return written, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Strip the leading "<owner>-<repo>-<sha>/" directory.
		name := hdr.Name
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[i+1:]
		} else {
			continue
		}
		name = path.Clean(name)
		if !want[name] || hdr.Size > int64(sastSizeLimit(name)) {
			continue
		}
		dst := filepath.Join(repoDir, filepath.FromSlash(name))
		rel, relErr := filepath.Rel(repoDir, dst)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(name) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			continue
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			continue
		}
		_, cpErr := io.Copy(f, io.LimitReader(tr, int64(sastSizeLimit(name))))
		f.Close()
		if cpErr != nil {
			continue
		}
		written++
	}
	return written, nil
}
