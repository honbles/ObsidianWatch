//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// File events come from fanotify marks on specific directories (writes) and files (opens). Marks on
// inodes are cheap: the kernel reports only those, not every open on the mount. fanotify needs
// CAP_SYS_ADMIN; where it is refused the sensor runs without file events and logs why.

const (
	fanEventSize   = 24 // sizeof(struct fanotify_event_metadata)
	maxWatchedDirs = 500
	maxWatchDepth  = 3
)

var defaultWatchDirs = []string{"/var/www", "/srv/www", "/usr/share/nginx/html", "/var/lib/tomcat/webapps", "/opt/tomcat/webapps"}

func (s *Sensor) secretFiles() []string {
	files := []string{"/etc/shadow", "/etc/gshadow"}
	files = append(files, s.o.SecretFiles...)
	homes := []string{"/root"}
	if ents, err := os.ReadDir("/home"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				homes = append(homes, filepath.Join("/home", e.Name()))
			}
		}
	}
	for _, h := range homes {
		for _, rel := range []string{".aws/credentials", ".kube/config", ".docker/config.json", ".git-credentials", ".netrc"} {
			files = append(files, filepath.Join(h, rel))
		}
		if keys, err := filepath.Glob(filepath.Join(h, ".ssh", "id_*")); err == nil {
			for _, k := range keys {
				if !strings.HasSuffix(k, ".pub") {
					files = append(files, k)
				}
			}
		}
	}
	return files
}

// walkDirs lists directories under root to a bounded depth.
func walkDirs(root string, budget *int) []string {
	var out []string
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.Count(filepath.Clean(p), string(filepath.Separator))-rootDepth > maxWatchDepth || *budget <= 0 {
			return filepath.SkipDir
		}
		*budget--
		out = append(out, p)
		return nil
	})
	return out
}

func (s *Sensor) runFanotify(ctx context.Context) {
	fd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_CLASS_NOTIF|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		s.o.Logger.Info("host sensor: file events unavailable (fanotify refused)", "err", err)
		return
	}
	defer unix.Close(fd)
	marked := 0
	budget := maxWatchedDirs
	dirs := append(append([]string{}, defaultWatchDirs...), s.o.WatchDirs...)
	for _, root := range dirs {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		for _, d := range walkDirs(root, &budget) {
			// Close-after-write on children of the directory: the file was created or modified.
			if unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_CLOSE_WRITE|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, d) == nil {
				marked++
			}
		}
	}
	for _, f := range s.secretFiles() {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		if unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN, unix.AT_FDCWD, f) == nil {
			marked++
		}
	}
	if marked == 0 {
		s.o.Logger.Info("host sensor: no watch directories or credential files found for file events")
		return
	}
	s.o.Logger.Info("host sensor: file events active", "marks", marked)
	buf := make([]byte, 64*1024)
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		// Wake the moment an event is ready: the writer may be short-lived, and its process can only be
		// identified while it still exists.
		if _, err := unix.Poll(pfd, 250); err != nil && err != unix.EINTR {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil || n < fanEventSize {
			continue
		}
		for off := 0; off+fanEventSize <= n; {
			evLen := int(binary.LittleEndian.Uint32(buf[off:]))
			if evLen < fanEventSize || off+evLen > n {
				break
			}
			mask := binary.LittleEndian.Uint64(buf[off+8:])
			efd := int(int32(binary.LittleEndian.Uint32(buf[off+16:])))
			pid := int(int32(binary.LittleEndian.Uint32(buf[off+20:])))
			off += evLen
			if efd < 0 {
				continue
			}
			path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", efd))
			unix.Close(efd)
			if path == "" || pid <= 0 || pid == os.Getpid() {
				continue
			}
			op := "open"
			if mask&unix.FAN_CLOSE_WRITE != 0 {
				op = "write"
			}
			s.onFile(pid, path, op)
		}
	}
}

// onFile reports a file access by a watched process.
func (s *Sensor) onFile(pid int, path, op string) {
	d, err := s.fs.full(pid)
	if err != nil || !s.watched(d.Lineage()) {
		return
	}
	mode := ""
	if st, err := os.Stat(path); err == nil {
		mode = fmt.Sprintf("%04o", st.Mode().Perm())
	}
	s.emit(FileEvent(&s.o, "fanotify", d.ProcInfo, path, op, mode), &s.nFile)
}
