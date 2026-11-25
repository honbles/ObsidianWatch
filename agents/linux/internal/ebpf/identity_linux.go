package ebpf

// identity_linux.go - what a discovered service really is. A bare binary name ("build", "redis-check-rdb",
// "otelopscol") tells an operator little; the systemd unit or the container (name, image, compose service)
// is what they call it. Both are read from the host with no daemon access: the unit from the process's
// cgroup path, the container from Docker's own on-disk config (/var/lib/docker/containers/<id>/config.v2.json,
// readable by the root agent). Podman and containerd-only hosts have no such file, so they keep the
// derived name and the container id.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var (
	unitRe = regexp.MustCompile(`([A-Za-z0-9:_.\-]+?)(@[^/]*)?\.service`)
	// units that are the container runtime itself or a login session, never the application
	notAppUnits = map[string]bool{"docker": true, "containerd": true, "user": true, "session": true, "init": true, "systemd": true, "crio": true}
)

// UnitFromCgroup returns the systemd service a cgroup path belongs to ("postgresql@16-main.service" ->
// "postgresql"), or "" for a container, a login session or no unit.
func UnitFromCgroup(cg string) string {
	var unit string
	for _, line := range strings.Split(cg, "\n") {
		i := strings.LastIndex(line, ":")
		if i < 0 {
			continue
		}
		path := line[i+1:]
		if strings.Contains(path, "user@") || strings.Contains(path, "/session-") {
			continue
		}
		if ms := unitRe.FindAllStringSubmatch(path, -1); len(ms) > 0 {
			unit = ms[len(ms)-1][1]
		}
	}
	if notAppUnits[strings.ToLower(unit)] {
		return ""
	}
	return unit
}

// ContainerInfo is what Docker's config says about a container.
type ContainerInfo struct {
	Name    string // container name without the leading slash
	Image   string
	Project string // docker compose project
	Service string // docker compose service
	// Build provenance from the image labels (merged into the container's labels by Docker).
	Revision string // org.opencontainers.image.revision
	Source   string // org.opencontainers.image.source
}

type dockerConfig struct {
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

type containerCache struct {
	mu   sync.Mutex
	root string
	m    map[string]ContainerInfo
}

func newContainerCache(root string) *containerCache {
	if root == "" {
		root = "/var/lib/docker"
	}
	return &containerCache{root: root, m: map[string]ContainerInfo{}}
}

// Lookup returns the container's details; ok is false when Docker's config is not on this host.
func (c *containerCache) Lookup(id string) (ContainerInfo, bool) {
	if len(id) != 64 {
		return ContainerInfo{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ci, ok := c.m[id]; ok {
		return ci, ci.Name != ""
	}
	b, err := os.ReadFile(filepath.Join(c.root, "containers", id, "config.v2.json"))
	ci := ContainerInfo{}
	if err == nil {
		var cfg dockerConfig
		if json.Unmarshal(b, &cfg) == nil {
			l := cfg.Config.Labels
			ci = ContainerInfo{Name: strings.TrimPrefix(cfg.Name, "/"), Image: cfg.Config.Image,
				Project: l["com.docker.compose.project"], Service: l["com.docker.compose.service"],
				Revision: firstLabel(l, "org.opencontainers.image.revision", "org.label-schema.vcs-ref", "vcs-ref"),
				Source:   firstLabel(l, "org.opencontainers.image.source", "org.label-schema.vcs-url", "vcs-url")}
		}
	}
	if len(c.m) > 2000 {
		c.m = map[string]ContainerInfo{}
	}
	c.m[id] = ci // cached even when empty, so a host without Docker config is not re-read every poll
	return ci, ci.Name != ""
}

// BetterName picks what an operator would call the service: the compose service, else the container
// name, else the systemd unit, else the name derived from the binary.
func BetterName(derived, unit string, ci ContainerInfo, haveContainer bool) string {
	if haveContainer {
		if n := cleanName(ci.Service); n != "" {
			return n
		}
		if n := cleanName(ci.Name); n != "" {
			return n
		}
	}
	if n := cleanName(unit); n != "" {
		return n
	}
	return derived
}

func firstLabel(l map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(l[k]); v != "" {
			return v
		}
	}
	return ""
}
