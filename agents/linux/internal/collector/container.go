//go:build linux

package collector

// container.go — P-12: container start events via the Docker Engine socket.
//
// Polls GET /containers/json over /var/run/docker.sock (no docker CLI needed).
// The first poll is a silent baseline. New containers are reported with risky
// settings (privileged, host network/PID, docker.sock mount). Hosts without the
// socket are skipped. Events: event_type="container", source="container".

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

const dockerSock = "/var/run/docker.sock"

type containerInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Image      string   `json:"image"`
	Privileged bool     `json:"privileged"`
	HostNet    bool     `json:"host_network"`
	HostPID    bool     `json:"host_pid"`
	SockMount  bool     `json:"docker_sock_mount"`
	Risks      []string `json:"risks,omitempty"`
}

type dockerInspect struct {
	ID         string
	Name       string
	Config     struct{ Image string }
	HostConfig struct {
		Privileged  bool
		NetworkMode string
		PidMode     string
		Binds       []string
	}
}

// riskOf converts an inspect document into a containerInfo with risk flags.
func riskOf(d dockerInspect) containerInfo {
	ci := containerInfo{ID: d.ID, Name: strings.TrimPrefix(d.Name, "/"), Image: d.Config.Image,
		Privileged: d.HostConfig.Privileged, HostNet: d.HostConfig.NetworkMode == "host", HostPID: d.HostConfig.PidMode == "host"}
	for _, b := range d.HostConfig.Binds {
		if strings.HasPrefix(b, "/var/run/docker.sock") || strings.HasPrefix(b, "/run/docker.sock") {
			ci.SockMount = true
		}
	}
	if ci.Privileged {
		ci.Risks = append(ci.Risks, "privileged")
	}
	if ci.HostNet {
		ci.Risks = append(ci.Risks, "host_network")
	}
	if ci.HostPID {
		ci.Risks = append(ci.Risks, "host_pid")
	}
	if ci.SockMount {
		ci.Risks = append(ci.Risks, "docker_sock_mount")
	}
	return ci
}

type ContainerCollector struct {
	sock    string
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
	client  *http.Client
}

func NewContainerCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *ContainerCollector {
	c := &ContainerCollector{sock: dockerSock, out: out, agentID: agentID, host: host, logger: logger}
	c.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.sock)
		}}}
	return c
}

func (c *ContainerCollector) get(path string, v interface{}) error {
	resp, err := c.client.Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func (c *ContainerCollector) list() map[string]bool {
	var l []struct{ Id string }
	out := map[string]bool{}
	if c.get("/containers/json", &l) == nil {
		for _, x := range l {
			out[x.Id] = true
		}
	}
	return out
}

func (c *ContainerCollector) Run(ctx context.Context) error {
	if _, err := os.Stat(c.sock); err != nil {
		return nil
	}
	known := c.list()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		cur := c.list()
		for id := range cur {
			if known[id] {
				continue
			}
			var d dockerInspect
			if c.get("/containers/"+id+"/json", &d) == nil {
				c.emit(riskOf(d))
			}
		}
		known = cur
	}
}

func (c *ContainerCollector) emit(ci containerInfo) {
	sev := schema.SeverityInfo
	if len(ci.Risks) > 0 {
		sev = schema.SeverityMedium
	}
	raw, _ := json.Marshal(map[string]interface{}{"action": "container_started", "container": ci})
	ev := schema.Event{
		Time: time.Now().UTC(), AgentID: c.agentID, Host: c.host, OS: "linux",
		EventType: schema.EventType("container"), Severity: sev, Source: "container", Raw: raw,
		ProcessName: ci.Image,
	}
	select {
	case c.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}
