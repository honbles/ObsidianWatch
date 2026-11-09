package collector

// es_exec_parse.go — parser for `eslogger exec` output (macOS 13+).
//
// eslogger streams one JSON object per Endpoint Security event. Only the exec
// fields we need are decoded. The schema is Apple-defined and not versioned in
// our repo, so every field is optional and a record missing the essentials
// (pid, executable path) is rejected rather than guessed.
// Kept free of build tags so it can be unit-tested on any OS.

import (
	"encoding/json"
	"errors"
	"time"
)

type esExecEvent struct {
	PID  int
	PPID int
	UID  uint32
	Exe  string
	Args []string
	Time time.Time
}

type esRecord struct {
	Time  string `json:"time"`
	Event struct {
		Exec *struct {
			Args   []string `json:"args"`
			Target struct {
				AuditToken struct {
					PID  int    `json:"pid"`
					EUID uint32 `json:"euid"`
				} `json:"audit_token"`
				PPID       int `json:"ppid"`
				Executable struct {
					Path string `json:"path"`
				} `json:"executable"`
			} `json:"target"`
		} `json:"exec"`
	} `json:"event"`
}

var errNotExec = errors.New("not an exec event")

// parseESExec decodes one eslogger line.
func parseESExec(line []byte) (esExecEvent, error) {
	var r esRecord
	if err := json.Unmarshal(line, &r); err != nil {
		return esExecEvent{}, err
	}
	if r.Event.Exec == nil {
		return esExecEvent{}, errNotExec
	}
	t := r.Event.Exec.Target
	if t.AuditToken.PID <= 0 || t.Executable.Path == "" {
		return esExecEvent{}, errors.New("exec event missing pid or executable path")
	}
	ev := esExecEvent{
		PID:  t.AuditToken.PID,
		PPID: t.PPID,
		UID:  t.AuditToken.EUID,
		Exe:  t.Executable.Path,
		Args: r.Event.Exec.Args,
		Time: time.Now().UTC(),
	}
	if r.Time != "" {
		if ts, err := time.Parse(time.RFC3339Nano, r.Time); err == nil {
			ev.Time = ts.UTC()
		}
	}
	return ev, nil
}
