//go:build linux

package ebpf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"time"

	"obsidianwatch/linux-agent/internal/runtimeinv"
	"obsidianwatch/linux-agent/pkg/schema"
)

// Runtime package inventory (Code step 4): every service process's loaded and
// deployed third-party packages, reported as runtime_inventory events so the
// server can tell which vulnerable dependencies are actually running.

const (
	inventoryEvery   = 15 * time.Minute
	inventoryResend  = 6 * time.Hour // unchanged inventories are re-sent this often
	inventoryChunk   = 500           // packages per event (events.raw is capped at 64 KiB)
	inventoryFirstAt = 2 * time.Minute
)

// EventTypeRuntimeInventory is the event type the server's reachability
// index reads.
const EventTypeRuntimeInventory schema.EventType = "runtime_inventory"

type invSent struct {
	hash string
	at   time.Time
}

func (s *Sensor) runInventory(ctx context.Context) {
	sent := map[string]invSent{} // pid:start -> last report
	timer := time.NewTimer(inventoryFirstAt)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		live := map[string]bool{}
		for pid, service := range s.reg.Snapshot() {
			d, err := s.fs.info(pid)
			if err != nil {
				continue
			}
			key := strconv.Itoa(pid) + ":" + d.Start.String()
			live[key] = true
			res, err := runtimeinv.Inventory(s.fs.root, pid)
			if err != nil || len(res.Packages) == 0 {
				continue
			}
			b, _ := json.Marshal(res.Packages)
			sum := sha256.Sum256(b)
			h := hex.EncodeToString(sum[:8])
			if prev, ok := sent[key]; ok && prev.hash == h && time.Since(prev.at) < inventoryResend {
				continue
			}
			if service == "otel" {
				service = ""
			}
			if s.emitInventory(pid, service, d, res, h) {
				sent[key] = invSent{hash: h, at: time.Now()}
			}
		}
		for k := range sent {
			if !live[k] {
				delete(sent, k)
			}
		}
		timer.Reset(inventoryEvery)
	}
}

func (s *Sensor) emitInventory(pid int, service string, d procDetail, res runtimeinv.Result, hash string) bool {
	n := (len(res.Packages) + inventoryChunk - 1) / inventoryChunk
	ok := true
	for i := 0; i < n; i++ {
		end := (i + 1) * inventoryChunk
		if end > len(res.Packages) {
			end = len(res.Packages)
		}
		raw, _ := json.Marshal(map[string]any{
			"inventory": map[string]any{
				"service": service, "pid": pid, "container": d.Container, "exe": d.Exe,
				"language": res.Language, "truncated": res.Truncated,
				"hash": hash, "chunk": i + 1, "chunks": n, "packages": res.Packages[i*inventoryChunk : end],
			},
		})
		ev := schema.Event{
			ID: newEventID(), Time: time.Now().UTC(), AgentID: s.o.AgentID, Host: s.o.Hostname, OS: s.o.OS,
			EventType: EventTypeRuntimeInventory, Severity: schema.SeverityInfo, Source: "runtime-inventory", Raw: raw,
			PID: pid, ProcessName: filepath.Base(d.Exe), ImagePath: d.Exe,
		}
		if !s.o.Emit(ev) {
			ok = false
		}
	}
	return ok
}
