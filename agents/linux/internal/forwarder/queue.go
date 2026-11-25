package forwarder

// queue.go - a durable FIFO backed by newline-delimited JSON segment files.
// Uses ONLY the Go standard library - zero external dependencies.
//
// Layout on disk:
//   <dir>/
//     segments/
//       0000000001.jsonl   <- oldest segment
//       0000000002.jsonl
//
// Each .jsonl file holds up to segmentSize events (one JSON object per line).
// Push appends to the newest segment and fsyncs it before returning.
// Delivery is at-least-once: Peek reads from the front without removing,
// and Ack removes what was read only after the backend accepted it. A crash
// between send and Ack resends the batch; the backend drops duplicates by
// event id. Pop (Peek then Ack at once) is kept for callers that do not send.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"obsidianwatch/linux-agent/pkg/schema"
)

const (
	segmentSize = 500 // max events per segment file
	maxSegments = 200 // max segments before evicting oldest (~100k events)
)

// Queue is a persistent file-backed FIFO of schema.Events.
type Queue struct {
	dir        string
	mu         sync.Mutex
	logger     *slog.Logger
	writeFile  *os.File
	writeSeq   int64
	writeCount int
}

// NewQueue opens (or creates) the queue directory at dir.
// maxRows is accepted for API compatibility; enforced via maxSegments.
func NewQueue(dir string, _ int, logger *slog.Logger) (*Queue, error) {
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0700); err != nil {
		return nil, fmt.Errorf("queue: mkdir %q: %w", segDir, err)
	}

	q := &Queue{dir: dir, logger: logger}

	seqs, err := q.listSegments()
	if err != nil {
		return nil, err
	}
	if len(seqs) > 0 {
		q.writeSeq = seqs[len(seqs)-1]
		q.writeCount, _ = countLines(q.segPath(q.writeSeq))
	} else {
		q.writeSeq = 1
	}
	return q, nil
}

// Push appends events to the queue.
func (q *Queue) Push(events []schema.Event) error {
	if len(events) == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	q.evictIfNeeded()

	for _, ev := range events {
		if q.writeCount >= segmentSize {
			if q.writeFile != nil {
				q.writeFile.Close()
				q.writeFile = nil
			}
			q.writeSeq++
			q.writeCount = 0
		}

		if q.writeFile == nil {
			f, err := os.OpenFile(q.segPath(q.writeSeq), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("queue: open segment: %w", err)
			}
			q.writeFile = f
		}

		b, err := json.Marshal(ev)
		if err != nil {
			q.logger.Warn("queue: marshal failed, skipping", "err", err)
			continue
		}
		if _, err := fmt.Fprintf(q.writeFile, "%s\n", b); err != nil {
			return fmt.Errorf("queue: write: %w", err)
		}
		q.writeCount++
	}
	if q.writeFile != nil {
		if err := q.writeFile.Sync(); err != nil {
			return fmt.Errorf("queue: sync: %w", err)
		}
	}
	return nil
}

// segTake is how many lines Peek read from the front of one segment.
type segTake struct {
	seq   int64
	lines int
}

// Receipt identifies what one Peek returned; pass it to Ack.
type Receipt struct {
	takes []segTake
}

// Peek returns up to n events from the front of the queue without removing
// them. Lines that do not parse are counted in the receipt so Ack removes
// them too.
func (q *Queue) Peek(n int) ([]schema.Event, Receipt, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var rc Receipt
	seqs, err := q.listSegments()
	if err != nil || len(seqs) == 0 {
		return nil, rc, err
	}
	var events []schema.Event
	for _, seq := range seqs {
		if len(events) >= n {
			break
		}
		lines, err := readLines(q.segPath(seq))
		if err != nil {
			q.logger.Warn("queue: read segment failed", "seq", seq, "err", err)
			continue
		}
		take := 0
		for _, line := range lines {
			if len(events) >= n {
				break
			}
			take++
			var ev schema.Event
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				q.logger.Warn("queue: unmarshal failed, dropping line", "err", err)
				continue
			}
			events = append(events, ev)
		}
		if take > 0 {
			rc.takes = append(rc.takes, segTake{seq: seq, lines: take})
		}
	}
	return events, rc, nil
}

// Ack removes what a Peek returned. Push only appends, so the lines Peek read
// are still the first lines of their segments; a segment evicted in between
// is skipped.
func (q *Queue) Ack(rc Receipt) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, t := range rc.takes {
		path := q.segPath(t.seq)
		lines, err := readLines(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("queue: ack read: %w", err)
		}
		isWriteSeg := t.seq == q.writeSeq
		// Windows cannot rename over an open handle: close it first.
		if isWriteSeg && q.writeFile != nil {
			q.writeFile.Close()
			q.writeFile = nil
		}
		if t.lines >= len(lines) {
			if isWriteSeg {
				q.writeCount = 0
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("queue: ack remove: %w", err)
			}
			continue
		}
		keep := lines[t.lines:]
		if err := writeLines(path, keep); err != nil {
			return fmt.Errorf("queue: ack rewrite: %w", err)
		}
		if isWriteSeg {
			q.writeCount = len(keep)
		}
	}
	syncDir(filepath.Join(q.dir, "segments"))
	return nil
}

// Pop removes and returns up to n events (Peek and Ack together). Use Peek
// and Ack when the events are sent somewhere that can fail.
func (q *Queue) Pop(n int) ([]schema.Event, error) {
	events, rc, err := q.Peek(n)
	if err != nil || len(events) == 0 && len(rc.takes) == 0 {
		return events, err
	}
	return events, q.Ack(rc)
}

// Len returns the approximate number of events currently queued.
func (q *Queue) Len() (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	seqs, err := q.listSegments()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, seq := range seqs {
		n, _ := countLines(q.segPath(seq))
		total += int64(n)
	}
	return total, nil
}

// Close flushes and closes any open file handles.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.writeFile != nil {
		err := q.writeFile.Close()
		q.writeFile = nil
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (q *Queue) segPath(seq int64) string {
	return filepath.Join(q.dir, "segments", fmt.Sprintf("%010d.jsonl", seq))
}

func (q *Queue) listSegments() ([]int64, error) {
	entries, err := os.ReadDir(filepath.Join(q.dir, "segments"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("queue: readdir: %w", err)
	}
	var seqs []int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		seq, err := strconv.ParseInt(strings.TrimSuffix(e.Name(), ".jsonl"), 10, 64)
		if err != nil {
			continue
		}
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, nil
}

func (q *Queue) evictIfNeeded() {
	seqs, err := q.listSegments()
	if err != nil || len(seqs) <= maxSegments {
		return
	}
	for i := 0; i < len(seqs)-maxSegments; i++ {
		// L-08: never silently lose the high-severity events in an evicted
		// segment - salvage up to 500 of them into the active segment and
		// count what is genuinely dropped.
		salvaged, dropped := q.salvageHighSeverity(seqs[i])
		os.Remove(q.segPath(seqs[i]))
		q.logger.Warn("queue: evicted oldest segment (queue full)",
			"seq", seqs[i], "salvaged_high_sev", salvaged, "dropped", dropped)
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.CreateTemp(filepath.Dir(path), "seg-*.tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()
	return os.Rename(f.Name(), path)
}

// syncDir makes renames and removals in dir durable. Not supported on
// Windows, where the error is ignored.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n, sc.Err()
}

// salvageHighSeverity copies severity>=4 lines from an about-to-be-evicted
// segment onto the end of the active write segment. Returns (kept, lost).
func (q *Queue) salvageHighSeverity(seq int64) (int, int) {
	lines, err := readLines(q.segPath(seq))
	if err != nil {
		return 0, 0
	}
	kept := 0
	for _, l := range lines {
		var probe struct {
			Severity int `json:"severity"`
		}
		if json.Unmarshal([]byte(l), &probe) != nil || probe.Severity < 4 || kept >= 500 {
			continue
		}
		if q.writeFile == nil {
			f, err := os.OpenFile(q.segPath(q.writeSeq), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				break
			}
			q.writeFile = f
		}
		if _, err := fmt.Fprintf(q.writeFile, "%s\n", l); err != nil {
			break
		}
		q.writeCount++
		kept++
	}
	return kept, len(lines) - kept
}
