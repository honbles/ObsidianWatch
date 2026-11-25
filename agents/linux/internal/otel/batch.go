package otel

// batch.go - the wire format of POST /api/v1/app/batch. It mirrors
// backend/internal/store.AppBatch field for field; keep the two in step.

import (
	"encoding/json"
	"time"
)

type BatchInstance struct {
	Service       string          `json:"service"`
	Environment   string          `json:"environment"`
	Source        string          `json:"source"`
	InstanceRef   string          `json:"instance_ref"`
	Version       string          `json:"version"`
	PID           int             `json:"pid"`
	ProcStart     time.Time       `json:"proc_start"`
	ContainerID   string          `json:"container_id"`
	Identity      string          `json:"identity"`
	Instrumented  bool            `json:"instrumented"`
	Listen        json.RawMessage `json:"listen,omitempty"`
	Language      string          `json:"language"`
	SDK           string          `json:"sdk"`
	Exe           string          `json:"exe"`
	Sensor        string          `json:"sensor,omitempty"`         // host sensor tier that saw it: ebpf | procevent | poll
	Unit          string          `json:"unit,omitempty"`           // systemd service the process runs under
	ContainerName string          `json:"container_name,omitempty"` // docker container name
	Image         string          `json:"image,omitempty"`          // docker image
}

type BatchRoute struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Route       string    `json:"route"`
	Method      string    `json:"method"`
	Minute      time.Time `json:"minute"`
	Calls       int64     `json:"calls"`
	Errors      int64     `json:"errors"`
	Status2xx   int64     `json:"status_2xx"`
	Status40103 int64     `json:"status_401_403"`
	Status429   int64     `json:"status_429"`
	Status5xx   int64     `json:"status_5xx"`
	DurBuckets  []int64   `json:"duration_buckets"`
	// Sketch is the mergeable latency sketch (schema_version 2). An older agent omits it; the backend then uses the histogram.
	Sketch *SketchWire `json:"sketch,omitempty"`
}

// BatchParam counts one parameter NAME seen on a route since the last flush. Values are never sent.
type BatchParam struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Route       string `json:"route"`
	Method      string `json:"method"`
	Name        string `json:"name"`
	Count       int64  `json:"count"`
}

// BatchPayload is one sampled request's allowed parameters from a route whose parameters were reviewed.
// Only parameters the admin left unmasked appear in Params; every other name is listed in Withheld.
type BatchPayload struct {
	Service     string            `json:"service"`
	Environment string            `json:"environment"`
	Route       string            `json:"route"`
	Method      string            `json:"method"`
	Time        time.Time         `json:"time"`
	Status      int               `json:"status"`
	DurationMs  float64           `json:"duration_ms,omitempty"`
	TraceID     string            `json:"trace_id,omitempty"`
	Params      map[string]string `json:"params"`
	Withheld    []string          `json:"withheld,omitempty"`
}

type BatchEdge struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	DstKind     string `json:"dst_kind"`
	DstName     string `json:"dst_name"`
	Source      string `json:"source"`
	Calls       int64  `json:"calls"`
	Errors      int64  `json:"errors"`
}

type BatchTrace struct {
	TraceID     string          `json:"trace_id"`
	Service     string          `json:"service"`
	Environment string          `json:"environment"`
	Started     time.Time       `json:"started"`
	DurationMs  int             `json:"duration_ms"`
	RootRoute   string          `json:"root_route"`
	Status      string          `json:"status"`
	KeepReason  string          `json:"keep_reason"`
	SpanCount   int             `json:"span_count"`
	Spans       json.RawMessage `json:"spans"`
}

// BatchClient is a per-minute failure counter for one (route, client address) pair (rules A01, A09, A13).
type BatchClient struct {
	Service        string    `json:"service"`
	Environment    string    `json:"environment"`
	Route          string    `json:"route"`
	Method         string    `json:"method"`
	Minute         time.Time `json:"minute"`
	ClientIP       string    `json:"client_ip"`
	PeerIP         string    `json:"peer_ip"`
	ExcType        string    `json:"exc_type"`
	Failures       int64     `json:"failures"`
	Status40103    int64     `json:"status_401_403"`
	Status429      int64     `json:"status_429"`
	Status4xxOther int64     `json:"status_4xx_other"`
	Status5xx      int64     `json:"status_5xx"`
}

type BatchNote struct {
	Service        string `json:"service"`
	Environment    string `json:"environment"`
	RouteOverflow  int64  `json:"route_overflow"`
	TraceDrops     int64  `json:"trace_drops"`
	ClientOverflow int64  `json:"client_overflow"`
}

// Batch is one POST body.
type Batch struct {
	AgentID    string           `json:"agent_id"`
	SentAt     time.Time        `json:"sent_at"`
	Instances  []BatchInstance  `json:"instances"`
	Routes     []BatchRoute     `json:"routes"`
	Edges      []BatchEdge      `json:"edges"`
	Traces     []BatchTrace     `json:"traces"`
	Clients    []BatchClient    `json:"clients"`
	Params     []BatchParam     `json:"params,omitempty"`
	Payloads   []BatchPayload   `json:"payloads,omitempty"`
	Children   []BatchChild     `json:"children,omitempty"`
	Queries    []BatchQuery     `json:"queries,omitempty"`
	NPlusOne   []BatchNPlusOne  `json:"n_plus_one,omitempty"`
	Errors     []BatchError     `json:"errors,omitempty"`
	Metrics    []BatchMetric    `json:"metrics,omitempty"`
	Sampling   []BatchSampling  `json:"sampling,omitempty"`
	Operations []BatchOperation `json:"operations,omitempty"`
	// SchemaVersion is 2 from the release that adds children, queries and n_plus_one. An older agent omits it.
	SchemaVersion int         `json:"schema_version,omitempty"`
	Notes         []BatchNote `json:"notes"`
}

// Empty reports whether the batch carries nothing.
func (b *Batch) Empty() bool {
	return len(b.Instances)+len(b.Routes)+len(b.Edges)+len(b.Traces)+len(b.Clients)+len(b.Params)+len(b.Payloads)+len(b.Children)+len(b.Queries)+len(b.NPlusOne)+len(b.Errors)+len(b.Metrics)+len(b.Sampling)+len(b.Operations)+len(b.Notes) == 0
}

func (b *Batch) items() int {
	return len(b.Instances) + len(b.Routes) + len(b.Edges) + len(b.Traces) + len(b.Clients) + len(b.Params) + len(b.Payloads) + len(b.Children) + len(b.Queries) + len(b.NPlusOne) + len(b.Errors) + len(b.Metrics) + len(b.Sampling) + len(b.Operations)
}

// Limits the backend enforces per batch (keep in step with app_batch.go).
const (
	BatchMaxInstances  = 200
	BatchMaxRoutes     = 2000
	BatchMaxEdges      = 500
	BatchMaxTraces     = 50
	BatchMaxClients    = 3000
	BatchMaxParams     = 5000
	BatchMaxPayloads   = 500
	BatchMaxChildren   = 5000
	BatchMaxQueries    = 3000
	BatchMaxNPlusOne   = 500
	BatchMaxErrors     = 1500
	BatchMaxMetrics    = 4000
	BatchMaxSampling   = 200
	BatchMaxOperations = 1500
)

// splitInto appends items to the pieces, opening a new piece whenever the
// current one holds max items of this kind.
func splitInto[T any](b *Batch, out *[]*Batch, items []T, max int, field func(*Batch) *[]T) {
	for _, v := range items {
		if len(*out) == 0 || len(*field((*out)[len(*out)-1])) >= max {
			*out = append(*out, &Batch{AgentID: b.AgentID, SentAt: b.SentAt, SchemaVersion: b.SchemaVersion})
		}
		f := field((*out)[len(*out)-1])
		*f = append(*f, v)
	}
}

// Split cuts a batch into pieces that each respect the backend's per-batch
// caps. Every section is carried; notes ride with the first piece.
func (b *Batch) Split() []*Batch {
	var out []*Batch
	splitInto(b, &out, b.Instances, BatchMaxInstances, func(x *Batch) *[]BatchInstance { return &x.Instances })
	splitInto(b, &out, b.Routes, BatchMaxRoutes, func(x *Batch) *[]BatchRoute { return &x.Routes })
	splitInto(b, &out, b.Edges, BatchMaxEdges, func(x *Batch) *[]BatchEdge { return &x.Edges })
	splitInto(b, &out, b.Traces, BatchMaxTraces, func(x *Batch) *[]BatchTrace { return &x.Traces })
	splitInto(b, &out, b.Clients, BatchMaxClients, func(x *Batch) *[]BatchClient { return &x.Clients })
	splitInto(b, &out, b.Params, BatchMaxParams, func(x *Batch) *[]BatchParam { return &x.Params })
	splitInto(b, &out, b.Payloads, BatchMaxPayloads, func(x *Batch) *[]BatchPayload { return &x.Payloads })
	splitInto(b, &out, b.Children, BatchMaxChildren, func(x *Batch) *[]BatchChild { return &x.Children })
	splitInto(b, &out, b.Queries, BatchMaxQueries, func(x *Batch) *[]BatchQuery { return &x.Queries })
	splitInto(b, &out, b.NPlusOne, BatchMaxNPlusOne, func(x *Batch) *[]BatchNPlusOne { return &x.NPlusOne })
	splitInto(b, &out, b.Errors, BatchMaxErrors, func(x *Batch) *[]BatchError { return &x.Errors })
	splitInto(b, &out, b.Metrics, BatchMaxMetrics, func(x *Batch) *[]BatchMetric { return &x.Metrics })
	splitInto(b, &out, b.Sampling, BatchMaxSampling, func(x *Batch) *[]BatchSampling { return &x.Sampling })
	splitInto(b, &out, b.Operations, BatchMaxOperations, func(x *Batch) *[]BatchOperation { return &x.Operations })
	if len(b.Notes) > 0 {
		if len(out) == 0 {
			out = append(out, &Batch{AgentID: b.AgentID, SentAt: b.SentAt, SchemaVersion: b.SchemaVersion})
		}
		out[0].Notes = append(out[0].Notes, b.Notes...)
	}
	// Count caps alone do not bound the size: halve any piece the backend's
	// 4 MiB body cap would refuse.
	var sized []*Batch
	for _, piece := range out {
		sized = append(sized, fitBytes(piece, BatchMaxBytes)...)
	}
	return sized
}

// BatchMaxBytes keeps a piece comfortably under the backend's 4 MiB body cap.
const BatchMaxBytes = 3 << 20

func half[T any](a []T) ([]T, []T) { return a[:len(a)/2], a[len(a)/2:] }

// fitBytes splits b in two, section by section, until each piece encodes
// under max bytes or cannot be split further.
func fitBytes(b *Batch, max int) []*Batch {
	raw, err := json.Marshal(b)
	if err != nil || len(raw) <= max {
		return []*Batch{b}
	}
	x := &Batch{AgentID: b.AgentID, SentAt: b.SentAt, SchemaVersion: b.SchemaVersion, Notes: b.Notes}
	y := &Batch{AgentID: b.AgentID, SentAt: b.SentAt, SchemaVersion: b.SchemaVersion}
	x.Instances, y.Instances = half(b.Instances)
	x.Routes, y.Routes = half(b.Routes)
	x.Edges, y.Edges = half(b.Edges)
	x.Traces, y.Traces = half(b.Traces)
	x.Clients, y.Clients = half(b.Clients)
	x.Params, y.Params = half(b.Params)
	x.Payloads, y.Payloads = half(b.Payloads)
	x.Children, y.Children = half(b.Children)
	x.Queries, y.Queries = half(b.Queries)
	x.NPlusOne, y.NPlusOne = half(b.NPlusOne)
	x.Errors, y.Errors = half(b.Errors)
	x.Metrics, y.Metrics = half(b.Metrics)
	x.Sampling, y.Sampling = half(b.Sampling)
	x.Operations, y.Operations = half(b.Operations)
	if x.items() == 0 || y.items() == 0 { // one item too large to split: send it and let the backend decide
		return []*Batch{b}
	}
	return append(fitBytes(x, max), fitBytes(y, max)...)
}
