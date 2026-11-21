package otel

// batch.go - the wire format of POST /api/v1/app/batch. It mirrors
// backend/internal/store.AppBatch field for field; keep the two in step.

import (
	"encoding/json"
	"time"
)

type BatchInstance struct {
	Service      string          `json:"service"`
	Environment  string          `json:"environment"`
	Source       string          `json:"source"`
	InstanceRef  string          `json:"instance_ref"`
	Version      string          `json:"version"`
	PID          int             `json:"pid"`
	ProcStart    time.Time       `json:"proc_start"`
	ContainerID  string          `json:"container_id"`
	Identity     string          `json:"identity"`
	Instrumented bool            `json:"instrumented"`
	Listen       json.RawMessage `json:"listen,omitempty"`
	Language     string          `json:"language"`
	SDK          string          `json:"sdk"`
	Exe          string          `json:"exe"`
	Sensor       string          `json:"sensor,omitempty"` // host sensor tier that saw it: ebpf | procevent | poll
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
	AgentID   string          `json:"agent_id"`
	SentAt    time.Time       `json:"sent_at"`
	Instances []BatchInstance `json:"instances"`
	Routes    []BatchRoute    `json:"routes"`
	Edges     []BatchEdge     `json:"edges"`
	Traces    []BatchTrace    `json:"traces"`
	Clients   []BatchClient   `json:"clients"`
	Params    []BatchParam    `json:"params,omitempty"`
	Payloads  []BatchPayload  `json:"payloads,omitempty"`
	Notes     []BatchNote     `json:"notes"`
}

// Empty reports whether the batch carries nothing.
func (b *Batch) Empty() bool {
	return len(b.Instances)+len(b.Routes)+len(b.Edges)+len(b.Traces)+len(b.Clients)+len(b.Params)+len(b.Payloads)+len(b.Notes) == 0
}

// Limits the backend enforces per batch (keep in step with app_batch.go).
const (
	BatchMaxInstances = 200
	BatchMaxRoutes    = 2000
	BatchMaxEdges     = 500
	BatchMaxTraces    = 50
	BatchMaxClients   = 3000
	BatchMaxParams    = 5000
	BatchMaxPayloads  = 500
)

// Split cuts a batch into pieces that each respect the backend's per-batch caps.
// Notes ride with the first piece.
func (b *Batch) Split() []*Batch {
	var out []*Batch
	cur := func() *Batch {
		if len(out) == 0 {
			out = append(out, &Batch{AgentID: b.AgentID, SentAt: b.SentAt})
		}
		return out[len(out)-1]
	}
	fresh := func() { out = append(out, &Batch{AgentID: b.AgentID, SentAt: b.SentAt}) }
	for _, v := range b.Instances {
		if c := cur(); len(c.Instances) >= BatchMaxInstances {
			fresh()
		}
		cur().Instances = append(cur().Instances, v)
	}
	for _, v := range b.Routes {
		if c := cur(); len(c.Routes) >= BatchMaxRoutes {
			fresh()
		}
		cur().Routes = append(cur().Routes, v)
	}
	for _, v := range b.Edges {
		if c := cur(); len(c.Edges) >= BatchMaxEdges {
			fresh()
		}
		cur().Edges = append(cur().Edges, v)
	}
	for _, v := range b.Traces {
		if c := cur(); len(c.Traces) >= BatchMaxTraces {
			fresh()
		}
		cur().Traces = append(cur().Traces, v)
	}
	for _, v := range b.Clients {
		if c := cur(); len(c.Clients) >= BatchMaxClients {
			fresh()
		}
		cur().Clients = append(cur().Clients, v)
	}
	for _, v := range b.Params {
		if c := cur(); len(c.Params) >= BatchMaxParams {
			fresh()
		}
		cur().Params = append(cur().Params, v)
	}
	for _, v := range b.Payloads {
		if c := cur(); len(c.Payloads) >= BatchMaxPayloads {
			fresh()
		}
		cur().Payloads = append(cur().Payloads, v)
	}
	if len(b.Notes) > 0 {
		cur().Notes = append(cur().Notes, b.Notes...)
	}
	return out
}
