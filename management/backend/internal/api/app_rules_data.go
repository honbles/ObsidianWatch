package api

// app_rules_data.go - the data the rules read. A narrow interface so every evaluator is
// testable with fixtures; appPGData implements it over the shared PostgreSQL database.

import (
	"context"
	"time"
)

// appInst is one service instance (a process) as the rules see it.
type appInst struct {
	ID          int64
	ServiceID   int64
	AgentID     string
	Host        string
	PID         int
	ProcStart   time.Time
	ContainerID string
	Identity    string
	Version     string
	Ref         string
	FirstSeen   time.Time
	LastSeen    time.Time
	Stopped     bool
	Name        string // executable base name when known
}

// appClientRow is one app_client_stats row.
type appClientRow struct {
	Minute         time.Time
	Route, Method  string
	ClientIP       string
	PeerIP         string
	ExcType        string
	Failures       int64
	Status40103    int64
	Status429      int64
	Status4xxOther int64
	Status5xx      int64
}

type appRouteRef struct {
	Route, Method string
	FirstSeen     time.Time
}

// appWindowStats are request counters over a time window.
type appWindowStats struct {
	Route, Method string
	Calls, Errors int64
}

type appData interface {
	// Host events.
	ServiceForLineage(ctx context.Context, agentID, containerID string, pids []int) (svc appSvc, inst appInst, idx int, ok bool)
	Baseline(ctx context.Context, svcID int64, kind, key string) (bool, error)
	RecordBaseline(ctx context.Context, svcID int64, kind, key string, now time.Time) error
	BaselineSamples(ctx context.Context, svcID int64, kind string) (int64, error)
	InDeployWindow(ctx context.Context, svc appSvc, agentID string, now time.Time, window time.Duration) bool
	IPIntel(ctx context.Context, ip string) (source string, hit bool)
	AppAnomaly(ctx context.Context, svc appSvc, since time.Time, spike5xx int64) (desc string, ok bool)

	// Periodic scans.
	ActiveServices(ctx context.Context, since time.Time) ([]appSvc, error)
	ClientRows(ctx context.Context, svcID int64, since time.Time) ([]appClientRow, error)
	NewRoutes(ctx context.Context, svcID int64, since time.Time) ([]appRouteRef, error)
	Requests(ctx context.Context, svc appSvc) (int64, error)
	RouteWindow(ctx context.Context, svcID int64, from, to time.Time) ([]appWindowStats, error)
	Instances(ctx context.Context, svcID int64) ([]appInst, error)
	AgentSeen(ctx context.Context, agentID string) (time.Time, error)
	ProcessAlive(ctx context.Context, agentID string, pid int, since time.Time) (bool, error)
	LastRequestMinute(ctx context.Context, svcID int64) (time.Time, error)
}
