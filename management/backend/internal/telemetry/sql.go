package telemetry

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"regexp"
	"strings"

	"github.com/lib/pq"
)

// DriverName is the database/sql driver that wraps lib/pq with spans. It only
// records statements made under a traced request or job, so background noise
// does not become traces of its own.
const DriverName = "postgres+telemetry"

func init() { sql.Register(DriverName, &tDriver{d: &pq.Driver{}}) }

var (
	reTable = regexp.MustCompile(`(?i)\b(?:from|into|update|join)\s+((?:"?\w+"?\.)?"?\w+"?)`)
)

// describe returns the operation and the first table of a statement.
func describe(q string) (op, table string) {
	f := strings.Fields(q)
	if len(f) > 0 {
		op = strings.ToUpper(f[0])
	}
	if m := reTable.FindStringSubmatch(q); m != nil {
		table = m[1]
		if i := strings.LastIndex(table, "."); i >= 0 {
			table = table[i+1:]
		}
		table = strings.Trim(table, `"`)
	}
	return op, table
}

func dbSpan(ctx context.Context, query string) *Span {
	if FromContext(ctx) == nil {
		return nil
	}
	op, table := describe(query)
	name := op
	if table != "" {
		name += " " + table
	}
	_, s := Start(ctx, name, KindClient)
	s.Set("db.system", "postgresql")
	if op != "" {
		s.Set("db.operation.name", op)
	}
	if table != "" {
		s.Set("db.collection.name", table)
	}
	// The statement text; the agent sends only a value-free fingerprint, and
	// only when the service's "statement fingerprints" setting is on.
	if len(query) > 2000 {
		query = query[:2000]
	}
	s.Set("db.query.text", query)
	return s
}

func endDB(s *Span, err error) {
	if s == nil {
		return
	}
	if err != nil && !errors.Is(err, driver.ErrSkip) && !errors.Is(err, sql.ErrNoRows) {
		s.SetError(err.Error())
	}
	s.End()
}

type tDriver struct{ d driver.Driver }

func (d *tDriver) Open(name string) (driver.Conn, error) {
	c, err := d.d.Open(name)
	if err != nil {
		return nil, err
	}
	return &tConn{c: c}, nil
}

type tConn struct{ c driver.Conn }

func (c *tConn) Prepare(q string) (driver.Stmt, error) {
	st, err := c.c.Prepare(q)
	if err != nil {
		return nil, err
	}
	return &tStmt{s: st, q: q}, nil
}

func (c *tConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	var st driver.Stmt
	var err error
	if p, ok := c.c.(driver.ConnPrepareContext); ok {
		st, err = p.PrepareContext(ctx, q)
	} else {
		st, err = c.c.Prepare(q)
	}
	if err != nil {
		return nil, err
	}
	return &tStmt{s: st, q: q}, nil
}

func (c *tConn) Close() error { return c.c.Close() }

//nolint:staticcheck // required by driver.Conn
func (c *tConn) Begin() (driver.Tx, error) { return c.c.Begin() }

func (c *tConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.c.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.c.Begin() //nolint:staticcheck
}

func (c *tConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	qc, ok := c.c.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	s := dbSpan(ctx, q)
	rows, err := qc.QueryContext(ctx, q, args)
	endDB(s, err)
	return rows, err
}

func (c *tConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	ec, ok := c.c.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	s := dbSpan(ctx, q)
	res, err := ec.ExecContext(ctx, q, args)
	endDB(s, err)
	return res, err
}

func (c *tConn) Ping(ctx context.Context) error {
	if p, ok := c.c.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c *tConn) ResetSession(ctx context.Context) error {
	if r, ok := c.c.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *tConn) IsValid() bool {
	if v, ok := c.c.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

func (c *tConn) CheckNamedValue(nv *driver.NamedValue) error {
	if n, ok := c.c.(driver.NamedValueChecker); ok {
		return n.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

type tStmt struct {
	s driver.Stmt
	q string
}

func (s *tStmt) Close() error  { return s.s.Close() }
func (s *tStmt) NumInput() int { return s.s.NumInput() }

//nolint:staticcheck // required by driver.Stmt
func (s *tStmt) Exec(args []driver.Value) (driver.Result, error) { return s.s.Exec(args) }

//nolint:staticcheck // required by driver.Stmt
func (s *tStmt) Query(args []driver.Value) (driver.Rows, error) { return s.s.Query(args) }

func (s *tStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	sp := dbSpan(ctx, s.q)
	var res driver.Result
	var err error
	if e, ok := s.s.(driver.StmtExecContext); ok {
		res, err = e.ExecContext(ctx, args)
	} else {
		res, err = s.s.Exec(namedToValues(args)) //nolint:staticcheck
	}
	endDB(sp, err)
	return res, err
}

func (s *tStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	sp := dbSpan(ctx, s.q)
	var rows driver.Rows
	var err error
	if q, ok := s.s.(driver.StmtQueryContext); ok {
		rows, err = q.QueryContext(ctx, args)
	} else {
		rows, err = s.s.Query(namedToValues(args)) //nolint:staticcheck
	}
	endDB(sp, err)
	return rows, err
}

func (s *tStmt) CheckNamedValue(nv *driver.NamedValue) error {
	if n, ok := s.s.(driver.NamedValueChecker); ok {
		return n.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

func namedToValues(nv []driver.NamedValue) []driver.Value {
	out := make([]driver.Value, len(nv))
	for i, v := range nv {
		out[i] = v.Value
	}
	return out
}
