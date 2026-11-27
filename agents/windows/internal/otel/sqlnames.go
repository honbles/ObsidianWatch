package otel

import (
	"regexp"
	"strings"
)

// sqlNames reads the operation and the main table from a SQL statement, for spans whose instrumentation
// reports the statement but not db.operation.name / db.collection.name (Go otelsql, some Node and Python
// drivers). Only the keyword and the identifier are taken, never a value, so this works whatever the
// service's statement setting is; the statement text itself still leaves the host only as a fingerprint.
var (
	sqlOpRe    = regexp.MustCompile(`(?is)^\s*(?:/\*.*?\*/\s*|--[^\n]*\n\s*)*(?:with\s+.+?\)\s*)?([a-z]+)`)
	sqlTableRe = regexp.MustCompile(`(?is)\b(?:from|into|update|join|table)\s+(?:if\s+(?:not\s+)?exists\s+|only\s+)?((?:[a-z_][a-z0-9_$]*|"[^"]+"|` + "`[^`]+`" + `)(?:\.(?:[a-z_][a-z0-9_$]*|"[^"]+"|` + "`[^`]+`" + `))?)`)
)

var sqlOps = map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "UPSERT": true, "MERGE": true,
	"REPLACE": true, "CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true, "CALL": true, "EXEC": true, "EXECUTE": true,
	"BEGIN": true, "COMMIT": true, "ROLLBACK": true, "SET": true, "SHOW": true, "COPY": true, "VALUES": true, "WITH": true}

func sqlNames(stmt string) (op, table string) {
	if stmt == "" {
		return "", ""
	}
	if m := sqlOpRe.FindStringSubmatch(stmt); m != nil {
		if w := strings.ToUpper(m[1]); sqlOps[w] {
			op = w
		}
	}
	if op == "" {
		return "", ""
	}
	if m := sqlTableRe.FindStringSubmatch(stmt); m != nil {
		t := strings.NewReplacer(`"`, "", "`", "").Replace(m[1])
		if i := strings.LastIndexByte(t, '.'); i >= 0 { // schema.table -> table
			t = t[i+1:]
		}
		table = strings.ToLower(t)
	}
	return op, table
}

// dbOpTable is a span's operation and table: the instrumentation's own attributes first, then the statement,
// then (operation only) the span name.
func dbOpTable(s *Span) (op, table string) {
	op, table = strings.ToUpper(s.DBOp), s.DBTable
	if f := strings.Fields(op); len(f) > 1 {
		// Some instrumentations put the span name in db.operation: SQLAlchemy's is "SELECT <database>".
		// The first word is the operation; the rest is never a table, so the statement supplies that.
		op = f[0]
	}
	if op == "" || table == "" {
		so, st := sqlNames(s.DBStmt)
		if op == "" {
			op = so
		}
		if table == "" {
			table = st
		}
	}
	if op == "" {
		op = strings.ToUpper(firstWord(s.Name))
	}
	return op, table
}

// driverLifecycleSpan reports a database span that is not a query: Go otelsql's sql.connector.connect,
// sql.conn.reset_session, sql.rows, sql.conn.prepare without a statement and the like. They carry the database
// system but no statement or operation, so counting them would add a meaningless "SQL" row to the Queries tab.
func driverLifecycleSpan(s *Span) bool {
	return s.DBStmt == "" && s.DBOp == "" && strings.HasPrefix(s.Name, "sql.")
}
