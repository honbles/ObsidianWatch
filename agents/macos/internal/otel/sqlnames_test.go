package otel

import "testing"

func TestSQLNames(t *testing.T) {
	cases := map[string][2]string{
		"SELECT id, name FROM orders WHERE id = 5":                     {"SELECT", "orders"},
		"select * from public.\"Users\" u join roles r on r.id=u.role": {"SELECT", "users"},
		"INSERT INTO audit_log (a, b) VALUES ('x', 2)":                 {"INSERT", "audit_log"},
		"update alerts set n = n + 1 where id = $1":                    {"UPDATE", "alerts"},
		"DELETE FROM `shop`.`cart` WHERE user_id = ?":                  {"DELETE", "cart"},
		"/* app */ SELECT 1":                                           {"SELECT", ""},
		"WITH recent AS (SELECT * FROM events) SELECT * FROM recent":   {"SELECT", "events"},
		"BEGIN":       {"BEGIN", ""},
		"hello world": {"", ""},
		"":            {"", ""},
	}
	for in, want := range cases {
		op, tb := sqlNames(in)
		if op != want[0] || tb != want[1] {
			t.Errorf("%q: got %q %q, want %q %q", in, op, tb, want[0], want[1])
		}
	}
	// the instrumentation's own attributes win; the span name is the last resort
	if op, tb := dbOpTable(&Span{DBOp: "find", DBTable: "carts", DBStmt: "SELECT * FROM orders"}); op != "FIND" || tb != "carts" {
		t.Errorf("attributes: %s %s", op, tb)
	}
	if op, tb := dbOpTable(&Span{Name: "sql.conn.query", DBStmt: "SELECT * FROM orders WHERE id = ?"}); op != "SELECT" || tb != "orders" {
		t.Errorf("otelsql span: %s %s", op, tb)
	}
	if op, tb := dbOpTable(&Span{DBOp: "select app", DBStmt: `select email from "user" where email = %(e)s`}); op != "SELECT" || tb != "user" {
		t.Fatalf("SQLAlchemy operation: %q %q", op, tb)
	}
	if op, tb := sqlNames("CREATE TABLE IF NOT EXISTS users (id BIGSERIAL)"); op != "CREATE" || tb != "users" {
		t.Fatalf("create if not exists: %q %q", op, tb)
	}
	if op, tb := sqlNames("DROP TABLE IF EXISTS public.audit"); op != "DROP" || tb != "audit" {
		t.Fatalf("drop if exists: %q %q", op, tb)
	}
	if !driverLifecycleSpan(&Span{Name: "sql.rows", DBSystem: "postgresql"}) || driverLifecycleSpan(&Span{Name: "sql.conn.query", DBStmt: "SELECT 1"}) {
		t.Fatal("driverLifecycleSpan")
	}
	if op, _ := dbOpTable(&Span{Name: "redis GET"}); op != "REDIS" {
		t.Errorf("span name fallback: %s", op)
	}
}

func TestDBSystemName(t *testing.T) {
	var s Span
	s.set("db.system.name", attrValue{s: "postgresql"})
	if s.DBSystem != "postgresql" {
		t.Errorf("db.system.name not read: %q", s.DBSystem)
	}
}
