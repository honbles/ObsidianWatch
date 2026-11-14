package store

import (
	"database/sql"
	"os"
	"reflect"
	"sort"
	"testing"

	_ "github.com/lib/pq"
)

// Runs compiled queries against a real Postgres. Set OW_TEST_PG to a DSN of a
// database holding the minimal events table (see the seed in the test body's
// comment); skipped otherwise.
//
//	events(id, time, host, os, event_type, severity, source, raw jsonb, pid, ppid, process_name,
//	       command_line, image_path, user_name, domain, logon_id, src_ip, src_port, dst_ip, dst_port,
//	       proto, reg_key, reg_value, file_path, file_hash, event_id, channel, process_guid)
//	rows: 1 web01/process/sev4/bash/blessing  2 web02/network/sev2/chrome/blessing/1.2.3.4:443
//	      3 db01/process/sev5/powershell.exe/SYSTEM (raw has "blessing")  4 ws1/dns/sev1/svchost/203.0.113.7:53
func TestQueryAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG")
	if dsn == "" {
		t.Skip("OW_TEST_PG not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cases := []struct {
		q    string
		want []string
	}{
		{`severity>=high and blessing`, []string{"1", "3"}}, // the bug: chip + text must combine
		{`blessing`, []string{"1", "2", "3"}},
		{`blessing and not user:SYSTEM`, []string{"1", "2"}},
		{`host:web*`, []string{"1", "2"}},
		{`host:web* and severity>=4`, []string{"1"}},
		{`type:(process or dns)`, []string{"1", "3", "4"}},
		{`port!=443 and type:network`, nil},
		{`port!=443`, []string{"1", "3", "4"}}, // events with no port are "not 443" too
		{`dst:203.0.113.7`, []string{"4"}},
		{`ip:1.2.`, []string{"2"}},
		{`user=system`, []string{"3"}},
		{`user!=SYSTEM and type:process`, []string{"1"}},
		{`cmd:"-enc"`, []string{"3"}},
		{`(proc:bash or proc:chrome) and severity<4`, []string{"2"}},
		{`not (type:process or type:dns)`, []string{"2"}},
		{`sev:critical`, []string{"3"}},
		{`severity=critical or severity=low`, []string{"2", "3"}},
		{`time>=2000-01-01`, []string{"1", "2", "3", "4"}},
		{`time>=2999-01-01`, nil},
		{`-chrome blessing`, []string{"1", "3"}},
	}
	for _, c := range cases {
		e, err := ParseEventQuery(c.q)
		if err != nil {
			t.Errorf("%q: %v", c.q, err)
			continue
		}
		clause, args, err := e.SQL(1)
		if err != nil {
			t.Errorf("%q: %v", c.q, err)
			continue
		}
		rows, err := db.Query(`SELECT id FROM events WHERE `+clause+` ORDER BY id`, args...)
		if err != nil {
			t.Errorf("%q: sql error: %v\n%s", c.q, err, clause)
			continue
		}
		var got []string
		for rows.Next() {
			var id string
			rows.Scan(&id)
			got = append(got, id)
		}
		rows.Close()
		sort.Strings(got)
		if !reflect.DeepEqual(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("%q: got %v want %v", c.q, got, c.want)
		}
	}
}
