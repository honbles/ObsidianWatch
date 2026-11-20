package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitFromCgroup(t *testing.T) {
	for cg, want := range map[string]string{
		"0::/system.slice/postgresql@16-main.service":                                       "postgresql",
		"0::/system.slice/mosquitto.service":                                                "mosquitto",
		"0::/system.slice/fluent-bit.service\n":                                             "fluent-bit",
		"0::/system.slice/docker.service":                                                   "",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/app.service":            "",
		"0::/user.slice/user-1000.slice/session-3.scope":                                    "",
		"0::/system.slice/docker-" + strings.Repeat("a", 64) + ".scope":                     "",
		"12:memory:/system.slice/tor@default.service\n0::/system.slice/tor@default.service": "tor",
	} {
		if got := UnitFromCgroup(cg); got != want {
			t.Errorf("%q: got %q want %q", cg, got, want)
		}
	}
}

func TestContainerLookupAndNaming(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("b", 64)
	dir := filepath.Join(root, "containers", id)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "config.v2.json"), []byte(`{"Name":"/shop-db-1","Config":{"Image":"postgres:16","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"db"}}}`), 0o644)
	c := newContainerCache(root)
	ci, ok := c.Lookup(id)
	if !ok || ci.Name != "shop-db-1" || ci.Image != "postgres:16" || ci.Service != "db" || ci.Project != "shop" {
		t.Fatalf("%+v %v", ci, ok)
	}
	if _, ok := c.Lookup(strings.Repeat("c", 64)); ok {
		t.Fatal("an unknown container must not resolve")
	}
	if _, ok := c.Lookup("short"); ok {
		t.Fatal("a malformed id must not resolve")
	}
	for _, tc := range []struct {
		derived, unit string
		ci            ContainerInfo
		have          bool
		want          string
	}{
		{"postgres", "", ci, true, "db"},
		{"postgres", "", ContainerInfo{Name: "juice"}, true, "juice"},
		{"build", "otelopscol", ContainerInfo{}, false, "otelopscol"},
		{"redis-check-rdb", "redis-server", ContainerInfo{}, false, "redis-server"},
		{"orders", "", ContainerInfo{}, false, "orders"},
	} {
		if got := BetterName(tc.derived, tc.unit, tc.ci, tc.have); got != tc.want {
			t.Errorf("%+v: got %q want %q", tc, got, tc.want)
		}
	}
}
