package api

import "testing"

func TestLocalEdgeResolve(t *testing.T) {
	for in, want := range map[string]int{"localhost:11434": 11434, "127.0.0.1:5432": 5432, "[::1]:80": 80} {
		if p, ok := appLocalPort(in); !ok || p != want {
			t.Errorf("%s: %d %v", in, p, ok)
		}
	}
	for _, in := range []string{"example.com:443", "10.0.0.5:80", "localhost", "localhost:0", "localhost:99999"} {
		if _, ok := appLocalPort(in); ok {
			t.Errorf("%s must not be a local endpoint", in)
		}
	}
	if got := appListenPorts([]byte(`[3000,"0.0.0.0:11434","[::]:80"]`)); len(got) != 3 || got[1] != 11434 || got[2] != 80 {
		t.Fatalf("%v", got)
	}
	ix := &appLocalIndex{byPort: map[int][]appLocalTarget{11434: {{ServiceID: 2, Name: "ollama", Agent: "a1"}, {ServiceID: 3, Name: "other", Agent: "a2"}}},
		agentOf: map[int64]map[string]bool{1: {"a1": true}}}
	if c, ok := ix.Resolve(1, "localhost:11434"); !ok || c.Name != "ollama" {
		t.Fatalf("%+v %v", c, ok)
	}
	if _, ok := ix.Resolve(1, "localhost:9"); ok {
		t.Fatal("no listener")
	}
	if _, ok := ix.Resolve(2, "localhost:11434"); ok {
		t.Fatal("a service is not linked to itself, nor to another host's listener")
	}
}
