package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestSplitGCPProjectList(t *testing.T) {
	got := splitGCPProjectList("a, b;c a *")
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("got %v", got)
	}
}

func TestNormalizeGCPParent(t *testing.T) {
	if normalizeGCPParent("organizations", "12") != "organizations/12" ||
		normalizeGCPParent("folders", "folders/9") != "folders/9" ||
		normalizeGCPParent("folders", "") != "" {
		t.Fatal("bad normalize")
	}
}

func TestDiscoverGCPProjectsWalksFolders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parent := r.URL.Query().Get("parent")
		switch {
		case r.URL.Path == "/projects" && parent == "organizations/1":
			w.Write([]byte(`{"projects":[{"projectId":"p-org","state":"ACTIVE"},{"projectId":"p-dead","state":"DELETE_REQUESTED"}]}`))
		case r.URL.Path == "/projects" && parent == "folders/2":
			w.Write([]byte(`{"projects":[{"projectId":"p-f2"}]}`))
		case r.URL.Path == "/folders" && parent == "organizations/1":
			w.Write([]byte(`{"folders":[{"name":"folders/2","state":"ACTIVE"}]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	old := gcpCRMBase
	gcpCRMBase = srv.URL
	defer func() { gcpCRMBase = old }()
	ids, err := discoverGCPProjects(context.Background(), "tok", "organizations/1")
	if err != nil || !reflect.DeepEqual(ids, []string{"p-org", "p-f2"}) {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}

func TestResolveGCPProjectsExplicit(t *testing.T) {
	ids, err := resolveGCPProjects(context.Background(), gcpServiceAccount{ProjectID: "sa"}, "x,y", "", "")
	if err != nil || len(ids) != 2 {
		t.Fatalf("%v %v", ids, err)
	}
	ids, _ = resolveGCPProjects(context.Background(), gcpServiceAccount{ProjectID: "sa"}, "", "", "")
	if len(ids) != 1 || ids[0] != "sa" {
		t.Fatalf("%v", ids)
	}
	if _, err := resolveGCPProjects(context.Background(), gcpServiceAccount{}, "*", "", ""); err == nil {
		t.Fatal("expected error for * without parent")
	}
}
