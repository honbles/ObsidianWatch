//go:build linux

package collector

import (
	"reflect"
	"testing"
)

func TestJournalArgs(t *testing.T) {
	if got := journalArgs(""); !reflect.DeepEqual(got, []string{"--output=json", "--follow", "--no-pager", "--since=now"}) {
		t.Fatalf("fresh start: %v", got)
	}
	got := journalArgs("s=abc;i=1")
	if got[len(got)-1] != "--after-cursor=s=abc;i=1" {
		t.Fatalf("resume: %v", got)
	}
	for _, a := range got {
		if a == "--since=now" {
			t.Fatal("must not combine --since with --after-cursor")
		}
	}
}
