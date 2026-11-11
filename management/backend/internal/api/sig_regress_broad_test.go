package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestTmpExecutionRulesNeedExecution(t *testing.T) {
	for _, id := range []string{"L-T1059.004b", "M-T1059.004b"} {
		sig, _ := fxFind(id)
		for _, c := range []string{"ls /tmp/", "rm -rf /tmp/build", "cat /tmp/app.log", "tar czf /tmp/x.tgz /home/a", "grep err /var/tmp/x"} {
			if sig.Match(fxProc("x", c)) {
				t.Errorf("%s must not fire on %q", id, c)
			}
		}
		for _, c := range []string{"/tmp/payload", "/var/tmp/.x -d", "bash /tmp/x.sh", "python3 -u /tmp/a.py", "sh -c /tmp/run"} {
			if !sig.Match(fxProc("x", c)) {
				t.Errorf("%s should fire on %q", id, c)
			}
		}
		if !sig.Match(fxProcImg("x", "x", "/tmp/implant")) {
			t.Errorf("%s should fire on an image under /tmp", id)
		}
	}
}

func TestLdPreloadRule(t *testing.T) {
	sig, _ := fxFind("L-T1574.006")
	if sig.Match(store.Event{EventType: "applog", Raw: []byte(`{"line":"env: LD_PRELOAD unset"}`)}) {
		t.Error("log text mentioning LD_PRELOAD must not fire")
	}
	if sig.Match(fxProc("sh", "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2 redis-server")) {
		t.Error("jemalloc preload is benign")
	}
	if !sig.Match(fxProc("sh", "LD_PRELOAD=/tmp/evil.so ls")) {
		t.Error("preloading an arbitrary library should fire")
	}
	if !sig.Match(fxFile("/etc/ld.so.preload")) {
		t.Error("changes to /etc/ld.so.preload should fire")
	}
}

func TestCloudCredentialAccessRule(t *testing.T) {
	sig, _ := fxFind("W-T1552.005")
	if sig.Match(fxProc("terraform", "terraform plan -state=terraform.tfstate")) || sig.Match(fxProc("aws", `aws s3 ls --profile x`)) {
		t.Error("ordinary cloud tooling must not fire")
	}
	if sig.Match(store.Event{EventType: "registry", Raw: []byte(`{"v":"c:\\users\\a\\.aws\\credentials"}`)}) {
		t.Error("raw text on a non-process, non-file event must not fire")
	}
	if !sig.Match(fxProc("type.exe", `type c:\users\a\.aws\credentials`)) || !sig.Match(fxFile(`C:\Users\a\.aws\credentials`)) {
		t.Error("reading or touching the credentials file should fire")
	}
	if sig.Match(fxProc("aws.exe", `aws configure`)) {
		t.Error("aws CLI itself must not fire")
	}
}
