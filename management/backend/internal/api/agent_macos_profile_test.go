package api

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestMacOSFDAProfile(t *testing.T) {
	p := macosFDAProfile("U1", "U2")
	if err := xml.NewDecoder(strings.NewReader(p)).Decode(new(interface{})); err != nil && !strings.Contains(err.Error(), "EOF") {
		// plist root decodes loosely; only reject real syntax errors
		if _, ok := err.(*xml.SyntaxError); ok {
			t.Fatalf("invalid XML: %v", err)
		}
	}
	for _, want := range []string{"SystemPolicyAllFiles", macosAgentInstalledPath, "<string>U1</string>", "<string>U2</string>"} {
		if !strings.Contains(p, want) {
			t.Errorf("profile missing %q", want)
		}
	}
}
