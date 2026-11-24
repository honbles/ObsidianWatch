//go:build windows

package response

import (
	"strings"
	"testing"
)

func TestDNSScripts(t *testing.T) {
	s := pointDNSScript("12=8.8.8.8,1.1.1.1;7=")
	if !strings.Contains(s, "$known=@(12,7)") || !strings.Contains(s, "-ServerAddresses '127.0.0.1'") {
		t.Fatal(s)
	}
	u := unpointDNSScript("12=8.8.8.8 1.1.1.1;7=")
	if !strings.Contains(u, "-InterfaceIndex 12 -ServerAddresses @('8.8.8.8','1.1.1.1')") || !strings.Contains(u, "-InterfaceIndex 7 -ResetServerAddresses") {
		t.Fatal(u)
	}
	if savedDNSRe.MatchString("12=8.8.8.8'; Remove-Item C:\\") {
		t.Fatal("injection accepted")
	}
}
