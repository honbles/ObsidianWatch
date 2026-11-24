//go:build darwin

package response

import (
	"reflect"
	"testing"
)

func TestNetworksetupParsing(t *testing.T) {
	list := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB 10/100 LAN\n"
	if got := networkServices(list); !reflect.DeepEqual(got, []string{"Wi-Fi", "USB 10/100 LAN"}) {
		t.Fatal(got)
	}
	if dnsServers("There aren't any DNS Servers set on Wi-Fi.\n") != nil {
		t.Fatal("unset must parse as nil")
	}
	if got := dnsServers("8.8.8.8\n2001:4860:4860::8888\n"); len(got) != 2 {
		t.Fatal(got)
	}
}
