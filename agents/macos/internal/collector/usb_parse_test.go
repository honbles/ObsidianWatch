package collector

import "testing"

func TestParseSPUSB(t *testing.T) {
	js := `{"SPUSBDataType":[{"_name":"USB31Bus","_items":[
	 {"_name":"USB3.0 Hub","vendor_id":"0x05e3","product_id":"0x0610","location_id":"0x14100000","_items":[
	   {"_name":"SanDisk Ultra","vendor_id":"0x0781","product_id":"0x5581","serial_num":"ABC123","manufacturer":"SanDisk","location_id":"0x14110000","Media":[{"_name":"disk2"}]},
	   {"_name":"Keyboard","vendor_id":"0x046d","product_id":"0xc31c","location_id":"0x14120000"}]}]}]}`
	m := parseSPUSB([]byte(js))
	if len(m) != 2 {
		t.Fatalf("want 2 devices (hub skipped), got %d: %+v", len(m), m)
	}
	var ms int
	for _, d := range m {
		if d.MassStorage {
			ms++
			if d.Serial != "ABC123" {
				t.Errorf("serial: %+v", d)
			}
		}
	}
	if ms != 1 {
		t.Fatalf("mass storage count %d", ms)
	}
	if len(parseSPUSB([]byte("garbage"))) != 0 {
		t.Fatal("garbage should yield none")
	}
}
