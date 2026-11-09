package collector

import (
	"encoding/json"
	"strings"
)

// usbDevice is one attached USB device as reported by system_profiler.
type usbDevice struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	VendorID     string `json:"vendor_id,omitempty"`
	ProductID    string `json:"product_id,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Serial       string `json:"serial,omitempty"`
	MassStorage  bool   `json:"mass_storage"`
}

type spUSBItem struct {
	Name         string                     `json:"_name"`
	VendorID     string                     `json:"vendor_id"`
	ProductID    string                     `json:"product_id"`
	Manufacturer string                     `json:"manufacturer"`
	Serial       string                     `json:"serial_num"`
	LocationID   string                     `json:"location_id"`
	Media        []json.RawMessage          `json:"Media"`
	Items        []spUSBItem                `json:"_items"`
	Extra        map[string]json.RawMessage `json:"-"`
}

// parseSPUSB flattens `system_profiler SPUSBDataType -json` into a keyed map.
// Hubs (items that only contain other devices and have no product id) are skipped.
func parseSPUSB(b []byte) map[string]usbDevice {
	out := map[string]usbDevice{}
	var doc struct {
		Data []spUSBItem `json:"SPUSBDataType"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return out
	}
	var walk func(items []spUSBItem)
	walk = func(items []spUSBItem) {
		for _, it := range items {
			if it.ProductID != "" || it.VendorID != "" {
				d := usbDevice{
					Name: it.Name, VendorID: it.VendorID, ProductID: it.ProductID,
					Manufacturer: it.Manufacturer, Serial: it.Serial, MassStorage: len(it.Media) > 0,
				}
				d.Key = it.LocationID + "|" + it.VendorID + ":" + it.ProductID + "|" + it.Serial
				if !strings.Contains(strings.ToLower(it.Name), "hub") || d.MassStorage {
					out[d.Key] = d
				}
			}
			walk(it.Items)
		}
	}
	walk(doc.Data)
	return out
}
