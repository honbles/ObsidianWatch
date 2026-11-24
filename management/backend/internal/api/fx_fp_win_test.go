package api

import (
	"fmt"

	"obsidianwatch/management/internal/store"
)

// fxProcParent builds a process event whose Sysmon ParentImage is parent
// (backslashes must already be escaped for JSON).
func fxProcParent(name, cmd, parent string) store.Event {
	e := fxProc(name, cmd)
	e.Raw = []byte(`{"event_data":{"ParentImage":"` + parent + `"}}`)
	return e
}

func fxKerbRaw(id uint32, user, raw string) store.Event {
	u := user
	e := store.Event{EventType: "kerberos", EventID: fxU32p(id), UserName: &u}
	e.Raw = []byte(raw)
	return e
}

func fxKerbRC4(svc, user string) store.Event {
	e := fxKerb(4769, svc, 1)
	u, ip := user, "10.0.0.7"
	e.UserName, e.SrcIP = &u, &ip
	e.Raw = []byte(`{"event_data":{"TicketEncryptionType":"0x17"}}`)
	return e
}

// fxRoastBurst primes four distinct SPN requests and returns the fifth.
func fxRoastBurst() store.Event {
	for i := 1; i <= 4; i++ {
		dcKerberoastBurst(fxKerbRC4(fmt.Sprintf("burst-svc-%d", i), "mallory"))
	}
	return fxKerbRC4("burst-svc-5", "mallory")
}

// fxRansomBurst primes 19 renames and returns the 20th.
func fxRansomBurst() store.Event {
	for i := 1; i <= 19; i++ {
		winRansomRenames(fxFile(fmt.Sprintf(`C:\Users\a\Documents\f%d.docx.locked`, i)))
	}
	return fxFile(`C:\Users\a\Documents\f20.docx.locked`)
}

