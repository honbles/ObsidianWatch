package api

// Fixtures for the account, remote-session, USB, software, container, tamper
// and posture rules (event shapes that are not plain process/registry events).

import "obsidianwatch/management/internal/store"

func fxWinEvent(id uint32, raw string) store.Event {
	e := id
	return store.Event{EventType: "eventlog", EventID: &e, Raw: []byte(raw)}
}

func fxTyped(typ, raw string) store.Event {
	return store.Event{EventType: typ, Raw: []byte(raw)}
}

func fxProcName(name, cmd string) store.Event { return fxProc(name, cmd) }

func init() {
	pub := "203.0.113.50"
	priv := "10.0.0.8"
	rdp := fxWinEvent(4624, `{"event_data":{"LogonType":"10"}}`)
	rdp.SrcIP = &pub
	rdpPrivate := fxWinEvent(4624, `{"event_data":{"LogonType":"10"}}`)
	rdpPrivate.SrcIP = &priv

	sigFixtures = append(sigFixtures, []sigFixture{
		{"W-ACCT-001", fxWinEvent(4720, `{}`), fxWinEvent(4624, `{}`)},
		{"W-ACCT-002", fxWinEvent(4726, `{}`), fxWinEvent(4720, `{}`)},
		{"W-ACCT-003", fxWinEvent(4724, `{}`), fxWinEvent(4723, `{}`)},
		{"W-ACCT-004", fxWinEvent(4732, `{"event_data":{"TargetUserName":"Administrators"}}`), fxWinEvent(4732, `{"event_data":{"TargetUserName":"Domain Admins"}}`)},
		{"W-RDP-001", rdp, rdpPrivate},
		{"L-ACCT-001", fxProc("useradd", "useradd bob"), fxProc("ls", "ls /home")},
		{"L-ACCT-002", fxProc("usermod", "usermod -aG sudo bob"), fxProc("usermod", "usermod -s /bin/zsh bob")},
		{"L-USB-001", fxTyped("usb", `{"device":{"mass_storage":true}}`), fxTyped("usb", `{"device":{"mass_storage":false}}`)},
		{"W-USB-001", fxWinEvent(6416, `{"event_data":{"DeviceId":"USB\\VID_0781&PID_5581"}}`), fxWinEvent(6416, `{"event_data":{"DeviceId":"HID\\VID_046D"}}`)},
		{"L-SW-001", fxTyped("software", `{"action":"software_installed","package":"nmap"}`), fxTyped("software", `{"action":"software_installed","package":"vim"}`)},
		{"L-CTR-001", fxTyped("container", `{"container":{"risks":["privileged"]}}`), fxTyped("container", `{"container":{"risks":[]}}`)},
		{"AGENT-TAMPER-001", store.Event{EventType: "agent.tamper"}, store.Event{EventType: "agent.health"}},
		{"M-POSTURE-001", store.Event{EventType: "config.posture_regression"}, store.Event{EventType: "config.posture"}},
		{"W-T1562.001d", fxWinEvent(7036, `{"event_data":{"param1":"Windows Defender Antivirus Service","param2":"stopped"}}`), fxWinEvent(7036, `{"event_data":{"param1":"Windows Event Log","param2":"stopped"}}`)},
		{"W-T1562.002", fxWinEvent(4719, `{}`), fxWinEvent(4720, `{}`)},
		{"W-T1562.006", fxSysmonCfg(16, "Microsoft-Windows-Sysmon/Operational"), fxSysmonCfg(16, "Security")},
		{"W-T1543.003b", fxWinEvent(7045, `{"event_data":{"ImagePath":"C:\\Users\\Public\\x.exe"}}`), fxWinEvent(7045, `{"event_data":{"ImagePath":"C:\\Program Files\\App\\svc.exe"}}`)},
		{"W-T1546.003b", fxSysmonCfg(5861, "Microsoft-Windows-WMI-Activity/Operational"), fxSysmonCfg(5861, "Security")},
	}...)
}

func fxSysmonCfg(id uint32, channel string) store.Event {
	e, c := id, channel
	return store.Event{EventType: "eventlog", EventID: &e, Channel: &c, Raw: []byte(`{}`)}
}
