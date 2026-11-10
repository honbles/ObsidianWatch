//go:build windows

package collector

// eventlog.go - reads Windows Event Log channels via wevtapi.dll.
// Full XML parsing: EventID, time, computer, user, and all EventData
// key-value pairs are extracted into normalized schema.Event fields.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"obsidianwatch/agent/pkg/schema"
)

var (
	modWevtapi                   = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe             = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext                  = modWevtapi.NewProc("EvtNext")
	procEvtRender                = modWevtapi.NewProc("EvtRender")
	procEvtClose                 = modWevtapi.NewProc("EvtClose")
	procEvtFormatMessage         = modWevtapi.NewProc("EvtFormatMessage")
	procEvtOpenPublisherMetadata = modWevtapi.NewProc("EvtOpenPublisherMetadata")
	procEvtCreateBookmark        = modWevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark        = modWevtapi.NewProc("EvtUpdateBookmark")
)

const (
	evtSubscribeToFutureEvents = 1
	evtSubscribeStartAfterBkmk = 3
	evtRenderBookmark          = 2
	evtRenderEventXml          = 1
)

// XML structures for parsing Windows Event XML
type winEventXML struct {
	XMLName   xml.Name     `xml:"Event"`
	System    winSystemXML `xml:"System"`
	EventData winEventData `xml:"EventData"`
}

type winSystemXML struct {
	Provider    winProvider `xml:"Provider"`
	EventID     uint32      `xml:"EventID"`
	Level       uint8       `xml:"Level"`
	Task        uint16      `xml:"Task"`
	TimeCreated winTime     `xml:"TimeCreated"`
	RecordID    uint64      `xml:"EventRecordID"`
	Channel     string      `xml:"Channel"`
	Computer    string      `xml:"Computer"`
}

type winProvider struct {
	Name string `xml:"Name,attr"`
}

type winTime struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type winEventData struct {
	Data []winDataItem `xml:"Data"`
}

type winDataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type EventLogCollector struct {
	channels []string
	agentID  string
	host     string
	out      chan<- schema.Event
	logger   *slog.Logger
}

func NewEventLogCollector(channels []string, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *EventLogCollector {
	return &EventLogCollector{channels: channels, agentID: agentID, host: host, out: out, logger: logger}
}

// elSub is one channel subscription plus its persisted bookmark (W-09), so
// events written while the agent was stopped or restarting are not lost.
type elSub struct {
	channel  string
	handle   windows.Handle
	bookmark windows.Handle
	path     string
	dirty    int
}

func bookmarkDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "ObsidianWatch", "bookmarks")
}

func bookmarkFile(channel string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", " ", "_", ":", "_")
	return filepath.Join(bookmarkDir(), r.Replace(channel)+".xml")
}

func (c *EventLogCollector) Run(ctx context.Context) error {
	_ = os.MkdirAll(bookmarkDir(), 0o700)
	subs := make([]*elSub, 0, len(c.channels))
	for _, ch := range c.channels {
		sb, err := c.subscribe(ch)
		if err != nil {
			c.logger.Error("eventlog: subscribe failed", "channel", ch, "err", err)
			continue
		}
		subs = append(subs, sb)
		c.logger.Info("eventlog: subscribed", "channel", ch)
	}
	if len(subs) == 0 {
		return fmt.Errorf("eventlog: no channels could be subscribed")
	}
	defer func() {
		for _, sb := range subs {
			c.saveBookmark(sb)
			closeEvtHandle(sb.handle)
			if sb.bookmark != 0 {
				closeEvtHandle(sb.bookmark)
			}
		}
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, sb := range subs {
				c.drain(sb)
			}
		}
	}
}

func (c *EventLogCollector) loadBookmark(path string) windows.Handle {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return 0
	}
	xp, err := windows.UTF16PtrFromString(string(data))
	if err != nil {
		return 0
	}
	h, _, _ := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(xp)))
	return windows.Handle(h)
}

func (c *EventLogCollector) saveBookmark(sb *elSub) {
	if sb.bookmark == 0 || sb.dirty == 0 {
		return
	}
	var used, props uint32
	buf := make([]uint16, 2048)
	ret, _, _ := procEvtRender.Call(0, uintptr(sb.bookmark), evtRenderBookmark,
		uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if ret == 0 || used == 0 {
		return
	}
	xml := windows.UTF16ToString(buf)
	tmp := sb.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(xml), 0o600); err == nil {
		_ = os.Rename(tmp, sb.path)
		sb.dirty = 0
	}
}

func (c *EventLogCollector) subscribe(channel string) (*elSub, error) {
	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, err
	}
	queryPtr, err := windows.UTF16PtrFromString("*")
	if err != nil {
		return nil, err
	}
	signalEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}
	defer windows.CloseHandle(signalEvent)
	sb := &elSub{channel: channel, path: bookmarkFile(channel)}
	bk := c.loadBookmark(sb.path)
	flags := uintptr(evtSubscribeToFutureEvents)
	if bk != 0 {
		flags = evtSubscribeStartAfterBkmk
	}
	h, _, callErr := procEvtSubscribe.Call(
		0, uintptr(signalEvent),
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		uintptr(bk), 0, 0,
		flags,
	)
	if h == 0 && bk != 0 {
		// Stale bookmark (log cleared / rotated): fall back to future events.
		closeEvtHandle(bk)
		bk = 0
		h, _, callErr = procEvtSubscribe.Call(
			0, uintptr(signalEvent),
			uintptr(unsafe.Pointer(channelPtr)),
			uintptr(unsafe.Pointer(queryPtr)),
			0, 0, 0, evtSubscribeToFutureEvents,
		)
	}
	if h == 0 {
		return nil, fmt.Errorf("EvtSubscribe: %w", callErr)
	}
	if bk == 0 {
		nb, _, _ := procEvtCreateBookmark.Call(0)
		bk = windows.Handle(nb)
	}
	sb.handle = windows.Handle(h)
	sb.bookmark = windows.Handle(bk)
	return sb, nil
}

func (c *EventLogCollector) drain(sb *elSub) {
	const batchSize = 64
	events := make([]windows.Handle, batchSize)
	for {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			uintptr(sb.handle), uintptr(batchSize),
			uintptr(unsafe.Pointer(&events[0])),
			500, 0, uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			break
		}
		for i := uint32(0); i < returned; i++ {
			ev := c.parseEvent(events[i])
			if sb.bookmark != 0 {
				procEvtUpdateBookmark.Call(uintptr(sb.bookmark), uintptr(events[i]))
				sb.dirty++
			}
			closeEvtHandle(events[i])
			if ev != nil {
				select {
				case c.out <- *ev:
				default:
					c.logger.Warn("eventlog: out channel full, dropping event")
				}
			}
		}
	}
	c.saveBookmark(sb)
}

func (c *EventLogCollector) parseEvent(evHandle windows.Handle) *schema.Event {
	xmlBytes, err := renderXML(evHandle)
	if err != nil {
		c.logger.Warn("eventlog: render failed", "err", err)
		return nil
	}
	return c.parseEventXML(xmlBytes)
}

// parseEventXML converts rendered event XML into a normalised event. It is
// split out from parseEvent so it can be tested without the Windows API.
func (c *EventLogCollector) parseEventXML(xmlBytes []byte) *schema.Event {
	var parsed winEventXML
	if err := xml.Unmarshal(xmlBytes, &parsed); err != nil {
		raw, _ := json.Marshal(map[string]string{"raw_xml": string(xmlBytes)})
		return &schema.Event{
			Time: time.Now().UTC(), AgentID: c.agentID, Host: c.host, OS: "windows",
			EventType: schema.EventTypeRaw, Severity: schema.SeverityInfo,
			Source: "EventLog", Raw: raw,
		}
	}

	sys := parsed.System
	ev := &schema.Event{
		AgentID:   c.agentID,
		Host:      c.host,
		OS:        "windows",
		EventID:   sys.EventID,
		Channel:   sys.Channel,
		RecordID:  sys.RecordID,
		Source:    sys.Channel,
		Severity:  windowsLevelToSeverity(sys.Level),
		EventType: schema.EventTypeRaw,
	}

	if t, err := time.Parse(time.RFC3339Nano, sys.TimeCreated.SystemTime); err == nil {
		ev.Time = t.UTC()
	} else {
		ev.Time = time.Now().UTC()
	}

	// Build flat data map from EventData
	dataMap := make(map[string]string, len(parsed.EventData.Data))
	for _, d := range parsed.EventData.Data {
		if d.Name != "" {
			dataMap[d.Name] = strings.TrimSpace(d.Value)
		}
	}

	rawPayload := map[string]interface{}{
		"event_id": sys.EventID, "channel": sys.Channel,
		"provider": sys.Provider.Name, "record_id": sys.RecordID,
		"level": sys.Level, "event_data": dataMap,
	}
	ev.Raw, _ = json.Marshal(rawPayload)

	extractCommonFields(ev, dataMap)
	classifyAndEnrichEvent(ev, dataMap)
	// If EventType was cleared (e.g. noisy logon type), drop the event
	if ev.EventType == "" {
		return nil
	}
	return ev
}

func extractCommonFields(ev *schema.Event, data map[string]string) {
	if v := firstOf(data, "SubjectUserName", "TargetUserName", "UserName", "User"); v != "" {
		ev.UserName = v
	}
	if v := firstOf(data, "SubjectDomainName", "TargetDomainName", "Domain"); v != "" {
		ev.Domain = v
	}
	if v := firstOf(data, "SubjectLogonId", "TargetLogonId", "LogonId"); v != "" {
		ev.LogonID = v
	}
	if v := firstOf(data, "NewProcessName", "ProcessName", "Application"); v != "" {
		ev.ProcessName = v
		ev.ImagePath = v
	}
	if v := firstOf(data, "NewProcessId", "ProcessId", "ProcessID"); v != "" {
		if pid, err := parseHexOrDec(v); err == nil {
			ev.PID = pid
		}
	}
	if v := firstOf(data, "ParentProcessId", "ParentProcessID"); v != "" {
		if ppid, err := parseHexOrDec(v); err == nil {
			ev.PPID = ppid
		}
	}
	if v := data["CommandLine"]; v != "" {
		ev.CommandLine = v
	}
}

func classifyAndEnrichEvent(ev *schema.Event, data map[string]string) {
	switch ev.EventID {
	case 4624:
		lt := data["LogonType"]
		// Skip noisy background logons: 3=Network, 4=Batch, 5=Service, 0=System
		// Keep: 2=Interactive, 7=Unlock, 10=RemoteInteractive(RDP), 11=CachedInteractive
		if lt == "3" || lt == "4" || lt == "5" || lt == "0" {
			// Skip — mark as skippable by clearing EventType so parseEvent drops it
			ev.EventType = ""
			return
		}
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityInfo
		if lt != "" {
			ev.Severity = logonTypeSeverity(lt)
		}
	case 4625:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityMedium
		if data["LogonType"] == "3" {
			ev.Severity = schema.SeverityHigh
		}
	case 4648:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityMedium
		if v := data["TargetServerName"]; v != "" {
			ev.DstIP = v
		}
	case 4672:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityMedium
	case 4634, 4647:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityInfo
	case 4776:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityLow
		if v := data["Workstation"]; v != "" {
			ev.SrcIP = v
		}
	case 4688:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityLow
	case 4689:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityInfo
	case 5156:
		ev.EventType = schema.EventTypeNetwork
		ev.Severity = schema.SeverityLow
		ev.SrcIP = data["SourceAddress"]
		ev.DstIP = data["DestAddress"]
		if p, err := strconv.Atoi(data["SourcePort"]); err == nil {
			ev.SrcPort = p
		}
		if p, err := strconv.Atoi(data["DestPort"]); err == nil {
			ev.DstPort = p
		}
		ev.Proto = protocolNumber(data["Protocol"])
	case 5157:
		ev.EventType = schema.EventTypeNetwork
		ev.Severity = schema.SeverityMedium
		ev.SrcIP = data["SourceAddress"]
		ev.DstIP = data["DestAddress"]
		if p, err := strconv.Atoi(data["SourcePort"]); err == nil {
			ev.SrcPort = p
		}
		if p, err := strconv.Atoi(data["DestPort"]); err == nil {
			ev.DstPort = p
		}
		ev.Proto = protocolNumber(data["Protocol"])
	case 4657:
		ev.EventType = schema.EventTypeRegistry
		ev.Severity = schema.SeverityMedium
		ev.RegKey = data["ObjectName"]
		ev.RegValue = data["ObjectValueName"]
		ev.RegData = data["NewValue"]
	case 4663:
		ev.EventType = schema.EventTypeFile
		ev.Severity = schema.SeverityLow
		ev.FilePath = data["ObjectName"]
	case 4660:
		ev.EventType = schema.EventTypeFile
		ev.Severity = schema.SeverityMedium
		ev.FilePath = data["ObjectName"]
	case 4698, 4702:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityHigh
	case 4720:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityHigh
	case 4728, 4732, 4756:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityHigh
	case 7045:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityHigh
		if v := data["ServiceName"]; v != "" {
			ev.ProcessName = v
		}
		if v := data["ImagePath"]; v != "" {
			ev.ImagePath = v
		}

	// -- Domain Controller Events -----------------------------------------------
	// 4662 — Object operation in AD (DCSync uses LDAP replication on DS-Replication objects)
	case 4662:
		ev.EventType = "ad_object_access"
		ev.Severity = schema.SeverityMedium
		if v := data["ObjectType"]; v != "" {
			ev.CommandLine = v // reuse CommandLine for object type
		}
		if v := data["ObjectName"]; v != "" {
			ev.FilePath = v
		}
	// 4768 — Kerberos TGT request
	case 4768:
		ev.EventType = "kerberos"
		ev.Severity = schema.SeverityLow
		if v := data["TargetUserName"]; v != "" {
			ev.UserName = v
		}
		if v := data["IpAddress"]; v != "" {
			ev.SrcIP = v
		}
	// 4769 — Kerberos service ticket request
	case 4769:
		ev.EventType = "kerberos"
		ev.Severity = schema.SeverityLow
		if v := data["TargetUserName"]; v != "" {
			ev.UserName = v
		}
		if v := data["IpAddress"]; v != "" {
			ev.SrcIP = v
		}
		if v := data["ServiceName"]; v != "" {
			ev.ProcessName = v
		}
	// 4770 — Kerberos service ticket renewed
	case 4770:
		ev.EventType = "kerberos"
		ev.Severity = schema.SeverityInfo
	// 4771 — Kerberos pre-auth failed (bad password at DC)
	case 4771:
		ev.EventType = "kerberos"
		ev.Severity = schema.SeverityMedium
		if v := data["TargetUserName"]; v != "" {
			ev.UserName = v
		}
		if v := data["IpAddress"]; v != "" {
			ev.SrcIP = v
		}
	// 5136 — AD directory object modified
	case 5136:
		ev.EventType = "ad_change"
		ev.Severity = schema.SeverityHigh
		if v := data["ObjectDN"]; v != "" {
			ev.FilePath = v
		}
		if v := data["AttributeLDAPDisplayName"]; v != "" {
			ev.RegKey = v
		}
		if v := data["AttributeValue"]; v != "" {
			ev.RegValue = v
		}
	// 5137 — AD directory object created
	case 5137:
		ev.EventType = "ad_change"
		ev.Severity = schema.SeverityHigh
		if v := data["ObjectDN"]; v != "" {
			ev.FilePath = v
		}
	// 5141 — AD directory object deleted
	case 5141:
		ev.EventType = "ad_change"
		ev.Severity = schema.SeverityHigh
		if v := data["ObjectDN"]; v != "" {
			ev.FilePath = v
		}
	// 4742 — Computer account changed
	case 4742:
		ev.EventType = "ad_change"
		ev.Severity = schema.SeverityMedium
	// 4741 — Computer account created
	case 4741:
		ev.EventType = "ad_change"
		ev.Severity = schema.SeverityHigh
	// 4743 — Computer account deleted
	case 4743:
		ev.EventType = "ad_change"
		ev.Severity = schema.SeverityHigh
	// 4739 — Domain policy changed
	case 4739:
		ev.EventType = "ad_change"
		ev.Severity = schema.SeverityCritical

	// -- Sysmon Events ----------------------------------------------------------
	// EventID 1 - Process Create
	case 1:
		ev.EventType = schema.EventTypeProcess
		ev.Source = "Sysmon"
		if v := data["Image"]; v != "" {
			ev.ImagePath = v
			idx := strings.LastIndex(v, "\\")
			if idx >= 0 {
				ev.ProcessName = v[idx+1:]
			} else {
				ev.ProcessName = v
			}
		}
		if v := data["CommandLine"]; v != "" {
			ev.CommandLine = v
		}
		if v := data["ProcessId"]; v != "" {
			if pid, err := parseHexOrDec(v); err == nil { ev.PID = pid }
		}
		if v := data["ParentProcessId"]; v != "" {
			if ppid, err := parseHexOrDec(v); err == nil { ev.PPID = ppid }
		}
		if v := data["ParentImage"]; v != "" {
			// parent image path available in v if needed
		}
		if v := firstOf(data, "User", "SubjectUserName"); v != "" {
			ev.UserName = v
		}
		ev.Severity = schema.SeverityLow
		// Elevate suspicious process names / command lines
		cmdLower := strings.ToLower(ev.CommandLine + ev.ProcessName)
		if containsAnyStr(cmdLower, "mimikatz", "meterpreter", "cobalt", "shellcode",
			"invoke-expression", "downloadstring", "-enc", "bypass", "webclient") {
			ev.Severity = schema.SeverityCritical
		} else if containsAnyStr(cmdLower, "powershell", "wscript", "cscript", "mshta",
			"regsvr32", "rundll32", "certutil", "bitsadmin", "wmic", "psexec") {
			ev.Severity = schema.SeverityMedium
		}

	// EventID 2 - File creation time changed
	case 2:
		ev.EventType = schema.EventTypeFile
		ev.Source = "Sysmon"
		ev.FilePath = data["TargetFilename"]
		ev.Severity = schema.SeverityMedium

	// EventID 3 - Network connection
	case 3:
		ev.EventType = schema.EventTypeNetwork
		ev.Source = "Sysmon"
		ev.SrcIP = data["SourceIp"]
		ev.DstIP = data["DestinationIp"]
		if p, err := strconv.Atoi(data["SourcePort"]); err == nil { ev.SrcPort = p }
		if p, err := strconv.Atoi(data["DestinationPort"]); err == nil { ev.DstPort = p }
		ev.Proto = strings.ToLower(data["Protocol"])
		if v := data["Image"]; v != "" {
			idx := strings.LastIndex(v, "\\")
			if idx >= 0 {
				ev.ProcessName = v[idx+1:]
			} else {
				ev.ProcessName = v
			}
		}
		ev.Severity = schema.SeverityLow

	// EventID 5 - Process terminated
	case 5:
		ev.EventType = schema.EventTypeProcess
		ev.Source = "Sysmon"
		if v := data["Image"]; v != "" {
			idx := strings.LastIndex(v, "\\")
			if idx >= 0 {
				ev.ProcessName = v[idx+1:]
			} else {
				ev.ProcessName = v
			}
		}
		ev.Severity = schema.SeverityInfo

	// EventID 6 - Driver loaded
	case 6:
		ev.EventType = schema.EventTypeProcess
		ev.Source = "Sysmon"
		ev.ImagePath = data["ImageLoaded"]
		ev.Severity = schema.SeverityMedium

	// EventID 7 - Image (DLL) loaded
	case 7:
		ev.EventType = schema.EventTypeProcess
		ev.Source = "Sysmon"
		if v := data["Image"]; v != "" {
			idx := strings.LastIndex(v, "\\")
			if idx >= 0 {
				ev.ProcessName = v[idx+1:]
			} else {
				ev.ProcessName = v
			}
		}
		ev.ImagePath = data["ImageLoaded"]
		ev.Severity = schema.SeverityInfo

	// EventID 8 - CreateRemoteThread (injection)
	case 8:
		ev.EventType = schema.EventTypeProcess
		ev.Source = "Sysmon"
		ev.Severity = schema.SeverityCritical
		if v := data["SourceImage"]; v != "" {
			idx := strings.LastIndex(v, "\\")
			if idx >= 0 {
				ev.ProcessName = v[idx+1:]
			} else {
				ev.ProcessName = v
			}
		}

	// EventID 10 - Process access (injection attempt)
	case 10:
		ev.EventType = schema.EventTypeProcess
		ev.Source = "Sysmon"
		ev.Severity = schema.SeverityHigh
		if v := data["SourceImage"]; v != "" {
			idx := strings.LastIndex(v, "\\")
			if idx >= 0 {
				ev.ProcessName = v[idx+1:]
			} else {
				ev.ProcessName = v
			}
		}

	// EventID 11 - File created
	case 11:
		ev.EventType = schema.EventTypeFile
		ev.Source = "Sysmon"
		ev.FilePath = data["TargetFilename"]
		if v := data["Image"]; v != "" {
			idx := strings.LastIndex(v, "\\")
			if idx >= 0 {
				ev.ProcessName = v[idx+1:]
			} else {
				ev.ProcessName = v
			}
		}
		ev.Severity = schema.SeverityLow

	// EventID 12 - Registry object create/delete
	case 12:
		ev.EventType = schema.EventTypeRegistry
		ev.Source = "Sysmon"
		ev.RegKey = data["TargetObject"]
		ev.Severity = schema.SeverityLow

	// EventID 13 - Registry value set
	case 13:
		ev.EventType = schema.EventTypeRegistry
		ev.Source = "Sysmon"
		ev.RegKey = data["TargetObject"]
		ev.RegData = data["Details"]
		ev.Severity = schema.SeverityLow
		// Persistence via run keys
		keyLower := strings.ToLower(ev.RegKey)
		if containsAnyStr(keyLower, `\run\`, `\runonce\`, `\services\`, "userinit", "shell") {
			ev.Severity = schema.SeverityHigh
		}

	// EventID 14 - Registry key/value renamed
	case 14:
		ev.EventType = schema.EventTypeRegistry
		ev.Source = "Sysmon"
		ev.RegKey = data["TargetObject"]
		ev.Severity = schema.SeverityMedium

	// EventID 15 - File stream created (ADS)
	case 15:
		ev.EventType = schema.EventTypeFile
		ev.Source = "Sysmon"
		ev.FilePath = data["TargetFilename"]
		ev.Severity = schema.SeverityHigh

	// EventID 17/18 - Named pipe
	case 17, 18:
		ev.EventType = schema.EventTypeNetwork
		ev.Source = "Sysmon"
		ev.Severity = schema.SeverityLow

	// EventID 22 - DNS query
	case 22:
		ev.EventType = schema.EventTypeDNS
		ev.Source = "Sysmon"
		ev.DstIP = data["QueryName"]
		if v := data["Image"]; v != "" {
			idx := strings.LastIndex(v, "\\")
			if idx >= 0 {
				ev.ProcessName = v[idx+1:]
			} else {
				ev.ProcessName = v
			}
		}
		ev.Severity = schema.SeverityInfo

	// EventID 23 - File deleted
	case 23:
		ev.EventType = schema.EventTypeFile
		ev.Source = "Sysmon"
		ev.FilePath = data["TargetFilename"]
		ev.Severity = schema.SeverityMedium

	// EventID 25 - Process tampering
	case 25:
		ev.EventType = schema.EventTypeProcess
		ev.Source = "Sysmon"
		ev.Severity = schema.SeverityCritical

		// PowerShell - Module logging (4103) and Script Block logging (4104)
	case 4103:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityLow
		ev.ProcessName = "powershell"
		// Payload contains the actual command/script that ran
		if v := firstOf(data, "Payload", "ScriptBlockText", "MessageNumber"); v != "" {
			ev.CommandLine = v
		}
		if v := firstOf(data, "HostApplication", "Path"); v != "" {
			ev.ImagePath = v
		}
		// Mark as suspicious if contains common attack patterns
		cmdLower := strings.ToLower(ev.CommandLine)
		if containsAnyStr(cmdLower, "-enc", "downloadstring", "iex", "invoke-expression",
			"webclient", "bypass", "hidden", "frombase64", "reflection.assembly") {
			ev.Severity = schema.SeverityHigh
		}
	case 4104:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityLow
		ev.ProcessName = "powershell"
		// 4104 = Script Block Logging - captures the ACTUAL script text
		if v := firstOf(data, "ScriptBlockText", "Payload"); v != "" {
			ev.CommandLine = v
		}
		if v := data["Path"]; v != "" {
			ev.ImagePath = v
		}
		cmdLower := strings.ToLower(ev.CommandLine)
		if containsAnyStr(cmdLower, "-enc", "downloadstring", "iex", "invoke-expression",
			"webclient", "bypass", "hidden", "frombase64", "reflection.assembly",
			"mimikatz", "invoke-mimikatz", "shellcode") {
			ev.Severity = schema.SeverityHigh
		}
	// Windows Defender detections
	case 1116, 1117:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityCritical
		if v := firstOf(data, "Threat Name", "ThreatName"); v != "" {
			ev.ProcessName = v
		}
		if v := firstOf(data, "Path", "Process Name"); v != "" {
			ev.FilePath = v
		}
	// W-08: Defender posture changes — real-time protection / scanning
	// disabled (5001, 5010, 5012) and configuration changes (5007), which
	// include exclusion additions (Exclusions\Paths / Extensions / Processes).
	case 5001, 5010, 5012:
		ev.Severity = schema.SeverityHigh
	case 5007:
		ev.Severity = schema.SeverityMedium
		for _, v := range data {
			if containsAnyStr(strings.ToLower(v), `\exclusions\`) {
				ev.Severity = schema.SeverityHigh
				break
			}
		}
	// AppLocker blocked execution
	case 8004, 8007:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityHigh
		if v := firstOf(data, "FilePath", "FullFilePath"); v != "" {
			ev.FilePath = v
			ev.ImagePath = v
		}
		if v := data["User"]; v != "" {
			ev.UserName = v
		}
	}
}

func containsAnyStr(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func renderXML(evHandle windows.Handle) ([]byte, error) {
	var bufSize uint32 = 4096
	buf := make([]uint16, bufSize)
	var used, propCount uint32
	ret, _, err := procEvtRender.Call(
		0, uintptr(evHandle), evtRenderEventXml,
		uintptr(bufSize*2), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propCount)),
	)
	if ret == 0 {
		if err == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]uint16, used/2+1)
			ret, _, err = procEvtRender.Call(
				0, uintptr(evHandle), evtRenderEventXml,
				uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
				uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propCount)),
			)
			if ret == 0 {
				return nil, fmt.Errorf("EvtRender retry: %w", err)
			}
		} else {
			return nil, fmt.Errorf("EvtRender: %w", err)
		}
	}
	return []byte(windows.UTF16ToString(buf)), nil
}

func closeEvtHandle(h windows.Handle) { procEvtClose.Call(uintptr(h)) }

func windowsLevelToSeverity(level uint8) schema.Severity {
	switch level {
	case 1:
		return schema.SeverityCritical
	case 2:
		return schema.SeverityHigh
	case 3:
		return schema.SeverityMedium
	default:
		return schema.SeverityInfo
	}
}

func logonTypeSeverity(logonType string) schema.Severity {
	switch logonType {
	case "10":
		return schema.SeverityMedium // RemoteInteractive (RDP)
	case "3":
		return schema.SeverityLow // Network
	default:
		return schema.SeverityInfo
	}
}

func protocolNumber(p string) string {
	switch p {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	default:
		return p
	}
}

func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" && v != "-" {
			return v
		}
	}
	return ""
}

func parseHexOrDec(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 64)
		return int(v), err
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return int(v), err
}
