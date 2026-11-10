package api

// Windows fixtures, part 2 (persistence, defence evasion, lateral, impact).

func init() {
	sigFixtures = append(sigFixtures, []sigFixture{
		{"W-T1552.001", fxProc("findstr.exe", "findstr /si password *.txt"), fxProc("findstr.exe", "findstr /i error app.log")},
		{"W-T1552.005", fxProc("type.exe", `type c:\users\a\.aws\credentials`), fxProc("type.exe", `type c:\users\a\notes.txt`)},
		{"W-T1547.001", fxReg(`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\evil`), fxReg(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`)},
		{"W-T1053.005", fxProc("schtasks.exe", "schtasks /create /tn x /tr calc.exe"), fxProc("schtasks.exe", "schtasks /query")},
		{"W-T1543.003", fxProc("sc.exe", `sc create evil binpath= c:\x.exe`), fxProc("sc.exe", "sc query spooler")},
		{"W-T1546.003", fxProc("powershell.exe", "powershell Set-WmiInstance -Class __EventFilter"), fxProc("powershell.exe", "powershell Get-WmiObject Win32_BIOS")},
		{"W-T1546.012", fxReg(`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe\Debugger`), fxReg(`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`)},
		{"W-T1562.001a", fxProc("powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring $true"), fxProc("powershell.exe", "powershell Get-MpPreference")},
		{"W-T1562.001c", fxEventID(5001, "Microsoft-Windows-Windows Defender/Operational"), fxEventID(5001, "Security")},
		{"W-T1070.001", fxEventID(1102, "Security"), fxEventID(4624, "Security")},
		{"W-T1027", fxProc("powershell.exe", "powershell [convert]::FromBase64String('aGk=')"), fxProc("powershell.exe", "powershell Get-Date")},
		{"W-T1036", fxProcImg("svchost.exe", "svchost.exe", `C:\Users\a\AppData\Local\Temp\svchost.exe`), fxProcImg("svchost.exe", "svchost.exe -k netsvcs", `C:\Windows\System32\svchost.exe`)},
		{"W-T1562.001b", fxProc("powershell.exe", "powershell [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"), fxProc("powershell.exe", "powershell Get-Process")},
		{"W-T1574.002", fxFile(`C:\Users\a\AppData\Local\Temp\evil.dll`), fxFile(`C:\Windows\System32\good.dll`)},
		{"W-T1021.001", fxProc("mstsc.exe", "mstsc /v:10.0.0.5"), fxProc("notepad.exe", "notepad a.txt")},
		{"W-T1570", fxProc("psexec.exe", `psexec \\srv cmd`), fxProc("notepad.exe", "notepad a.txt")},
		{"W-T1490", fxProc("vssadmin.exe", "vssadmin delete shadows /all /quiet"), fxProc("vssadmin.exe", "vssadmin list shadows")},
		{"W-T1486", fxFile(`C:\Users\a\Documents\report.docx.locked`), fxFile(`C:\Users\a\Documents\report.docx`)},
	}...)
}
