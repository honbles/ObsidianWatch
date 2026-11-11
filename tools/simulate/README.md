# Alert self-test scripts

`ow-simulate-windows.ps1`, `ow-simulate-linux.sh` and `ow-simulate-macos.sh` check that detection
rules fire end to end on a real endpoint: agent -> ingest -> detection -> alert.

Each script runs harmless look-alikes of attacker behaviour, then logs in to the management server
and prints PASS or FAIL per rule. It does not run malware, exploit anything or download anything:

- Most tests only run `echo` (cmd.exe on Windows, /bin/echo elsewhere) with the suspicious command
  text as arguments, so the process command line matches the rule.
- Some tests run a copy of a harmless system binary renamed like the tool (for example `wscript.exe`),
  from a temporary folder that is removed afterwards, so the process name matches the rule.
- One Windows test sets and removes a temporary `HKCU\...\Run` value that points at nothing.

Run it on a test machine: it creates real alerts, which may be emailed or sent to webhooks.
Security software may also flag the command text itself. Every test carries a marker
`OWSIM-<nonce>` so the alerts are easy to find and close afterwards.

```powershell
.\ow-simulate-windows.ps1 -ApiUrl https://obsidianwatch.example.com -Username admin -SkipCertCheck
.\ow-simulate-windows.ps1 -List          # show what runs and what cannot be simulated
.\ow-simulate-windows.ps1 -Only W-T1003.001,W-T1547.001 -ApiUrl ...
```

```sh
./ow-simulate-linux.sh --api https://obsidianwatch.example.com --user admin --insecure
./ow-simulate-linux.sh --list
```

Rules that need a real log, file, DNS or logon event (audit policy changes, FIM paths, account
creation, USB and so on) cannot be triggered safely from a script; `--list` shows them.

The scripts are generated from the signature fixtures so they cannot drift from the rules:

```sh
cd management/backend
OW_UPDATE_SIM=1 go test ./internal/api -run TestSimScriptsUpToDate
```

A test in the normal suite fails if the checked-in scripts are stale. The PowerShell script has not
been run on a live Windows machine yet (it was written and syntax-checked here); the shell script was
exercised against a mock server.
