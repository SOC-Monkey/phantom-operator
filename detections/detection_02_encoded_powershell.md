# Detection 02 - Encoded PowerShell Command Execution

### Purpose
Detects use of **PowerShell with Base64 encoded commands** (`-EncodedCommand`). This is a common evasion technique used by attackers to hide malicous payloads

---

### Data Source
| Source | Details |
|--------|---------|
| Sysmon |EventCode 1 - Process Creation |
| Splunk sourcetype | `WinEventLog:Microsoft-Windows-Sysmon/Operational` |

---

### Test Evidence ( Lab Execution )

**Command Used (benign payload):**
```powershell
$cmd = 'Write-Output "Detection Test 02" | Out-File C:\Temp\d02_test.txt -Encoding ASCII'
- $bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
- $enc = [Convert]::ToBase64String($bytes)
- Start-Process powershell.exe -ArgumentList "-NoLogo -NoProfile-ExecutionPolicy Bypass -EncodedCommand $enc"
```
Sysmon - Confirmed event for powershell.exe -EncodedCommand
Splunk - Event found and parsed

### Detection Logic (SPL)

**Production Detection Rule**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
Image="*\\powershell.exe" CommandLine="*-EncodedCommand
|table _time host User Image CommandLine ParentImage ProcessGuid```

**Hunting Variant**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
Image="*\\powershell.exe" CommandLine="*-EncodedCommand
| search CommandLine="*-enc* OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*"
|table _time host User Image CommandLine ParentImage ProcessGuid
| sort -_time```

### Detection Notes
- This event is rare in normal environments so detection of this is a good signal of suspicous activity
- PowerShell logging does not capture the full command by default - Sysmon is required
- Detection works even if bypass is used or ExecutionPolicy is modified
- Defender doesn't block this test


### Possible False Positives

- Admin scripts
- Automation tools
- PenTesting tools

### Possible Mitigations

- Decode the Base64 command to verify intent
- Check for the parent process
- Investigate possible persistence
- Check for lateral movement indicators

### Status

✅ Validated in Splunk
✅ Test evidence captured
✅ Ready for final report


