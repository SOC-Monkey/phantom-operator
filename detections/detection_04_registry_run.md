# Detection 04 — Registry Run Key Persistence

### Purpose
Detect the creation or modification Windows registry keys for the use of persistence. This is a common technique used by threat actors to maintain presence in a system.

---

### ATT&CK Mappings
T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys and Startup Folder

---

### Data Sources

| Source | Details |
|--------|---------|
| Sysmon | Event ID 13 - Registry value set |
| Windows: Security | Process creation |

---

### Test case 

In elevated powershell, create two registry values (HKCU and HKLM) 

1. Create test values (HKCU and HKLM)

HKCU:

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Phantom_Run_HKCU" /t REG_SZ /d "C:\Temp\phantom_hkcu.exe" /f
```

HKLM:

```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Phantom_Run_HKLM" /t REG_SZ /d "C:\Temp\phantom_hklm.exe" /f
```

2. Verify local Sysmon capture (PowerShell)

```powershell

# show last 50 Sysmon events with Registry set (EventID 13)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} -MaxEvents 50 |
```

Or parse only entries matching Run keys:
```powershell

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} -MaxEvents 100 |
  Where-Object { $_.ToXml() -match 'CurrentVersion\\Run' } |

```

3. Verify events are ingested into Splunk using the Production Rule

4. Cleanup (remove test values)
```powershell
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Phantom_Run_HKCU" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Phantom_Run_HKLM" /f
```
---

### SPL Detection Queries

**Production Rule**

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*"
| table _time host User TargetObject TaskCategory Details ProcessId ProcessGuid
| sort -_time
```

**Tighter Rule (Exclude privilleged folders):**

```spl

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
(TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*")
| where NOT (Details LIKE "%Program Files%" OR Details LIKE "%Windows%")
| table _time host User TargetObject TaskCategory Details ProcessId ProcessGuid
| sort -_time
```

Detections will show:
- TargetObject - The Registry Key
- Task Category - The Registry event categegory (Value set)
- Details - The value set
- ProcessId
- ProcessGuid

### Notes

- Sysmon EventID 13 may be noisy if you include all registry changes. Prefer to include RegistryValueSet and target known persistence hives (Run, RunOnce, Services, Winlogon, etc.) in the Sysmon config to reduce volume.
- The tighter rule will exclude persistence alerts from Program Files and Windows. They require admin privileges and will reduce false positives at the risk of missing high signal alerts.

### False positives & Tuning

- Whitelist Legit software installed by admins
- Ignore values that point to C:\Program Files\ or signed installers (Use tighter rule)
- If using the tighter rule, add targeted detections of suspicious files written to %Program FIles% and %Windows%
- Add rarity checks for changes made by uncommon hosts/end users

### Playbook

1. Pull Sysmon event (EventID 13) and capture ProcessGuid/ProcessId → determine process that set the key.
2. Query host for the registry value:

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Phantom_Run_HKCU
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Phantom_Run_HKLM
```
3. Check file referenced by value (hash, location, signature).
4. Identify parent process and timestamp; check for other persistence (services, scheduled tasks).
5. If malicious → isolate host, collect memory & filesystem artifacts, remove registry value, remediate binary, rotate creds if needed.

Elevate severity when:

Non-admin user created a value in HKLM

Value points to user-writable locations (AppData, Temp)

Parent process is Office/Email client or unusual parent (e.g., mshta.exe)
