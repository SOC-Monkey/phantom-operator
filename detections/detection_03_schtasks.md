# Detection 03 - Suspicious Scheduled Task Creation/Execution

### Purpose

Detect creation or execution of scheduled tasks (schtasks.exe) for persistence.

Attackers will commonly created scheduled tasks to execute scripts at specific times to evade detetion or maintain persistence across reboots.

---

### Data Sources

| Source | Details |
|--------|---------|
| Sysmon | EventCode 1 - Process Create (detect `schtasks.exe` creation and execution |
| Splunk sourcetype | `WinEventLog:Microsoft-Windows-Sysmon/Operational` |

---

### Test Case

**A. Create a benign scheduled task (create & delete)**

Run in elevated powershell:

```powershell
# create a harmless scheduled task that echoes a file every minute
`schtasks /create /sc minute /mo 1 /tn "PhantomTask" /tr "cmd.exe /c echo PhantomTaskExecuted > C:\Temp\phantom_task_test.txt" /ru SYSTEM`
#Note: Using SYSTEM avoids the need for credentials and safe in an isolated lab)

# Wait a minute or optionally run it immediately
schtasks /run /tn "Detection_03_TestTask"

# Check the file was created
Test-Path C:\Temp\phantom_task.txt
Get-Content C:\Temp\phantom_task.txt

# delete the task (cleanup)
schtasks /delete /tn "Detection_03_TestTask" /f```
```

### SPL Detection Queries

**Production Rule**
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\schtasks.exe"
| table _time host User Image CommandLine ParentImage ProcessGuid
| sort -_time```
```

### Notes
- This event should only ever occur under a system account or a dedicated service account by an admin user
- This rule only captures sysmon events, Windows Security can also detect this event under the ID 4698 if security audit is enabled
- Detection will work even if ExecutionPolicy if modified or bypassed
- Defender does not block this event

### False Positive Cases

- Admin's scheduling legitimate tasks
- Backup solutions
- Patching tools
- Monitored maintenance

### Mitigations and Tuning

- Whitelist known automation users/hosts
- Correlate with asset inventory (i.e Administrative hosts vs user enpoints)
- Supress tasks created by approved groups using `ParentImage` and `User` fields
- Add rarity checks (Treat hosts/users who never create tasks aa higher priority)

# Playbook 

On detection:

1. Look up the `User` and `ParentImage`. If the user is non-admin and the ParentImage is a Living of the Land (LotL) Binary such as explorer.exe or powershell -> Escalate.
2. Pull the created task's command from the `CommandLine` field
3. If the task runs a suspicious binary or attempts to contact an external network -> Isolate the host
4. Search for related persistence (i.e Other tasks, installs, registry changes, WMI changes, dropped files)

### Status

- ✅ Test case validated
- ✅ Test Evidence captured
- ✅ Production ready
 
 
