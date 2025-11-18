# Phantom Operator - A 10-rule persistence detection suite for Windows using sysmon + splunk

- **Author:** Joshua Robin
- **Focus:** Detection Engineering + Security Automation
- **SIEM:** Splunk
- **Theme:** Phantom Operator (Defense evasion + persistence tactics)

This repo documents my journey building a personal SOC detection program and security tooling portfolio

**It currently includes:**
- Custom Splunk detections (10-rules)
- Validated test cases
- Sysmon configuration tuning
- Writeups
- Quick response playbooks

---

 ### Detections

 | Name | Technique | MITRE ID |
 |------|-----------|----------|
 | [Detection 01](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_01_certutil.md) | Certutil File Retrieval | T1218.010 |
 | [Detection 02](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_02_encoded_powershell.md) | Encoded Powershell Execution | T1059.001 + T1027 |
 | [Detection 03](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_03_schtasks.md) | Suspicious Scheduled Task | T1053.005 |
 | [Detection 04](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_04_registry_run.md) | Run key Persistence | T1547.001 |
 | [Detection 05](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_05_ads_execution.md) | Alternate Data Stream Execution | T1564.004 |
 | [Detection 06](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_06_wmi_persistence.md) | WMI Subscription Persistence | T1546.003 |
 | [Detection 07](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_07_service_creation.md) | Service Creation | T1543.003 |
 | [Detection 08](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_08_user_account_creation.md) | User Account Creation | T1136.001 + T1098 | 
 | [Detection 09](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_09_dll_so_hijacking.md) | DLL Hijacking | T1574.001 | 
 | [Detection 10](https://github.com/SOC-Monkey/phantom-operator/blob/main/detections/detection_10_startup_folder_abuse.md) | Startup Folder Abuse | T1574.001 |

 ### Testing Method

 Each detection had a unique test case to simulate the event. Attacks were simulated using benign payloads. Sysmon and Windows Event Log are the data sources used.

 ### Skills Demonstrated

 - Windows threat detection engineering
 - Splunk query engineering
 - Sysmon configuration
 - Pipeline setup -> (VM -> Sysmon -> UF -> Splunk)
 - MITRE ATT&CK Mapping
 - Tuning and noise reduction
 - Testing & Attack simulations
 - Incident response
 - Documentation



 
