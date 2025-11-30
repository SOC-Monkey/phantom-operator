# Universal Forwarder Inputs

**Use the following config for the Universal Forwarders inputs.conf file

```conf
[default]
host = Win10-VM

[WinEventLog://Application]
disabled = 0
index = main

[WinEventLog://Security]
disabled = 0
renderXml = true
index = main
start_from = newest
current_only = 0
checkpointInterval = 5
evt_resolve_ad_obj = 1

[WinEventLog://System]
disabled = 0
index = main

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
renderXml = false
```