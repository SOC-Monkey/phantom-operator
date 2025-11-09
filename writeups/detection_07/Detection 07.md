**Config**:

***inputs.conf***

Ensure the Security and System channels for WinEventLog are forwarded:

![[Pasted image 20251110050543.png]]


**Test Process**:

Create a harmless service, then verify the service creation in splunk

Expected outcome: A service that echo's some text is created.

1. Create a service that echo's some text

```powershell
sc.exe create HarmlessService binPath= "cmd.exe /c echo harmless > C:\Temp\harmless.txt" start= auto
```

![[Pasted image 20251110050052.png]]

2. Check the service was created

```powershell
sc.exe query HarmlessService
```

![[Pasted image 20251110050119.png]]

3. Verify the event was ingested into Splunk using the production spl query

**Production Rule**

```
index=main (EventCode=7045 OR EventCode=4697)
| eval ServiceName=coalesce(Service_Name,ServiceName)
| eval ServiceFileName=coalesce(Service_File_Name, ServiceFileName)
| eval ServiceType=coalesce(Service_Type, ServiceType)
| eval ServiceAccount=coalesce(Service_Account, ServiceAccount)
| where NOT like(ServiceFileName,"%Program Files%")
| where NOT like(ServiceFileName,"%SystemRoot%\\System32%")
| where NOT like(ServiceFileName,"%system32%")
| where NOT like(ServiceName, "Sysmon64")
| where NOT like(ServiceName, "SysmonDrv")
| table _time, host, EventCode, ServiceName, ServiceFileName, ServiceType, ServiceAccount
| sort -_time
```

![[Pasted image 20251110050208.png]]

4. Cleanup the service by deleting it

```powershell
sc.exe delete HarmlessService
```

![[Pasted image 20251110050329.png]]