# Detection 09 - DLL Search Order Hijacking

### Purpose

Detect the use of DLL serach order hijacking for persistence

Attackers can cause legitmate executables to load an unexpected DLL (Dynamic Link Library) which contains malicious code that allows them to maintain presence on a system. 

Windows has a specific sequence of searches for dlls to load when an applicaiton calls for one. Attackers exploit this by placing a malicious dll early in this sequence i.e Hijacking the search order.

### ATT&CK Mapping

T1574.001 - Hijack Execution Flow: DLL

### Data Sources

| Source | Details |
|--------|---------|
| Sysmon | EventCode: 7 |

### Test Case

Create a bengin dll and application to run (Or pull the compiled versions from the test_files folder). Verify the dll was loaded in Splunk

Expected Result: Application calls the dll. The dll should write a test file to the system. Splunk should log the event under event code 7 using sysmon

1. Create a benign dll (Requires Visual Studio):

```c
// benign_dll.c
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        char path[MAX_PATH];
        char tempPath[MAX_PATH];
        DWORD len = GetTempPathA(MAX_PATH, tempPath);
        snprintf(path, MAX_PATH, "%s\\dll_test_log.txt", tempPath);
        FILE *f = fopen(path, "a");
        if (f) {
            fprintf(f, "DLL loaded by PID=%lu\n", GetCurrentProcessId());
            fclose(f);
        }
    }
    return TRUE;
}
```

2. Compile with Visual Studio Developer Command Prompt

```cmd
cl /LD benign_dll.c /Fe:benign_test.dll
```

3. Create a test executable that loads the dll we created

```c
// loader.c
#include <windows.h>
int main() {
    HMODULE h = LoadLibraryA("benign_test.dll");
    if (h) { Sleep(1000); FreeLibrary(h); }
    return 0;
}
```

4. Compile the executable

```cmd
cl loader.c
```

5. Copy the compiled dll and executable onto your target machine. Ensure they are in the same folder

6. Run the executable

7. Verify the dll loaded (You should see "DLL loaded by PID=")

```powershell
type $env:TEMP\dll_test_log.txt
```

8. Verify splunk logged the event using the Production rule

### SPL Detection Queries

**Production Rule**

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
| table _time, host, User, EventCode, ProcessGuid, ProcessId, Image, ImageLoaded,
| where NOT (ImageLoaded LIKE "C:\\Windows\\%") 
  AND NOT (ImageLoaded LIKE "C:\\Program Files\\%")
  AND NOT (ImageLoaded LIKE "C:\\Program Files (x86)\\%")
  AND NOT (ImageLoaded LIKE "C:\\ProgramData\Microsoft\Windows Defender\\%") 
| sort -_time
```

### Notes
- This detection will still pick up a lot legitmate dll loading from \AppData\
- Consider whitelisting legimate paths on an ongoing basis
- Do not blanket whitelist noisy non-privileged directories, these are favored by attackers

### False Positives
- Legitmate dll loading by the system/applications
- dlls created by trusted developers on the network

### Tuning 
- Filter out privileged paths
- Whitelist legitmate dlls on ongoing basis

### Quick Playbook
1. Pull the Image, and ImageLoaded fields
2. Check if the dll is in a writeable directory or signed by a trusted vendor, if unsigned -> isolate
3. Check file creation/modification time, if new and unknown -> isolate
4. Search for historical loads of the same dll, if novel -> isolate
5. Preserve dll for analysis
6. Suspend/kill the parent process if confirmed malicious
7. Search for related persistence

**Elevate when:**
- Host needs isolation for any of the above reasons
- dll is confirmed malicious

### Status:

- Test case verified
- Detection verified
- Production Ready

