# KDBG
It's a PoC of an anti-debugger kernel:
It's a project made for fun, maybe in the future I'll add more detections and more things.

## Detections
```ini
[+] DebugPort Check
[+] BeingDebugged Check
[+] NtGlobalFlag Check
[+] DebugObjectHandle Check
[+] DebugFlags Check
[+] ExeCheck Check
```
These are the checks that are there at the moment, above each check I also put a comment to explain.

### Info
Compile this project in x64 Release and of course with the WDK installed: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

## License
[MIT](https://choosealicense.com/licenses/mit/)
