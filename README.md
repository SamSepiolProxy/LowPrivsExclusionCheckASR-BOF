# LowPrivsExclusionCheckASR BOF - Windows Defender ASR Scanner

A Beacon Object File (BOF) for Cobalt Strike that enumerates Windows Defender configuration by reading Event ID 5007 from the Defender Operational event log.

## Features

- **Defender Exclusions**: Discovers path and file exclusions
- **ASR Exclusions**: Finds Attack Surface Reduction exclusions
- **ASR Rule States**: Lists all configured ASR rules with their modes (Disabled/Block/Audit/Warn)
- **Low Privileges**: Works with standard user privileges - no admin rights required
- **Stealthy**: Uses native Windows Event Log API (no PowerShell, WMI, or registry queries)
- **Lightweight**: Runs in-process as a BOF

## What is Detected

### Defender Exclusions
Registry paths under:
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\`

### ASR Exclusions
Registry paths under:
- `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyExclusions`
- `HKLM\SOFTWARE\Microsoft\Windows Defender Exploit Guard\ASR\ASROnlyPerRuleExclusions`

### ASR Rules (19 total)
All Microsoft-defined ASR rules including:
- Block abuse of exploited vulnerable signed drivers
- Block credential stealing from lsass.exe
- Block Office applications from creating child processes
- Block executable content from email client
- And 15 more...

## Usage

### In Cobalt Strike Beacon
```
beacon> lowprivsexclusioncheckasr
```

The command takes no arguments and will:
1. Query the Defender Operational event log
2. Parse all Event ID 5007 entries (configuration changes)
3. Extract and display:
   - Defender exclusions
   - ASR exclusions
   - ASR rule configurations

### Example Output
```
[*] LowPrivsExclusionCheckASR - Windows Defender ASR Scanner (BOF)
[*] Querying Event Log: Microsoft-Windows-Windows Defender/Operational
[*] Event ID: 5007 (Configuration changes)
[*] No admin privileges required

[*] Processed 42 events

===== Defender Exclusions =====
[+] HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\temp
[+] HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\.tmp

===== ASR Exclusions =====
No ASR exclusions found.

===== ASR Summary =====
=> 8 rules configured
=> 2 Disabled ** 3 Audit ** 3 Block ** 0 Warn

===== ASR Rules =====
Rule ID : 5beb7efe-fd9a-4556-801d-275e5ffc04cc
Name    : Block execution of potentially obfuscated scripts
Action  : Block

Rule ID : 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
Name    : Block credential stealing from lsass.exe
Action  : Block

[...]

[*] Scan Complete
```

## Important Notes

### Event ID 5007 Limitation
Event ID 5007 only logs **configuration changes**. This means:
- Rules that were set but never modified will NOT appear
- Fresh installations with default settings may show no rules
- Historical changes are limited by log retention policy

To see ALL current rules (not just changed ones), use registry/WMI queries instead.

### Privileges
- **No admin privileges required** - works with standard user rights
- The Defender Operational event log is readable by standard users
- Event log access is governed by standard Windows security descriptors


## Technical Details

### How It Works
1. Opens handle to `Microsoft-Windows-Windows Defender/Operational` event log
2. Queries for Event ID 5007 (Configuration change events)
3. Parses XML event data using simple pattern matching
4. Extracts registry paths for exclusions and ASR rules
5. Decodes ASR rule GUIDs to human-readable names
6. Outputs organised results to beacon console

### API Usage
- `EvtQuery()` - Query event log
- `EvtNext()` - Iterate events
- `EvtRender()` - Extract event XML
- `EvtClose()` - Cleanup handles

### Memory Management
- Uses Beacon heap API (`HeapAlloc`/`HeapFree`)
- Fixed-size buffers (32KB XML buffer)
- Maximum 256 exclusions, 32 ASR rules

## Credits

Original research: Primusinterp
Original implementation: https://primusinterp.com/posts/WindowsASR/
Original code: https://github.com/Primusinterp/PrimusASR

## License

Use for authorised security testing only. Unauthorised access to computer systems is illegal.

## References

- [Microsoft ASR Rules Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [Windows Event Log API](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Cobalt Strike BOF Development](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm)
