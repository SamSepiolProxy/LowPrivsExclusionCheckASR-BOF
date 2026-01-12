/*
 * LowPrivsExclusionCheckASR BOF - Windows Defender ASR Scanner
 * Reads Event Log (Defender/Operational, EventID=5007) to enumerate:
 *   - Defender exclusions
 *   - ASR exclusions
 *   - ASR rule states
 *
 * Note: Works with standard user privileges - no admin rights required
 * Compile: x64 mingw, or Visual Studio with BOF flags
 */

#include <windows.h>
#include <winevt.h>
#include "beacon.h"

/* BOF API declarations */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT int WINAPI MSVCRT$_wcsnicmp(const wchar_t*, const wchar_t*, size_t);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int WINAPI MSVCRT$_vsnwprintf(wchar_t*, size_t, const wchar_t*, va_list);
DECLSPEC_IMPORT wchar_t* WINAPI MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* WINAPI MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* WINAPI MSVCRT$wcsstr(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int WINAPI MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT wchar_t WINAPI MSVCRT$towlower(wchar_t);

DECLSPEC_IMPORT EVT_HANDLE WINAPI WEVTAPI$EvtQuery(EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtNext(EVT_HANDLE, DWORD, EVT_HANDLE*, DWORD, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtRender(EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtClose(EVT_HANDLE);

#define EVT_QUERY_CHANNEL_PATH 0x1
#define EVT_RENDER_EVENT_XML 1
#define MAX_EXCLUSIONS 256
#define MAX_ASR_RULES 32
#define BUFFER_SIZE 32768

/* Helper structures */
typedef struct {
    wchar_t path[512];
} Exclusion;

typedef struct {
    wchar_t guid[64];
    wchar_t name[256];
    wchar_t action[32];
} AsrRule;

typedef struct {
    Exclusion defenderExcl[MAX_EXCLUSIONS];
    int defenderCount;
    Exclusion asrExcl[MAX_EXCLUSIONS];
    int asrCount;
    AsrRule asrRules[MAX_ASR_RULES];
    int ruleCount;
    int totalDisabled;
    int totalBlock;
    int totalAudit;
    int totalWarn;
} ScanResults;

/* Memory helpers */
static void* bof_alloc(size_t size) {
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void bof_free(void* ptr) {
    if (ptr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ptr);
}

/* String helpers */
static void to_lower(wchar_t* str) {
    while (*str) {
        *str = MSVCRT$towlower(*str);
        str++;
    }
}

static BOOL contains_substr(const wchar_t* haystack, const wchar_t* needle) {
    wchar_t* lower_haystack = (wchar_t*)bof_alloc((MSVCRT$wcslen(haystack) + 1) * sizeof(wchar_t));
    wchar_t* lower_needle = (wchar_t*)bof_alloc((MSVCRT$wcslen(needle) + 1) * sizeof(wchar_t));
    
    if (!lower_haystack || !lower_needle) {
        bof_free(lower_haystack);
        bof_free(lower_needle);
        return FALSE;
    }
    
    MSVCRT$wcscpy(lower_haystack, haystack);
    MSVCRT$wcscpy(lower_needle, needle);
    to_lower(lower_haystack);
    to_lower(lower_needle);
    
    BOOL result = (MSVCRT$wcsstr(lower_haystack, lower_needle) != NULL);
    
    bof_free(lower_haystack);
    bof_free(lower_needle);
    return result;
}

/* ASR GUID to name mapping */
static const wchar_t* get_asr_name(const wchar_t* guid) {
    wchar_t lower_guid[64];
    MSVCRT$wcscpy(lower_guid, guid);
    to_lower(lower_guid);
    
    if (MSVCRT$wcsstr(lower_guid, L"56a863a9-875e-4185-98a7-b882c64b5ce5"))
        return L"Block abuse of exploited vulnerable signed drivers";
    if (MSVCRT$wcsstr(lower_guid, L"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"))
        return L"Block Adobe Reader from creating child processes";
    if (MSVCRT$wcsstr(lower_guid, L"d4f940ab-401b-4efc-aadc-ad5f3c50688a"))
        return L"Block all Office applications from creating child processes";
    if (MSVCRT$wcsstr(lower_guid, L"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"))
        return L"Block credential stealing from lsass.exe";
    if (MSVCRT$wcsstr(lower_guid, L"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"))
        return L"Block executable content from email client and webmail";
    if (MSVCRT$wcsstr(lower_guid, L"01443614-cd74-433a-b99e-2ecdc07bfc25"))
        return L"Block executable files from running unless they meet criteria";
    if (MSVCRT$wcsstr(lower_guid, L"5beb7efe-fd9a-4556-801d-275e5ffc04cc"))
        return L"Block execution of potentially obfuscated scripts";
    if (MSVCRT$wcsstr(lower_guid, L"d3e037e1-3eb8-44c8-a917-57927947596d"))
        return L"Block JavaScript or VBScript from launching downloaded content";
    if (MSVCRT$wcsstr(lower_guid, L"3b576869-a4ec-4529-8536-b80a7769e899"))
        return L"Block Office applications from creating executable content";
    if (MSVCRT$wcsstr(lower_guid, L"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"))
        return L"Block Office applications from injecting code into other processes";
    if (MSVCRT$wcsstr(lower_guid, L"26190899-1602-49e8-8b27-eb1d0a1ce869"))
        return L"Block Office communication application from creating child processes";
    if (MSVCRT$wcsstr(lower_guid, L"e6db77e5-3df2-4cf1-b95a-636979351e5b"))
        return L"Block persistence through WMI event subscription";
    if (MSVCRT$wcsstr(lower_guid, L"d1e49aac-8f56-4280-b9ba-993a6d77406c"))
        return L"Block process creations originating from PSExec and WMI commands";
    if (MSVCRT$wcsstr(lower_guid, L"33ddedf1-c6e0-47cb-833e-de6133960387"))
        return L"Block rebooting machine in Safe Mode";
    if (MSVCRT$wcsstr(lower_guid, L"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"))
        return L"Block untrusted and unsigned processes that run from USB";
    if (MSVCRT$wcsstr(lower_guid, L"c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"))
        return L"Block use of copied or impersonated system tools";
    if (MSVCRT$wcsstr(lower_guid, L"a8f5898e-1dc8-49a9-9878-85004b8a61e6"))
        return L"Block Webshell creation for Servers";
    if (MSVCRT$wcsstr(lower_guid, L"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"))
        return L"Block Win32 API calls from Office macros";
    if (MSVCRT$wcsstr(lower_guid, L"c1db55ab-c21a-4637-bb3f-a12568109d35"))
        return L"Use advanced protection against ransomware";
    
    return L"Unknown ASR rule";
}

static const wchar_t* action_name(DWORD val) {
    switch (val) {
        case 0: return L"Disabled";
        case 1: return L"Block";
        case 2: return L"Audit";
        case 6: return L"Warn";
        default: return L"Unknown";
    }
}

/* Parse hex value from string like "0x1" */
static DWORD parse_hex(const wchar_t* str) {
    DWORD result = 0;
    const wchar_t* p = str;
    
    if (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) {
        p += 2;
    }
    
    while (*p) {
        wchar_t c = *p;
        if (c >= L'0' && c <= L'9') {
            result = result * 16 + (c - L'0');
        } else if (c >= L'a' && c <= L'f') {
            result = result * 16 + (c - L'a' + 10);
        } else if (c >= L'A' && c <= L'F') {
            result = result * 16 + (c - L'A' + 10);
        } else {
            break;
        }
        p++;
    }
    
    return result;
}

/* Simple pattern matching for registry paths */
static BOOL match_defender_exclusion(const wchar_t* xml, int pos, int len, wchar_t* out, int out_size) {
    const wchar_t* pattern = L"hklm\\software\\microsoft\\windows defender\\exclusions\\";
    
    if (!contains_substr(xml + pos, pattern)) {
        return FALSE;
    }
    
    // Find the start of the match
    const wchar_t* start = MSVCRT$wcsstr(xml + pos, L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\");
    if (!start) {
        start = MSVCRT$wcsstr(xml + pos, L"hklm\\software\\microsoft\\windows defender\\exclusions\\");
    }
    if (!start) return FALSE;
    
    // Copy until newline or bracket
    int i = 0;
    while (i < out_size - 1 && start[i] && start[i] != L'<' && start[i] != L'\r' && start[i] != L'\n') {
        out[i] = start[i];
        i++;
    }
    out[i] = L'\0';
    
    return (i > 0);
}

static BOOL match_asr_exclusion(const wchar_t* xml, int pos, int len, wchar_t* out, int out_size) {
    if (!contains_substr(xml + pos, L"asr\\asronlyexclusions") && 
        !contains_substr(xml + pos, L"asr\\asronlyperruleexclusions")) {
        return FALSE;
    }
    
    const wchar_t* patterns[] = {
        L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\ASROnlyExclusions",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender Exploit Guard\\ASR\\ASROnlyExclusions",
        L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\ASROnlyPerRuleExclusions",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender Exploit Guard\\ASR\\ASROnlyPerRuleExclusions"
    };
    
    const wchar_t* start = NULL;
    for (int p = 0; p < 4 && !start; p++) {
        start = MSVCRT$wcsstr(xml + pos, patterns[p]);
    }
    
    if (!start) return FALSE;
    
    int i = 0;
    while (i < out_size - 1 && start[i] && start[i] != L'<' && start[i] != L'\r' && start[i] != L'\n') {
        out[i] = start[i];
        i++;
    }
    out[i] = L'\0';
    
    return (i > 0);
}

static BOOL match_asr_rule(const wchar_t* xml, int pos, int len, wchar_t* guid_out, DWORD* val_out) {
    if (!contains_substr(xml + pos, L"asr\\rules\\")) {
        return FALSE;
    }
    
    // Look for pattern: ASR\Rules\{GUID} = 0xN
    const wchar_t* rules_pos = MSVCRT$wcsstr(xml + pos, L"ASR\\Rules\\");
    if (!rules_pos) {
        rules_pos = MSVCRT$wcsstr(xml + pos, L"asr\\rules\\");
    }
    if (!rules_pos) return FALSE;
    
    // Skip past "ASR\Rules\"
    const wchar_t* guid_start = rules_pos;
    while (*guid_start && *guid_start != L'{' && guid_start < xml + len) {
        guid_start++;
    }
    
    if (*guid_start != L'{') return FALSE;
    guid_start++; // Skip '{'
    
    // Copy GUID
    int i = 0;
    while (i < 36 && guid_start[i] && guid_start[i] != L'}') {
        guid_out[i] = guid_start[i];
        i++;
    }
    guid_out[i] = L'\0';
    
    if (i != 36) return FALSE; // GUID should be exactly 36 chars
    
    // Look for the value "= 0x"
    const wchar_t* val_start = guid_start + i;
    while (*val_start && *val_start != L'=' && val_start < xml + len) {
        val_start++;
    }
    if (*val_start != L'=') return FALSE;
    val_start++;
    
    while (*val_start == L' ' || *val_start == L'\t') val_start++;
    
    if (val_start[0] != L'0' || (val_start[1] != L'x' && val_start[1] != L'X')) {
        return FALSE;
    }
    
    wchar_t hex_val[16];
    i = 0;
    while (i < 15 && val_start[i] && val_start[i] != L' ' && val_start[i] != L'\r' && val_start[i] != L'\n' && val_start[i] != L'<') {
        hex_val[i] = val_start[i];
        i++;
    }
    hex_val[i] = L'\0';
    
    *val_out = parse_hex(hex_val);
    return TRUE;
}

/* Check if item already exists in array */
static BOOL exclusion_exists(Exclusion* arr, int count, const wchar_t* path) {
    for (int i = 0; i < count; i++) {
        if (MSVCRT$_wcsnicmp(arr[i].path, path, 512) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL rule_exists(AsrRule* arr, int count, const wchar_t* guid) {
    for (int i = 0; i < count; i++) {
        if (MSVCRT$_wcsnicmp(arr[i].guid, guid, 64) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LowPrivsExclusionCheckASR - Windows Defender ASR Scanner (BOF)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Querying Event Log: Microsoft-Windows-Windows Defender/Operational\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Event ID: 5007 (Configuration changes)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] No admin privileges required\n\n");
    
    const wchar_t* channel = L"Microsoft-Windows-Windows Defender/Operational";
    const wchar_t* query = L"*[System[(EventID=5007)]]";
    
    EVT_HANDLE hQuery = WEVTAPI$EvtQuery(NULL, channel, query, EVT_QUERY_CHANNEL_PATH);
    if (!hQuery) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query event log. Error: 0x%x\n", KERNEL32$GetLastError());
        BeaconPrintf(CALLBACK_ERROR, "[-] Note: Ensure Event Log service is running and log channel exists.\n");
        return;
    }
    
    ScanResults* results = (ScanResults*)bof_alloc(sizeof(ScanResults));
    if (!results) {
        WEVTAPI$EvtClose(hQuery);
        BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed\n");
        return;
    }
    
    wchar_t* xml_buffer = (wchar_t*)bof_alloc(BUFFER_SIZE);
    if (!xml_buffer) {
        bof_free(results);
        WEVTAPI$EvtClose(hQuery);
        BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed\n");
        return;
    }
    
    EVT_HANDLE events[10];
    DWORD returned = 0;
    int event_count = 0;
    
    while (WEVTAPI$EvtNext(hQuery, 10, events, INFINITE, 0, &returned)) {
        for (DWORD i = 0; i < returned; i++) {
            DWORD bufferUsed = 0, propertyCount = 0;
            
            // Get required buffer size
            WEVTAPI$EvtRender(NULL, events[i], EVT_RENDER_EVENT_XML, 0, NULL, &bufferUsed, &propertyCount);
            
            if (bufferUsed < BUFFER_SIZE) {
                bufferUsed = 0;
                propertyCount = 0;
                
                if (WEVTAPI$EvtRender(NULL, events[i], EVT_RENDER_EVENT_XML, 
                                      BUFFER_SIZE, xml_buffer, &bufferUsed, &propertyCount)) {
                    
                    int xml_len = MSVCRT$wcslen(xml_buffer);
                    event_count++;
                    
                    // Scan for patterns in the XML
                    for (int pos = 0; pos < xml_len - 50; pos++) {
                        wchar_t temp[512];
                        
                        // Check for Defender exclusions
                        if (results->defenderCount < MAX_EXCLUSIONS && 
                            match_defender_exclusion(xml_buffer, pos, xml_len - pos, temp, 512)) {
                            if (!exclusion_exists(results->defenderExcl, results->defenderCount, temp)) {
                                MSVCRT$wcscpy(results->defenderExcl[results->defenderCount].path, temp);
                                results->defenderCount++;
                            }
                        }
                        
                        // Check for ASR exclusions
                        if (results->asrCount < MAX_EXCLUSIONS && 
                            match_asr_exclusion(xml_buffer, pos, xml_len - pos, temp, 512)) {
                            if (!exclusion_exists(results->asrExcl, results->asrCount, temp)) {
                                MSVCRT$wcscpy(results->asrExcl[results->asrCount].path, temp);
                                results->asrCount++;
                            }
                        }
                        
                        // Check for ASR rules
                        wchar_t guid[64];
                        DWORD val;
                        if (results->ruleCount < MAX_ASR_RULES && 
                            match_asr_rule(xml_buffer, pos, xml_len - pos, guid, &val)) {
                            
                            to_lower(guid);
                            
                            if (!rule_exists(results->asrRules, results->ruleCount, guid)) {
                                MSVCRT$wcscpy(results->asrRules[results->ruleCount].guid, guid);
                                MSVCRT$wcscpy(results->asrRules[results->ruleCount].name, get_asr_name(guid));
                                MSVCRT$wcscpy(results->asrRules[results->ruleCount].action, action_name(val));
                                
                                const wchar_t* action = action_name(val);
                                if (MSVCRT$wcsstr(action, L"Disabled")) results->totalDisabled++;
                                else if (MSVCRT$wcsstr(action, L"Block")) results->totalBlock++;
                                else if (MSVCRT$wcsstr(action, L"Audit")) results->totalAudit++;
                                else if (MSVCRT$wcsstr(action, L"Warn")) results->totalWarn++;
                                
                                results->ruleCount++;
                            }
                        }
                    }
                }
            }
            
            WEVTAPI$EvtClose(events[i]);
        }
    }
    
    WEVTAPI$EvtClose(hQuery);
    
    // Output results
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Processed %d events\n\n", event_count);
    
    BeaconPrintf(CALLBACK_OUTPUT, "===== Defender Exclusions =====\n");
    if (results->defenderCount > 0) {
        for (int i = 0; i < results->defenderCount; i++) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %S\n", results->defenderExcl[i].path);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "No Defender exclusions found.\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    
    BeaconPrintf(CALLBACK_OUTPUT, "===== ASR Exclusions =====\n");
    if (results->asrCount > 0) {
        for (int i = 0; i < results->asrCount; i++) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %S\n", results->asrExcl[i].path);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "No ASR exclusions found.\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    
    BeaconPrintf(CALLBACK_OUTPUT, "===== ASR Summary =====\n");
    if (results->ruleCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "=> %d rules configured\n", results->ruleCount);
        BeaconPrintf(CALLBACK_OUTPUT, "=> %d Disabled ** %d Audit ** %d Block ** %d Warn\n\n",
                     results->totalDisabled, results->totalAudit, results->totalBlock, results->totalWarn);
        
        BeaconPrintf(CALLBACK_OUTPUT, "===== ASR Rules =====\n");
        for (int i = 0; i < results->ruleCount; i++) {
            BeaconPrintf(CALLBACK_OUTPUT, "Rule ID : %S\n", results->asrRules[i].guid);
            BeaconPrintf(CALLBACK_OUTPUT, "Name    : %S\n", results->asrRules[i].name);
            BeaconPrintf(CALLBACK_OUTPUT, "Action  : %S\n\n", results->asrRules[i].action);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "No ASR rules found in event log.\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Note: Event ID 5007 only logs configuration changes.\n");
        BeaconPrintf(CALLBACK_OUTPUT, "      Rules never modified may not appear.\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Scan Complete\n");
    
    bof_free(xml_buffer);
    bof_free(results);
}
