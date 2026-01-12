/*
 * beacon.h - Beacon Object File API definitions
 * Minimal header for Cobalt Strike BOF development
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* Beacon callback types */
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_OUTPUT_OEM 0x1e
#define CALLBACK_ERROR 0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* Data parser structure */
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

/* Beacon API functions */
#ifdef __cplusplus
extern "C" {
#endif

DECLSPEC_IMPORT void __cdecl BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT int __cdecl BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short __cdecl BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int __cdecl BeaconDataLength(datap* parser);
DECLSPEC_IMPORT char* __cdecl BeaconDataExtract(datap* parser, int* size);

DECLSPEC_IMPORT void __cdecl BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void __cdecl BeaconOutput(int type, char* data, int len);

DECLSPEC_IMPORT BOOL __cdecl BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void __cdecl BeaconRevertToken();
DECLSPEC_IMPORT BOOL __cdecl BeaconIsAdmin();

DECLSPEC_IMPORT void __cdecl BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
DECLSPEC_IMPORT void __cdecl BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);
DECLSPEC_IMPORT void __cdecl BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);
DECLSPEC_IMPORT BOOL __cdecl BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO* si, PROCESS_INFORMATION* pInfo);
DECLSPEC_IMPORT void __cdecl BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);

DECLSPEC_IMPORT BOOL __cdecl toWideChar(char* src, wchar_t* dst, int max);

#ifdef __cplusplus
}
#endif

/* BOF entry point */
#ifdef BOF
#define main go
#endif

#endif /* BEACON_H */
