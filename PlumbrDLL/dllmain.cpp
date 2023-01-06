// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <stdio.h>
#include "detours.h"
#include <string.h>

#pragma comment(lib,"detours.lib")


// Real Addresses Of Hooked Functions

static BOOL(WINAPI* RealWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) = WriteFile;
static BOOL(WINAPI* RealReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = ReadFile;
static int (WINAPI * RealMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) = MessageBoxA;
static WCHAR g_tmpFileName[MAX_PATH];
static HANDLE g_hTmpFile;

// Our Hooks

BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL result = RealReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (*lpNumberOfBytesRead == 0)
        return result;
    // check if we wrote to a pipe
    if (GetFileType(hFile) != FILE_TYPE_PIPE)
        return result;
    // ok its a pipe lets get the name of the pipe.
    ULONG nameSize = sizeof(FILE_NAME_INFO) + (sizeof(WCHAR) * MAX_PATH);
    FILE_NAME_INFO nameInfo = { 0 };
    GetFileInformationByHandleEx(hFile, FileNameInfo, &nameInfo, sizeof(FILE_NAME_INFO));
    FILE_NAME_INFO* realName = (FILE_NAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_NAME_INFO) + nameInfo.FileNameLength);
    if (realName == NULL) {
        return result;
    }
    BOOL check = GetFileInformationByHandleEx(hFile, FileNameInfo, realName, sizeof(FILE_NAME_INFO) + nameInfo.FileNameLength);
    if (!check) {
        HeapFree(GetProcessHeap(), 0, realName);
        return result;
    }
    WCHAR logMsg[MAX_PATH + 30];
    //_snwprintf_s(logMsg, wcstrlen(realName), L"Wrote %d bytes to pipe %ws\n", *lpNumberOfBytesWritten, realName->FileName);
    //printf("Pipe name %ws\n", realName->FileName);
    WCHAR msg[MAX_PATH];
    DWORD lengthOfMsg = _snwprintf(NULL, 0, L"--- Read %d bytes from pipe %ws --- \n\0", *lpNumberOfBytesRead, realName->FileName) + (realName->FileNameLength * sizeof(WCHAR)) + sizeof(int);
    //printf("%d\n", lengthOfMsg);
    _snwprintf_s(msg, lengthOfMsg, L"--- Read %d bytes from pipe %ws --- \n\0", *lpNumberOfBytesRead, realName->FileName);
    RealWriteFile(g_hTmpFile, msg, lengthOfMsg, NULL, NULL);
    HeapFree(GetProcessHeap(), 0, realName);
    // Write Bytes Somewhere.
    // Write Original Bytes To File with original 
    RealWriteFile(g_hTmpFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    // Write Message That Chunk Is Done
    DWORD lengthOfEndMsg = lstrlenW(L"--- End Of Chunk ---\n\0");
    RealWriteFile(g_hTmpFile, L"--- End Of Chunk ---\n\0", lengthOfEndMsg, NULL, NULL);
    return result;
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    BOOL result = RealWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    // check if we wrote to a pipe
    if(*lpNumberOfBytesWritten == 0) 
        return result;
    if (GetFileType(hFile) != FILE_TYPE_PIPE)
        return result;
    // ok its a pipe lets get the name of the pipe.
    ULONG nameSize = sizeof(FILE_NAME_INFO) + (sizeof(WCHAR) * MAX_PATH);
    FILE_NAME_INFO nameInfo = { 0 };
    GetFileInformationByHandleEx(hFile, FileNameInfo, &nameInfo, sizeof(FILE_NAME_INFO));
    FILE_NAME_INFO* realName  = (FILE_NAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_NAME_INFO) + nameInfo.FileNameLength);
    if (realName == NULL) {
        return result;
    }
    BOOL check = GetFileInformationByHandleEx(hFile, FileNameInfo, realName, sizeof(FILE_NAME_INFO) + nameInfo.FileNameLength);
    if (!check) {
        HeapFree(GetProcessHeap(), 0, realName);
        return result;
    }
    //printf("Pipe name %ws\n", realName->FileName);
    DWORD pipeNameLength = wcslen(realName->FileName) * sizeof(WCHAR);
    WCHAR msg[MAX_PATH];
    //DWORD lengthOfMsg = wcslen(L"\n--- Wrote %d bytes to pipe %ws --- \n\0") * 2;
    DWORD lengthOfMsg = _snwprintf(NULL, 0, L"\n--- Wrote %d bytes to pipe %ws --- \n\0", *lpNumberOfBytesWritten, realName->FileName);
    LONG length = lengthOfMsg * 2;
;   //DWORD length = _snwprintf(NULL, 0, L"\n--- Wrote %d bytes to pipe %ws --- \n\0", *lpNumberOfBytesWritten, realName->FileName) + (realName->FileNameLength * sizeof(WCHAR)) + sizeof(DWORD);
    //printf("%d\n", length);
    _snwprintf_s(msg, length, L"\n--- Wrote %d bytes to pipe %ws --- \n\0", *lpNumberOfBytesWritten, realName->FileName);
    // Write That We Wrote To A Pipe
    RealWriteFile(g_hTmpFile, msg,length, NULL, NULL);
    HeapFree(GetProcessHeap(), 0, realName);
    // Write Original Bytes To File with original 
    RealWriteFile(g_hTmpFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    // Write Message That Chunk Is Done
    DWORD lengthOfEndMsg = lstrlenW(L"\n--- End Of Chunk ---\n\0") * sizeof(WCHAR);
    RealWriteFile(g_hTmpFile, L"\n--- End Of Chunk ---\n\0", lengthOfEndMsg, NULL, NULL);
    return result;
}


BOOL InitSharedFile() {
    DWORD pid = GetCurrentProcessId();
    WCHAR tmpPath[MAX_PATH] = L"";
    if (GetTempPath(MAX_PATH, tmpPath) == 0)
        return FALSE;
    _snwprintf_s(g_tmpFileName, MAX_PATH, L"%wsPLUMBER.%d.LOG",tmpPath,pid);
    g_hTmpFile = CreateFile(g_tmpFileName,FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,NULL);
    if (g_hTmpFile == INVALID_HANDLE_VALUE)
        return false;
    return true;
}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH: {
            if (!InitSharedFile()) {
                return FALSE;
            }
            DetourRestoreAfterWith();
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)RealWriteFile, HookedWriteFile);
            DetourAttach(&(PVOID&)RealReadFile, HookedReadFile);
            LONG lError = DetourTransactionCommit();
            if (lError != NO_ERROR) {
                return FALSE;
            }
            else {
            }
            break;
        }
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH: {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)RealWriteFile, HookedWriteFile);
            DetourDetach(&(PVOID&)RealReadFile, HookedReadFile);
            DetourTransactionCommit();
            CloseHandle(g_hTmpFile);
            break;
        }
    }
    return TRUE;
}

