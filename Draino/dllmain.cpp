// dllmain.cpp : Defines the entry point for the DLL application.
// https://github.com/ZeroMemoryEx/TrampHook/blob/master/TrampHook/TrampHook.cpp
// https://github.com/bats3c/ChromeTools
// The RootKit Arsenal

#include <windows.h>
#include <stdio.h>

VOID* gWriteFileAddress;
VOID* gReadFileAddress;
unsigned char writeFileOriginalBytes[13];
unsigned char readFileOriginalBytes[13];

static WCHAR g_tmpFileName[MAX_PATH];
static HANDLE g_hTmpFile;

BOOL WINAPI WriteFileHook(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
BOOL WINAPI ReadFileHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

BOOL WINAPI OriginalWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
BOOL WINAPI OriginalReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

VOID StealPipeInfo(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWantedToUse, LPDWORD lpNumberOfBytesUsed, LPOVERLAPPED lpOverlapped, BOOL isWrite);


BOOL InitSharedFile();

//VOID WriteBothHooks();
VOID WriteReadFileHook();
VOID WriteWriteFileHook();

extern "C" __declspec(dllexport) BOOL SetupHooks();


BOOL InitSharedFile() {
    DWORD pid = GetCurrentProcessId();
    WCHAR tmpPath[MAX_PATH] = L"c:\\windows\\temp\\";
    //if (GetTempPath(MAX_PATH, tmpPath) == 0)
    //    return FALSE;
    _snwprintf_s(g_tmpFileName, MAX_PATH, L"%wsPLUMBER.%d.LOG", tmpPath, pid);
    g_hTmpFile = CreateFile(g_tmpFileName, FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hTmpFile == INVALID_HANDLE_VALUE)
        return false;
    printf("LogFile -> %ws\n", g_tmpFileName);
    return true;
}


VOID StealPipeInfo(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWantedToUse, LPDWORD lpNumberOfBytesUsed, LPOVERLAPPED lpOverlapped,BOOL isWrite ) {
    // check if we wrote to a pipe
    if (GetFileType(hFile) != FILE_TYPE_PIPE)
        return;
    if (lpNumberOfBytesUsed != NULL) {
        if (*lpNumberOfBytesUsed == 0)
            return;
    }
    // maybe try GetFinalPathNameByHandleA 
    // ok its a pipe lets get the name of the pipe.
    /*
    ULONG nameSize = sizeof(FILE_NAME_INFO) + (sizeof(WCHAR) * MAX_PATH);
    FILE_NAME_INFO nameInfo = { 0 };
    GetFileInformationByHandleEx(hFile, FileNameInfo, &nameInfo, sizeof(FILE_NAME_INFO));
    FILE_NAME_INFO* realName = (FILE_NAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_NAME_INFO) + nameInfo.FileNameLength);
    if (realName == NULL) {
        return;
    }
    BOOL check = GetFileInformationByHandleEx(hFile, FileNameInfo, realName, sizeof(FILE_NAME_INFO) + nameInfo.FileNameLength);
    if (!check) {
        HeapFree(GetProcessHeap(), 0, realName);
        return;
    }
    */
    // we could also try printing the actual handle value and look it up in process hacker or another program?
    if (isWrite)
        WriteFile(g_hTmpFile, L"\n--- Wrote Data To Pipe ", lstrlenW(L"\n--- Wrote Data To Pipe ") * sizeof(WCHAR), NULL, NULL);
    else 
        WriteFile(g_hTmpFile, L"\n--- Read Data From Pipe ", lstrlenW(L"\n--- Read Data To Pipe ") * sizeof(WCHAR), NULL, NULL);
    WriteFile(g_hTmpFile, L"???", lstrlenW(L"???") * sizeof(WCHAR), NULL, NULL);
    WriteFile(g_hTmpFile, L" ---\n\0 ", lstrlenW(L" ---\n\0 ") * sizeof(WCHAR), NULL, NULL);
    //WriteFile(g_hTmpFile, L"\n--- Data ---\n\0", lstrlenW(L"--- Data ---\n\0") * sizeof(WCHAR), NULL, NULL);
    WriteFile(g_hTmpFile, lpBuffer, nNumberOfBytesToWantedToUse, lpNumberOfBytesUsed, NULL);
    // Write Message That Chunk Is Done
    DWORD lengthOfEndMsg = lstrlenW(L"\n--- End Of Chunk ---\n\0") * sizeof(WCHAR);
    WriteFile(g_hTmpFile, L"\n--- End Of Chunk ---\n\0", lengthOfEndMsg, NULL, NULL);
}


BOOL WINAPI OriginalWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    // Restore Original Bytes
    DWORD oldProt;
    VirtualProtect(gWriteFileAddress, 16, PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(GetCurrentProcess(), gWriteFileAddress, writeFileOriginalBytes, sizeof(writeFileOriginalBytes), NULL);
    VirtualProtect(gWriteFileAddress, 16, oldProt, &oldProt);
    // Now we call original function
    BOOL realResult = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    // Here we can do stuff before we write our hooks back.
    StealPipeInfo(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, NULL,TRUE);
    // Now we write our hooks back again
    WriteWriteFileHook();
    // and return the result of WriteFile
    return realResult;
}


BOOL WINAPI OriginalReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    // Restore Original Bytes
    DWORD oldProt;
    VirtualProtect(gWriteFileAddress, 16, PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(GetCurrentProcess(), gReadFileAddress, readFileOriginalBytes, sizeof(readFileOriginalBytes), NULL);
    VirtualProtect(gWriteFileAddress, 16, oldProt, &oldProt);
    // Now we call original function
    BOOL res = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    // Here we can do stuff before we write our hooks back.
    StealPipeInfo(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, NULL, FALSE);
    // Now we write our hooks back again
    WriteReadFileHook();
    // and return the result of WriteFile
    return res;
}

BOOL WINAPI WriteFileHook(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    // Do Stuff Before Function Is Called.
    //MessageBoxA(NULL, (char*)lpBuffer, "Hooked WriteFile", 0);
    //
    return OriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


BOOL WINAPI ReadFileHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    // Do Stuff Here for now we just pop a message box.
    //MessageBoxA(NULL, (char*)lpBuffer, "Hooked ReadFile", 0);
    //
    return OriginalReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

VOID WriteWriteFileHook(){
    DWORD oldProt;
    SIZE_T wrote;
    // set hooks for write file
    VirtualProtect(gWriteFileAddress, 16, PAGE_EXECUTE_READWRITE, &oldProt);
    unsigned char writeFileTramp[] = { 0x49, 0xbb, 0xde, 0xad, 0xc0, 0xde, 0xde, 0xad, 0xc0, 0xde, 0x41, 0xff, 0xe3 };
    *(void**)(writeFileTramp + 2) = &WriteFileHook;
    WriteProcessMemory(GetCurrentProcess(), gWriteFileAddress, writeFileTramp, sizeof(writeFileTramp), &wrote);
    VirtualProtect(gWriteFileAddress, 16, oldProt, &oldProt);
}

VOID WriteReadFileHook() {
    DWORD oldProt;
    SIZE_T wrote;
    // set hook for read file;
    VirtualProtect(gWriteFileAddress, 16, PAGE_EXECUTE_READWRITE, &oldProt);
    unsigned char readFileTramp[] = { 0x49, 0xbb, 0xde, 0xad, 0xc0, 0xde, 0xde, 0xad, 0xc0, 0xde, 0x41, 0xff, 0xe3 };
    *(void**)(readFileTramp + 2) = &ReadFileHook;
    WriteProcessMemory(GetCurrentProcess(), gReadFileAddress, readFileTramp, sizeof(readFileTramp), &wrote);
    VirtualProtect(gWriteFileAddress, 16, oldProt, &oldProt);
    // done setting hooks.
    //MessageBoxA(NULL, "Hooks Set", "Hooks Set", 0);
}

/*
VOID WriteBothHooks() {
    WriteWriteFileHook();
    WriteReadFileHook();
}
*/

extern "C" __declspec(dllexport) BOOL SetupHooks() {
    // get address of function to hook
    BOOL res;
    SIZE_T read;
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (hKernel32 == 0) {
        fprintf(stderr, "EXITING. Failed to get address of kernel32\n");
        exit(1);
    }
    gWriteFileAddress = GetProcAddress(hKernel32, "WriteFile");
    if (gWriteFileAddress == NULL) {
        fprintf(stderr, "EXITING. Failed to get address of WriteFile\n");
        exit(1);
    }
    gReadFileAddress = GetProcAddress(hKernel32, "ReadFile");
    if (gReadFileAddress == NULL) {
        fprintf(stderr, "EXITING. Failed to get address of ReadFile\n");
        exit(1);
    }
    printf("Address Of Kernel32 0x%p\n", hKernel32);
    printf("Address Of WriteFile 0x%p\n", gWriteFileAddress);
    printf("Address Of ReadFile 0x%p\n", gReadFileAddress);
    // Save original bytes for write file
    res = ReadProcessMemory(GetCurrentProcess(), gWriteFileAddress, writeFileOriginalBytes, sizeof(writeFileOriginalBytes), &read);
    if (!res) {
        fprintf(stderr, "EXITING. Failed to read original bytes %x %d\n", GetLastError(), read);
        exit(1);
    }
    res = ReadProcessMemory(GetCurrentProcess(), gReadFileAddress, readFileOriginalBytes, sizeof(readFileOriginalBytes), &read);
    if (!res) {
        fprintf(stderr, "EXITING. Failed to read original bytes %x %d\n", GetLastError(), read);
        exit(1);
    }

    // This Writes Tramp
    //WriteBothHooks();
    WriteWriteFileHook();
    WriteReadFileHook();
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL TEST() {
    if (!InitSharedFile()) {
        MessageBoxA(NULL, "Failed to init shared file", "error", 0);
        exit(1);
    }
    SetupHooks();
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Injected", "!", 0);
        if (!InitSharedFile()) {
            MessageBoxA(NULL, "Failed to init shared file", "error", 0);
            exit(1);
        }
        MessageBoxA(NULL, "Got Past Shared File", "!", 0);
        SetupHooks();
        MessageBoxA(NULL, "Got Past SetupHooks", "!", 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

