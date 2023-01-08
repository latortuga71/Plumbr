// RotoRooter.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// https://github.com/csandker/InterProcessCommunication-Samples/blob/master/NamedPipes/CPP-NamedPipe-Basic-Client-Server/CPP-Basic-PipeServer/CPP-Basic-PipeServer.cpp
#include <stdio.h>
#include <windows.h>
#include <aclapi.h>
int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: <PipeName> <Optional: RemoteHost>\n");
        fprintf(stderr, "Ex: %s pipename \n",argv[0]);
        fprintf(stderr, "Ex: %s pipename dc01\n", argv[0]);
        return 1;
    }
    //https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt
    char buffer[MAX_PATH];
    if (argc == 3) {
        //printf("[!] Remote host detected.");
        sprintf_s(buffer, "\\\\%s\\pipe\\%s",argv[2],argv[1]);
    }
    else {
        sprintf_s(buffer, "\\\\.\\pipe\\%s", argv[1]);
    }
    printf("%s\n", buffer);
    if (WaitNamedPipeA(buffer, NMPWAIT_USE_DEFAULT_WAIT) == 0) {
        fprintf(stderr, "[-] Wait Named Pipe Timeout. Pipe Was Never Available For Us.\n");
        fprintf(stderr, "[-] We could enumerate all pipe handles on the system and find the one that matches but thats alot of work right now lol\n");
        return 1;
    }
    HANDLE hPipe = CreateFileA(buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to get handle to pipe");
        return 1;
    }
    PSID sidUser = NULL;
    PSID sidGrp = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;
    //https://learn.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--
    // LookupAccountSid;
    PSECURITY_DESCRIPTOR securityDescriptor;
    DWORD mask;
    DWORD error = GetSecurityInfo(hPipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);
    if (error != ERROR_SUCCESS) {
        error = GetLastError();
        fprintf(stderr, "Failed to GetSecurityInfo ErrorCode %d\n", error);
        return 1;
    }
    ACCESS_ALLOWED_ACE* pAce = NULL;
    for (int x = 0; x < pDacl->AceCount; x++) {
        if (GetAce(pDacl, x, (LPVOID*)&pAce) == FALSE) {
            fprintf(stderr, "Failed to get ACE\n");
            continue;
        }
        if (pAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
            PSID sid = (PSID) & ((ACCESS_ALLOWED_ACE*)pAce)->SidStart;
            char name[MAX_PATH];
            char domain[MAX_PATH];
            DWORD nameLen = MAX_PATH;
            SID_NAME_USE type;
            //wcout << "domianName/AccoutName : " << doname << "/" << oname << endl;
            printf("\t");
            mask = ((ACCESS_ALLOWED_ACE*)pAce)->Mask;
            if (FILE_READ_DATA & mask) {
                printf("R");
            }
            if (FILE_WRITE_DATA & mask) {
                printf("W");
            }
            if (DELETE & mask) {
                printf("D");
            }
            if (FILE_EXECUTE & mask) {
                printf("X");
            }
            printf(" ");
            if (WRITE_DAC & mask) {
                printf("WD");
            }
            if (WRITE_OWNER & mask) {
                printf("WO");
            }
            LookupAccountSidA(NULL, sid, name, &nameLen, domain, &nameLen, &type);
            printf(" %s/%s\n", domain, name);
        }
    }
    LocalFree(securityDescriptor);
    CloseHandle(hPipe);
}