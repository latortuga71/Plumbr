// CheckRace.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// Base Code For Server From https://github.com/csandker/InterProcessCommunication-Samples/blob/master/NamedPipes/CPP-NamedPipe-Basic-Client-Server/CPP-Basic-PipeServer/CPP-Basic-PipeServer.cpp

#include <windows.h>
#include <stdio.h>



int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: <PipeName> <Optional: RemoteHost>\n");
		fprintf(stderr, "Ex: %s pipename \n", argv[0]);
		fprintf(stderr, "Ex: %s pipename dc01\n", argv[0]);
		return 1;
	}
	//https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt
	char buffer[MAX_PATH];
	if (argc == 3) {
		//printf("[!] Remote host detected.");
		sprintf_s(buffer, "\\\\%s\\pipe\\%s", argv[2], argv[1]);
	}
	else {
		sprintf_s(buffer, "\\\\.\\pipe\\%s", argv[1]);
	}
	printf("%s\n", buffer);
	HANDLE hServerPipe;
	BOOL bSuccess;
	DWORD bytesWritten = 0;
	DWORD messageLenght;
	BOOL bAttemptImpersonation = TRUE;
	printf("[*] Creating named pipe: %s\n", buffer);
	hServerPipe = CreateNamedPipeA(
		buffer,			// name of our pipe, must be in the form of \\.\pipe\<NAME>
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, // open mode, specifying a duplex pipe so server and client can send and receive data
		PIPE_TYPE_MESSAGE,	// MESSAGE mode to send/receive messages in discrete units (instead of a byte stream)
		PIPE_UNLIMITED_INSTANCES,					// number of instanced for this pipe, 1 is enough for our use case
		2048,				// output buffer size
		2048,				// input buffer size
		0,					// default timeout value, equal to 50 milliseconds
		NULL				// use default security attributes
	);

	wprintf(L"[*] Waiting for incoming connections...");
	bSuccess = ConnectNamedPipe(hServerPipe, NULL);
	if (bSuccess) {
		wprintf(L"Someone Connected! You should add more code here to impersonate the user (check tokens etc.).\n");
	}
	else wprintf(L"Error: %d", GetLastError());
	// Sending a message
	/*
	wchar_t message[] = L"Gooooooooooooood Morning Vietnam...";
	messageLenght = lstrlen(message) * 2;
	wprintf(L"[*] Sending message '%s'...", message);
	bSuccess = WriteFile(hServerPipe, message, messageLenght, &bytesWritten, NULL);
	if (!bSuccess) {
		wprintf(L"Error writing to pipe. Error: %d", GetLastError());
	}
	else wprintf(L"Done.\n");
	*/
	// Close handle
	CloseHandle(hServerPipe);
	return 0;
}

