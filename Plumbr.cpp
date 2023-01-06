// Plumbr.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <windows.h>


int main()
{
    printf("Not hookin");
    getchar();
    MessageBoxA(NULL,"A","A",MB_OK);
    HMODULE hinstDLL = LoadLibraryA("PlumbrDll.dll");
    if (hinstDLL == NULL) {
        printf("FAILED TO LOAD DLL %d\n", GetLastError());
        return 1;
    }
    printf("Ya Hookin\n");
    getchar();
    MessageBoxA(NULL, "B", "B", MB_OK);
    getchar();
    return 0;
}
