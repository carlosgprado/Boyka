//////////////////////////////////////////////////////////////////////////////////////////
// BoykaDll.cpp (detours action)
//
// This DLL will be injected to the process by BoykaConsole.
// Contains the code for the client software modifications (argument overwriting, etc.)
//
// COMPILE with:
// cl.exe /EHsc /LD /I <path to detours.h> BoykaDll.cpp \
//				<path to detours.lib> user32.lib
//////////////////////////////////////////////////////////////////////////////////////////

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "ws2_32.lib")


#undef UNICODE

#include <Windows.h>
#include <cstdio>
#include <string.h>
#include <detours.h>
#include <assert.h>
#include <time.h>		// used by rand()
#include "Fuzzing.h"	// Test case definitions
#include <Boyka.h>		// always the last one

BOOL WithinLoopFlag = TRUE;	// Work on this approach

BOYKATESTCASE testCase = {NULL, 0};

////////////////////////////////////////////////////////////////////////////////////////////
// Prototype for a function pointer to the "real" function.
//
// The typedef "declares" a FUNCTION POINTER with the specific return value and arguments.
// 
// Don't forget to specify the calling convetion as well
// NOTE: This is something you will have to change every time...
////////////////////////////////////////////////////////////////////////////////////////////
typedef char* (*pDetouredFunction)(char*, char*, unsigned int); // pointer to function with argument char*,... and return char*
pDetouredFunction detFunc = (pDetouredFunction)(dwDetouredFunctionAddress); // initialization by address
typedef void (*pMyFree)(void *); // pointer to function with argument void* and no return
pMyFree detFree = (pMyFree)free; // initialization
typedef BOOL (*pMyCloseHandle)(HANDLE); // ...
pMyCloseHandle detCloseHandle = (pMyCloseHandle)CloseHandle;
// In C++ the preferred method is to return from the thread, also this won't work...
// TODO: Add TerminateThread as well?
typedef BOOL (*pMyFreeLibrary)(HMODULE);
pMyFreeLibrary detFreeLibrary = (pMyFreeLibrary)FreeLibrary;
typedef HGLOBAL (*pMyGlobalFree)(HGLOBAL);
pMyGlobalFree detGlobalFree = (pMyGlobalFree)GlobalFree;
typedef HLOCAL (*pMyLocalFree)(HLOCAL);
pMyLocalFree detLocalFree = (pMyLocalFree)LocalFree;
typedef BOOL (*pMyVirtualFree)(LPVOID, SIZE_T, DWORD);
pMyVirtualFree detVirtualFree = (pMyVirtualFree)VirtualFree;
typedef BOOL (*pMyHeapFree)(HANDLE, DWORD, LPVOID);
pMyHeapFree detHeapFree = (pMyHeapFree)HeapFree;
typedef BOOL (*pMyHeapDestroy)(HANDLE);
pMyHeapDestroy detHeapDestroy = (pMyHeapDestroy)HeapDestroy;




////////////////////////////////////////////////////////////////////////////////////
// The DETOUR functions
//
// This will be executed everytime the {detoured, original, real} function 
// gets hit. In our case overwrites the {detoured, original, real} arguments.
////////////////////////////////////////////////////////////////////////////////////
BOOL WINAPI MyFreeLibrary(HMODULE hModule)
{
	if(!WithinLoopFlag)
		return FreeLibrary(hModule);
	else
		return TRUE;
}


BOOL WINAPI MyCloseHandle(HANDLE hMyHandle)
{
	if(!WithinLoopFlag)
		return detCloseHandle(hMyHandle);
	else
		return TRUE;
}


void __cdecl MyFree(void *mem)
{
	// flag not set: call free as usual
	// flag set: don't do anything
	if(!WithinLoopFlag) free(mem);
}


HGLOBAL WINAPI MyGlobalFree(HGLOBAL hMem)
{
	if(!WithinLoopFlag)
		return detGlobalFree(hMem);
	else
		return NULL;
}


HLOCAL WINAPI MyLocalFree(HLOCAL hMem)
{
	if(!WithinLoopFlag)
		return detLocalFree(hMem);
	else
		return NULL;
}


BOOL WINAPI MyVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	if(!WithinLoopFlag)
		return detVirtualFree(lpAddress, dwSize, dwFreeType);
	else
		return TRUE;
}


BOOL WINAPI MyHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
	if(!WithinLoopFlag)
		return detHeapFree(hHeap, dwFlags, lpMem);
	else
		return TRUE;
}


BOOL WINAPI MyHeapDestroy(HANDLE hHeap)
{
	if(!WithinLoopFlag)
		return detHeapDestroy(hHeap);
	else
		return TRUE;
}


// Don't forget to specify here the function call type (cdecl, stdcall, etc.)
char* __cdecl MyDetourFunction(char* login, char* szPacket, unsigned int len)
{	
	// We need to specify the function prototype so that 
	// we have access to the arguments :)
	login	= GetFuzzStringCase();
	len		= GetFuzzIntegerCase();

	//free(testCase.szStringCase);
	// Fill the current test case structure
	testCase.szStringCase = (char*)malloc(strlen(login));
	strcpy(testCase.szStringCase, login);
	testCase.iIntegerCase = len;

	// It transfers execution back to the original point.
	return detFunc(login, szPacket, len);
}


/////////////////////////////////////////////////////////////////////
// It implements the *detouring* (at DLL loading time)
// Patching MOV ESI, ESI with a JMP, the trampoline function, etc.
/////////////////////////////////////////////////////////////////////

BOOL APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
	switch(Reason)
	{
		case DLL_PROCESS_ATTACH:
			/* Detour interesting function */
			DisableThreadLibraryCalls(hDLL);
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detFunc, MyDetourFunction); // actual detour fn_a -> fn_b
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("function detoured successfully");
			/* Detour Free()
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detFree, MyFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("Free() detoured successfully");
			*/
			/* Detour CloseHandle() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detCloseHandle, MyCloseHandle);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("CloseHandle() detoured successfully");
			/* Detour FreeLibrary() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detFreeLibrary, MyFreeLibrary);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("FreeLibrary() detoured successfully");
			/* Detour GlobalFree() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detGlobalFree, MyGlobalFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("GlobalFree() detoured successfully");
			/* Detour LocalFree() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detLocalFree, MyLocalFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("LocalFree() detoured successfully");
			/* Detour VirtualFree() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detVirtualFree, MyVirtualFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("VirtualFree() detoured successfully");
			/* Detour HeapFree() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detHeapFree, MyHeapFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("HeapFree() detoured successfully");
			/* Detour HeapDestroy() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)detHeapDestroy, MyHeapDestroy);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("HeapDestroy() detoured successfully");

			break;


		case DLL_PROCESS_DETACH:
			/* De-Detour interesting function */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detFunc, MyDetourFunction); // removing the detour
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("function detour removed");
			/* De-Detour Free() function
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detFree, MyFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("Free() detour removed");
			*/
			/* De-Detour CloseHandle() function */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detCloseHandle, MyCloseHandle);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("CloseHandle() detour removed");
			/* De-Detour FreeLibrary() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detFreeLibrary, MyFreeLibrary);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("FreeLibrary() detour removed");
			/* De-Detour GlobalFree() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detGlobalFree, MyGlobalFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("GlobalFree() detour removed");
			/* De-Detour LocalFree() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detLocalFree, MyLocalFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("LocalFree() detour removed");
			/* De-Detour VirtualFree() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detVirtualFree, MyVirtualFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("VirtualFree() detour removed");
			/* Detour HeapFree() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detHeapFree, MyHeapFree);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("HeapFree() detour removed");
			/* Detour HeapDestroy() */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detHeapDestroy, MyHeapDestroy);
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("HeapDestroy() detour removed");

			break;


		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
	}
	return TRUE;
}



///////////////////////////////////////////////////////////////////
// Exported functions
///////////////////////////////////////////////////////////////////
char* currentFuzzStringCase()
{
	return testCase.szStringCase;
}


int currentFuzzIntegerCase()
{
	return testCase.iIntegerCase;
}


///////////////////////////////////////////////////////////////////
// Let's write here some *stupid* fuzz case generation functions.
// TODO: Change this to something more... sophisticated :)
// 		 Some code reusing would be nice as well ;)
//
// NOTE: The XXXFuzzCases are defined in Fuzzing.h
///////////////////////////////////////////////////////////////////

char*
GetFuzzStringCase()
{
	unsigned int idx, arrayLength;
	
	srand(time(NULL));	// initialize random seed
	arrayLength = sizeof(StringFuzzCases)/sizeof(StringFuzzCases[0]);
	idx = rand() % arrayLength;
	printf("[BoykaDLL - GetFuzzStringCase] index %u selected\n", idx);

	return StringFuzzCases[idx];
}


int
GetFuzzIntegerCase()
{
	unsigned int idx, arrayLength;
	
	srand(time(NULL));	// initialize random seed
	arrayLength = sizeof(IntegerFuzzCases)/sizeof(IntegerFuzzCases[0]);
	idx = rand() % arrayLength;

	return IntegerFuzzCases[idx];
}


int 
RandomInteger()
{
	int i;

	srand(time(NULL));  // initialize random seed
	i = ((double)rand() / (RAND_MAX + 1)) * UINT_MAX;

	return i;
}


char *
RepeatedToken(char *t, unsigned int n, BOOL nullTerminate)
{
	// NOTE: This does NOT null terminate the buffer
	// TODO: Remember to free this afterwars 
	// to prevent a memory leak...
	char *repBuffer, *idx;
	unsigned int len = 0, s = 0;

	len = strlen(t) * n;
	// Null terminate implies I reserve one byte more that 
	// won't be overwritten and stays (0x00)
	if(nullTerminate)
		len++;

	repBuffer = (char *)malloc(len);
	memset(repBuffer, 0x00, sizeof(repBuffer));

	idx = repBuffer;

	while(s < n)
	{
		strcpy(idx, t);
		s++;
		idx += strlen(t);
	}


	return repBuffer;
}