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



extern "C" {  // unmangled var name, please
	__declspec(dllexport) BOYKATESTCASE testCase; // the DLL must export this symbol 
}  


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


////////////////////////////////////////////////////////////////////////////////////
// The DETOUR functions
//
// This will be executed everytime the {detoured, original, real} function 
// gets hit. In our case overwrites the {detoured, original, real} arguments.
////////////////////////////////////////////////////////////////////////////////////


// Don't forget to specify here the function call type (cdecl, stdcall, etc.)
char* __cdecl MyDetourFunction(char* login, char* szPacket, unsigned int len)
{	
	// We need to specify the function prototype so that 
	// we have access to the arguments :)
	login	= GetFuzzStringCase();
	len		= GetFuzzIntegerCase();

	// Fill the current test case structure
	testCase.szStringCase = login;
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

			break;


		case DLL_PROCESS_DETACH:
			/* De-Detour interesting function */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)detFunc, MyDetourFunction); // removing the detour
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("function detour removed");

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
// Defined in BoykaExports.def
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