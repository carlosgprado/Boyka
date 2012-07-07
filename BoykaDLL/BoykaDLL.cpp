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

#include <cstdio>
#include <string.h>
#include <Windows.h>
#include <detours.h>
#include <assert.h>
#include <time.h>		// used by rand()
#include "Fuzzing.h"	// Test case definitions
#include <Boyka.h>		// always the last one


////////////////////////////////////////////////////////////////////////////////////
// Prototype for a function pointer to the "real" function.
//
// The typedef "declares" a FUNCTION POINTER with these
// specific return value and arguments
// NOTE: This is something you will have to change every time...
////////////////////////////////////////////////////////////////////////////////////

typedef int (*pDetouredFunction)(char*); // function pointer declaration
pDetouredFunction FuncToDetour = (pDetouredFunction)(dwDetouredFunctionAddress); // initialization


////////////////////////////////////////////////////////////////////////////////////
// The DETOUR function
//
// This will be executed everytime the {detoured, original, real} function 
// gets hit. In our case overwrites the {detoured, original, real} arguments.
//
// NOTE: you may need to modify the way you locate the arguments on the stack,
// depending on whether the function prolog has been executed yet or not...
////////////////////////////////////////////////////////////////////////////////////

int WINAPI MyDetourFunction(char* buf)
{
	// We have total R/W access to the intercepted function's variables
	// They start at ESP + 0x04, since we operate *before* the prolog 
	// Therefore EBP hasn't been pushed nor switched yet
	// (at the top of the stack there's only saved EIP)

	CONTEXT context;
	HANDLE hProc = GetCurrentProcess();		// pseudo-handle (only valid within the thread)
	DWORD pRead = 0;
	LPVOID testAddr;

	memset(&context, 0, sizeof(CONTEXT));	// initialize with 0x00 bytes
	context.ContextFlags = CONTEXT_FULL;

	//////////////////////////////////////////////////////////////////
	// NOTE: Neither GetThreadContext nor RtlCaptureContext worked.
	// So this is an alternative way to get some of the CONTEXT
	// On a related note: "Real men do it in assembler" :)
	///////////////////////////////////////////////////////////////////
	__asm
	{
		call x
		x: 	pop eax					; GetPC trick
			mov context.Eip, eax	; EIP
			mov context.Esp, esp	; ESP  :)
			mov context.Ebp, ebp	; EBP
	}


	char* test = GetFuzzStringCase();

	///////////////////////////////////////////////////////////////////
	// Copy the test string into the victim memory space.
	//
	// I need to place the test string in our memory space
	// so it'll still be there after detour returns.
	///////////////////////////////////////////////////////////////////

	printf("[debug] Execution Detoured. String Fuzz Case: %s\n", test);

	testAddr = VirtualAlloc(
			NULL,	// I don't care where
			strlen(test),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

	if(testAddr == NULL)
		printf("[BoykaDLL - Detoured Function] Failed to VirtualAlloc()\n");
		

	int wrStatus = WriteProcessMemory(
			hProc,
			(LPVOID)testAddr,
			(LPVOID)test,
			strlen(test),
			NULL);

	if(wrStatus == 0)
		printf("[BoykaDLL - Detoured Function] Failed to WriteProcessMemory()\n");
		

	ReadProcessMemory(
			hProc,
			(LPVOID)(context.Ebp + 8),
			(LPVOID)&pRead,
			4, // buffer *pointer*
			NULL);
			

	printf("[debug] EBP is located at %08x\n", context.Ebp);
	printf("[debug] EBP + 8 contains %08x\n", pRead);
	printf("[debug] This points to %s\n", pRead);
	

	WriteProcessMemory(
			hProc,
			(LPVOID)(context.Ebp + 8),
			(LPVOID)&testAddr,
			4,
			NULL);

	// Cleanup
	CloseHandle(hProc);


	// It transfers execution back to the original point.
	return FuncToDetour(buf);
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
			/* Microsoft DETOURS stuff */
			DisableThreadLibraryCalls(hDLL);
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)FuncToDetour, MyDetourFunction); // actual detour fn_a -> fn_b
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("send() detoured successfully");				
			break;


		case DLL_PROCESS_DETACH:
			/* Microsoft DETOURS stuff */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)FuncToDetour, MyDetourFunction); // removing the detour
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("send() detour removed");
			break;


		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
	}
	return TRUE;
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
