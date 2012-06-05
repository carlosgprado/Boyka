//////////////////////////////////////////////////////////////////////////////////////////
// BoykaDll.cpp (detours action)
//
// This DLL will be injected to the process by BoykaConsole.
// Contains the code for the client software modifications (argument overwriting, etc.)
//
// COMPILE with:
// cl.exe /EHsc /LD /I <path to detours.h> BoykaDll.cpp \
//				BoykaCommunication.cpp <path to detours.lib> user32.lib
//////////////////////////////////////////////////////////////////////////////////////////

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "ws2_32.lib")



#undef UNICODE

#include <cstdio>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <detours.h>
#include <assert.h>
#include <time.h>	// used by rand()
#include "Boyka.h"  // always the last one


///////////////////////////////////////////////////////////////////
// Prototype for a function pointer to the "real" function.
//
// The typedef "declares" a function pointer with these
// specific return value and arguments
//
///////////////////////////////////////////////////////////////////

typedef int (*pArithmeticSender01)(char*, int, int); // function pointer declaration
pArithmeticSender01 FuncToDetour = (pArithmeticSender01)(dwBeginLoopAddress); // initialization



///////////////////////////////////////////////////////////////////
// The detour function
///////////////////////////////////////////////////////////////////

int WINAPI MyArithmeticSender01(char* buf, int len, int unknown)
{
	// We have total R/W access to the intercepted function's variables
	// They are located at EBP + 0x08, like in a normal call
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	HANDLE hProc = GetCurrentProcess();		// pseudo-handle (only valid within the thread)
	DWORD pRead;
	LPVOID testAddr;

	memset(&context, 0, sizeof(CONTEXT));



	///////////////////////////////////////////////////////////////////
	// Copy the test string into the victim memory space.
	//
	// I need to place the test string in our memory space
	// so that it'll still be there after detour returns.
	///////////////////////////////////////////////////////////////////
	char* test = GetFuzzStringCase();

	testAddr = VirtualAlloc(
			NULL,	// I don't care where
			sizeof(test),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);


	WriteProcessMemory(
			hProc,
			(LPVOID)testAddr,
			(LPVOID)test,
			sizeof(test),
			NULL);


	///////////////////////////////////////////////////////////////////
	// NOTE: Nor GetThreadContext nor RtlCaptureContext worked.
	// This is an alternative way to get some of the CONTEXT
	// On a related note: "Real men do it in assembler" :)
	///////////////////////////////////////////////////////////////////
	__asm
	{
		call x
		x: 	pop eax
			add eax, 4				; GetPC trick
			mov context.Eip, eax	; EIP
			mov context.Esp, esp	; ESP
			mov context.Ebp, ebp	; EBP :)
	}


	ReadProcessMemory(
			hProc,
			(LPVOID)(context.Ebp + 8),	// Careful with optimized binaries w/o saved frame pointers!
			(LPVOID)&pRead,
			4, // buffer *pointer*
			NULL);


	WriteProcessMemory(
			hProc,
			(LPVOID)(context.Ebp + 8),	// Careful with optimized binaries w/o saved frame pointers!
			(LPVOID)&testAddr,
			4,
			NULL);


	CloseHandle(hProc);

	return FuncToDetour(buf, len, unknown);
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
			DetourAttach(&(PVOID&)FuncToDetour, MyArithmeticSender01); // *actual* detour
			if(DetourTransactionCommit() == NO_ERROR)
				OutputDebugString("send() detoured successfully");

			/* Winsock initialization */
			WSADATA		wsd;
			if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
			{
				OutputDebugString("[debug] Error: Can't load WinSock");
				return 0;
			}

			/* Create the Communications Module thread */
			HANDLE	hListenerThread;
			DWORD	dwListenerThread;
			hListenerThread = CreateThread(
					NULL,
					0,
					ListenerThread,	// LPTHREAD_START_ROUTINE
					0,				// LPVOID lpParam
					0,
					&dwListenerThread
					);
				
			break;


		case DLL_PROCESS_DETACH:
			/* Microsoft DETOURS stuff */
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(PVOID&)FuncToDetour, MyArithmeticSender01); // removing the detour
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
// NOTE: The *FuzzCases are defined in Boyka.h
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