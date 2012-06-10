/////////////////////////////////////////////////////////////////////////////////////
// BoykaDebugging.cpp
//
// This module contains the functions strictly regarding debugging operations.
// The main debugging loop (responding to breakpoints, events, etc.)
// Implementations of set and restore breakpoints.
//
/////////////////////////////////////////////////////////////////////////////////////

#undef UNICODE
#include <vector>
#include <string>
#include <Windows.h>
#include "Boyka.h"



/////////////////////////////////////////////////////////////////////////////////////
// Boyka Console Debugging Thread.
//
// Code in response of diverse events (breakpoint hit, exception raised, etc.)
/////////////////////////////////////////////////////////////////////////////////////
DWORD
DebuggingThread(LPVOID lpParam)
{
	unsigned int iterationNumber = 0;
	DEBUG_EVENT de = {0};
	DWORD dwContinueStatus = DBG_CONTINUE;
	DWORD Pid = 0;
	HANDLE	hProcess = 0;


	// Cast the lpParam before dereferencing.
	Pid = *((DWORD*)lpParam);

	/////////////////////////////////////////////////////////////////////////////////////
	// Attach to the process
	/////////////////////////////////////////////////////////////////////////////////////
	BOOL bAttach = DebugActiveProcess(Pid);
	if(bAttach == 0) {
		printf("[Debug - Attach] Couldn't attach to %s.\n", szExeName);
		DisplayError();
		ExitProcess(1);
	} else {
		printf("[Debug - Attach] Attached to %s!\n", szExeName);
	}

	// Get a handle to the process.
	// TODO: I already got a handle. Pass this to the Thread along with the Pid
	// through a structure, instead of OpenProccess twice.
	if((hProcess = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE, Pid)) == NULL)
	{
		printf("Couldn't open a handle to %s\n", szExeName);
		DisplayError();
	}

	/////////////////////////////////////////////////////////////////////////////////////
	// NOTE: Set a breakpoint at both ends of the fuzzing execution path.
	// For example, around the authentication process. The first breakpoint triggers
	// the snapshot process, the second restores the snapshot.
	/////////////////////////////////////////////////////////////////////////////////////
	BYTE originalByteBegin	= SetBreakpoint(hProcess, dwBeginLoopAddress);
	BYTE originalByteExit	= SetBreakpoint(hProcess, dwExitLoopAddress);


	// READY TO GO!
	while(1)
	{
		WaitForDebugEvent(&de, INFINITE);

		switch (de.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			switch(de.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:
				//////////////////////////////////////////////////////////////////////////////////////
				// At the begin of loop	-> restore bp and save process state (EIP = next instruction)
				// At the end of loop	-> restore process state (back to start of the loop)
				//////////////////////////////////////////////////////////////////////////////////////

				if(de.u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)dwExitLoopAddress)
					{
						// This will execute only when the CS is signaled
						EnterCriticalSection(&boyka_cs);

						printf("[Debug - DebugLoop] Hit RestoreProcessState Breakpoint!\n");
						printf("[Debug - DebugLoop] *** Iteration Number: %u ***\n", iterationNumber++);

						dwContinueStatus = RestoreProcessState(de.dwProcessId);	// debuggee's PID

						LeaveCriticalSection(&boyka_cs);
					}
				else if(de.u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)dwBeginLoopAddress)
					{
						// NOTE: The saved EIP will be the one of the next instruction. Nevertheless it could be that
						// after returning the function is called again from another one. Therefore the RestoreBreakpoint()
						printf("[Debug - DebugLoop] Hit SaveProcessState Breakpoint!\n");
						RestoreBreakpoint(hProcess, de.dwThreadId, (DWORD)de.u.Exception.ExceptionRecord.ExceptionAddress, originalByteBegin);
						dwContinueStatus = SaveProcessState(de.dwProcessId);
					}

				break;

			default:	/* Unhandled exception. Just do some logging right now */
				if(de.u.Exception.dwFirstChance)
					{
						printf(
								"First chance exception at %x, exception-code: 0x%08x\n",
								de.u.Exception.ExceptionRecord.ExceptionAddress,
								de.u.Exception.ExceptionRecord.ExceptionCode
								);
					}

				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}

			break;  // This is the end of "case EXCEPTION_DEBUG_EVENT"

		// We are only interested in exceptions. The rest aren't processed (for now)
		// Just return DBG_EXCEPTION_NOT_HANDLED and continue
		default:
			dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
			break;
		} // End of outer switch (Event Code)

		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	} // End of while loop
}



/////////////////////////////////////////////////////////////////////////////////////
// Rather self explanatory :)
/////////////////////////////////////////////////////////////////////////////////////
BYTE
SetBreakpoint(HANDLE hProcess, DWORD dwAddress)
{
	BYTE originalByte;
	BYTE bpInstruction = 0xCC;

	BOOL bBPReadOK = ReadProcessMemory(
			hProcess,
			(void*)dwAddress,
			&originalByte,
			1,	// ONE BYTE to rule them all
			NULL
			);

	if(!bBPReadOK)
		{
			printf("[Debug - Set BP] Error reading the original byte at intended breakpoint address.\n");
			DisplayError();
		}

	// Replace the original byte with { INT 3 }

	BOOL bBPWriteOK = WriteProcessMemory(
			hProcess,
			(void*)dwAddress,
			&bpInstruction,
			1,
			NULL
			);

	if(!bBPWriteOK)
		{
			printf("[Debug - Set BP] Error writing {INT 3} at intended breakpoint address.\n");
			DisplayError();
		}
	else {
			printf("[Debug - Set BP] Substituted 0x%x with 0x%x at 0x%08x.\n", originalByte, bpInstruction, dwAddress);
	}

	FlushInstructionCache(	// In case instruction has been cached by CPU
			hProcess,
			(void*)dwAddress,
			1
			);

	return originalByte;	// 1 means cool
}



/////////////////////////////////////////////////////////////////////////////////////
// Rather self explanatory :)
/////////////////////////////////////////////////////////////////////////////////////
int
RestoreBreakpoint(HANDLE hProcess, DWORD dwThreadId, DWORD dwAddress, BYTE originalByte)
{
	CONTEXT thContext;
	thContext.ContextFlags = CONTEXT_ALL;
	HANDLE ThreadHandle = OpenThread(
			THREAD_ALL_ACCESS,
			FALSE,
			dwThreadId
			);

	GetThreadContext(ThreadHandle, &thContext);
	// move back EIP one byte
	thContext.Eip--;
	SetThreadContext(ThreadHandle, &thContext);

	// Revert the original byte
	BOOL bBPRestoreOK = WriteProcessMemory(
			hProcess,
			(void*)dwAddress,
			&originalByte,
			1,
			NULL
			);

	if(!bBPRestoreOK)
		{
			printf("[Debug - Restore BP] Error restoring original byte.\n");
			DisplayError();
		}
	else {
			printf("[Debug - Restore BP] Wrote back 0x%x to 0x%08x.\n", originalByte, dwAddress);
	}

	FlushInstructionCache(	// In case instruction has been cached by CPU
			hProcess,
			(void*)dwAddress,
			1
			);


	return 1;	// This means cool
}
