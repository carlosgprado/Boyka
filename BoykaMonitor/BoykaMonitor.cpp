/////////////////////////////////////////////////////////////////////////////////////
// BoykaMonitor.cpp
//
// Server side fault monitor.
// It coordinates the attack with the hijacked client.
/////////////////////////////////////////////////////////////////////////////////////

#include "Boyka.h"
#include <Windows.h>


int
main(int argc, char *argv[])
{


	/////////////////////////////////////////////////////////////////////////////////////
	// Attach to the process
	/////////////////////////////////////////////////////////////////////////////////////
	BOOL bAttach = DebugActiveProcess(pe32.th32ProcessID);
	if(bAttach == 0) {
		printf("[Debug] Couldn't attach to %s. ErrCode: %u\n", pe32.szExeFile, GetLastError());
		ExitProcess(1);
	} else {
		printf("[Debug] Attached to %s!\n", pe32.szExeFile);
	}


	/////////////////////////////////////////////////////////////////////////////////////
	// Here starts the action :)
	/////////////////////////////////////////////////////////////////////////////////////
	BoykaDebugLoop();


	return 0;
}




void
BoykaDebugLoop()
{
	DEBUG_EVENT de;
	DWORD dwContinueStatus = 0;

	while(1)
	{
		WaitForDebugEvent(&de, INFINITE);

		switch (de.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			switch(de.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:
				// TODO: change this to a more elaborated
				// 		 logging callback :)
				MessageBoxA(0, "Found break point", "", 0);

				dwContinueStatus = DBG_CONTINUE;
				break;

			default:	/* unhandled exception */
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}
			break;

		// We are only interested in exceptions. The rest aren't processed (for now)
		default:
			dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
			break;
		}

		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}
