/////////////////////////////////////////////////////////////////////////////////////
// BoykaMonitor.cpp
//
// SERVER SIDE Fault Monitor.
// It coordinates the attack with the hijacked client.
//
// NOTE: This code is analogous to BoykaConsole (two threads: net and debug)
/////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <Windows.h>
#include <WinSock.h>
#include <Boyka.h>



int
main(int argc, char *argv[])
{
	BOYKAPROCESSINFO bpiMon;

	if(argc < 3)
	{
		printf("Usage: %s <server process name> <console IP>\n", argv[0]);
		return 1;
	}
	
	char *serverExeName = argv[1];
	char *ipConsole = argv[2];


	// Find the process (command line argument)
	bpiMon = FindProcessByName(serverExeName);
	if(bpiMon.Pid == 0)
	{
		printf("\n[debug] Process %s NOT found. Is it running?\n", serverExeName);
		return 1;
	}



	/////////////////////////////////////////////////////////////////////////////////////
	// Here starts the action :)
	/////////////////////////////////////////////////////////////////////////////////////

	/* Winsock initialization */
	WSADATA		wsd;
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("[debug] Error: Can't load WinSock");
		WSACleanup();
		return 1;
	}

	
	/* Establish a TCP connection back to the Console module */

	SOCKADDR_IN toConsole;

	toConsole.sin_family = AF_INET;
	toConsole.sin_port = htons(1337);
	toConsole.sin_addr.s_addr = inet_addr(ipConsole);

	SOCKET sockMon = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sockMon == INVALID_SOCKET)
	{
		printf("[debug] Couldn't create the socket to Console.\n");
		return 1;
	}

	// Try to connect...
	if(connect(sockMon, (SOCKADDR *)&toConsole, sizeof(toConsole)) == SOCKET_ERROR)
	{
		printf("[debug] Unable to CONNECT to the Console (%s).\n", ipConsole);
		return 1;
	}
	else
		printf("[debug] SUCCESSFULLY CONNECTED to the Console (%s).\n", ipConsole);
	

	
	/////////////////////////////////////////////////////////////////////////////////////
	// NOTE: Let's do some tests without threads for the moment.
	/////////////////////////////////////////////////////////////////////////////////////
	
		
	// Attach to the process
	BOOL bAttach = DebugActiveProcess(bpiMon.Pid);
	if(bAttach == 0) {
		printf("[Debug] Couldn't attach to %s. ErrCode: %u\n", bpiMon.szExeName, GetLastError());
		ExitProcess(1);
	} else {
		printf("[Debug] Attached to %s!\n", bpiMon.szExeName);
	}


	DEBUG_EVENT de;
	DWORD dwContinueStatus = 0;
	unsigned int lav, lso;
	char msgAV[] = "Access violation detected!";
	char msgSO[] = "Stack overflow detected!";


	while(1)
	{
		WaitForDebugEvent(&de, INFINITE);

		switch (de.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			switch(de.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
				// TODO: Maybe consolidate all this logging callbacks using OOP:
				//		 inherit from Exception Logging object or something like that
				lav = LogExceptionAccessViolation();
				CommunicateToConsole(sockMon, msgAV);

				dwContinueStatus = DBG_CONTINUE;
				break;

			case EXCEPTION_STACK_OVERFLOW:
				lso = LogExceptionStackOverflow();
				CommunicateToConsole(sockMon, msgSO);

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

	return 0;
}





