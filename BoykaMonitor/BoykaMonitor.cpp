/////////////////////////////////////////////////////////////////////////////////////
// BoykaMonitor.cpp
//
// SERVER SIDE Fault Monitor.
// It coordinates the attack with the hijacked client.
//
// NOTE: This code is analogous to BoykaConsole (two threads: net and debug)
/////////////////////////////////////////////////////////////////////////////////////

#undef UNICODE

#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <WinSock.h>
#include <Boyka.h>

#pragma comment(lib, "ws2_32.lib")


int
main(int argc, char *argv[])
{
	HANDLE hThisProcess = 0;
	BOYKAPROCESSINFO bpiMon;

	if(argc < 3)
	{
		printf("Usage: %s <server process name> <console IP>\n", argv[0]);
		return 1;
	}
	
	char *serverExeName = argv[1];
	char *ipConsole = argv[2];

	/////////////////////////////////////////////////////////////////////////////////////
	// Change our privileges. We need to OpenProcess() with OPEN_ALL_ACCESS
	// in order to be able to debug another process.
	/////////////////////////////////////////////////////////////////////////////////////

	if(!OpenProcessToken(
			GetCurrentProcess(),	// handle
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
			&hThisProcess
			))
		{
			printf("[Debug - PrivEsc] Error (OpenProcessToken)\n");
			DisplayError();
			return 1;
		}


	if(SetPrivilege(hThisProcess, SE_DEBUG_NAME, TRUE))
		printf("[Debug - PrivEsc] Successfully set SeDebugPrivilege :)\n");
	else {
		printf("[Debug - PrivEsc] Unable to set SeDebugPrivilege :(\n");
		DisplayError();
		return 1;
	}

	
	// This snippet must be here (after Priv Escalation) since
	// it tries to get an ALL_ACCESS handle to the process.

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
	
	// If I'm attaching to the process at this point, I guess this is a good state 
	// to go back if everything gets all fucked up (access violation, for example)
	int iSaveProc = SaveProcessState(bpiMon.Pid);
	if(iSaveProc != DBG_CONTINUE)
	{
		printf("[debug] Unable to snapshot the program state :(\n");
		printf("[debug] This is FATAL. Aborting...\n");
		return(1);
	}
	else 
	{
		printf("[debug] Saved process state :)\n");
	}


	/* Winsock initialization */
	WSADATA		wsd;
	SOCKET sockMon = INVALID_SOCKET;

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

	sockMon = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sockMon == INVALID_SOCKET)
	{
		printf("[debug] Couldn't create the socket to Console.\n");
		DisplayError();
		WSACleanup();
		return 1;
	}

	// Try to connect...
	int iConRes = connect(sockMon, (SOCKADDR *)&toConsole, sizeof(toConsole));
	if(iConRes == SOCKET_ERROR)
	{
		printf("[debug] Unable to CONNECT to the Console (%s).\n", ipConsole);
		closesocket(sockMon);
		WSACleanup();
		return 1;
	}
	else
		printf("[debug] SUCCESSFULLY CONNECTED to the Console (%s).\n", ipConsole);
	

	// Let's send a test string
	char *sendbuf = "Connection to console established!";
	int iResSend = send(sockMon, sendbuf, (int)strlen(sendbuf), 0);
	if(iResSend == SOCKET_ERROR)
	{
		printf("Send() failed...\n");
		DisplayError();
	}


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
				lav = LogExceptionAccessViolation(bpiMon);
				CommunicateToConsole(sockMon, msgAV);
				WriteMiniDumpFile(&de);
				RestoreProcessState(bpiMon.Pid);

				dwContinueStatus = DBG_CONTINUE;
				break;
			case EXCEPTION_STACK_OVERFLOW:
				// This is in response to a Stack Exhaustion ;)
				lso = LogExceptionStackOverflow(bpiMon);
				CommunicateToConsole(sockMon, msgSO);
				WriteMiniDumpFile(&de);
				RestoreProcessState(bpiMon.Pid);

				dwContinueStatus = DBG_CONTINUE;
				break;

			default:	/* unhandled exception */
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}
			break;

		// I'm only interested in exceptions. The rest won't be processed (for now)
		default:
			dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
			break;
		}

		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}

	return 0;
}





