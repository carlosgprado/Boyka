//////////////////////////////////////////////////////////////////////////////////////
// Communications Module.
//
// This implements the TCP components that allow
// Server and Client side debuggers to talk to each other.
//////////////////////////////////////////////////////////////////////////////////////

#undef UNICODE

#include <winsock.h>
#include <string.h>
#include <stdio.h>
#include "Boyka.h"

#pragma comment(lib, "ws2_32.lib")

extern "C" {  // unmangled var name, please
	__declspec(dllimport) BOYKATESTCASE testCase; // I need to import this symbol 
}


// This little thing will allow me to synchronize threads.
CRITICAL_SECTION	boyka_cs;


///////////////////////////////////////////////////////////////////////////////////////
// BoykaConsole Listener Module.
// This will launch a recv() infinite loop.
// TODO: recv() is blocking, maybe implement it in a separate thread?
///////////////////////////////////////////////////////////////////////////////////////

DWORD WINAPI 
ListenerThread(LPVOID lpParam)
{
	// This function will be executed in a separate thread.

	UNREFERENCED_PARAMETER(lpParam);
	SOCKET		sServerListen, sClient;
	struct		sockaddr_in localaddr;
	int			iRecv = 0, iSend = 0;
	char		szRecvBuffer[BOYKA_BUFLEN];
	char*		szACKBuffer = "ALL_OK_NEXT_ONE";

	/* Winsock initialization */
	WSADATA		wsd;
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("[debug] Error: Can't intialize WinSock");
		DisplayError();
		return 1;
	}


	// Create a SOCKET for connecting to server
	sServerListen = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sServerListen == INVALID_SOCKET)
	{
		printf("[debug] Error: Can't create the socket\n");
		DisplayError();
		WSACleanup();
		return 1;
	}


	// Setup the TCP listening socket
	localaddr.sin_addr.s_addr = htonl(INADDR_ANY);	// Listens in all interfaces
	localaddr.sin_family = AF_INET;
	localaddr.sin_port = htons(1337);				// what else? :)

	// BIND
	if (bind(sServerListen, (struct sockaddr *)&localaddr,
			sizeof(localaddr)) == SOCKET_ERROR)
	{
		printf("[debug] Error: Can't bind\n");
		closesocket(sServerListen);
		WSACleanup();
		return 1;
	}
	else
		printf("[debug] ## Bound to 0.0.0.0:1337 ##\n");


	// LISTEN
	if(listen(sServerListen, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("[debug] Error: Listen failed\n");
		DisplayError();
		closesocket(sServerListen);
		WSACleanup();
		return 1;
	}


	// ACCEPT a client SOCKET
	// NOTE: NULL because I don't care about the connecting client address
	sClient = accept(sServerListen, NULL, NULL);
	if (sClient == INVALID_SOCKET)
	{
		printf("[debug] Error: accept failed\n");
		closesocket(sServerListen);
		WSACleanup();
		return 1;
	}

	// SETSOCKOPTIONS
	// I don't want recv() to block until something is received.
	// Instead of this, a TIMEOUT will be set for the case no exception
	// occurred on the server side (no feedback)
	int sTimeout = CONSOLE_SOCK_TIMEOUT;	// milliseconds
	
	int sockOptRes = setsockopt(sClient, SOL_SOCKET, SO_RCVTIMEO, (const char *)&sTimeout, sizeof(int));
	if(sockOptRes == SOCKET_ERROR)
		printf("[debug - setsockopt] Recv() Timeout couldn't be set.\n");
	else
		//printf("[debug - setsockopt] Recv() Timeout set to %u milliseconds.\n", sTimeout);


	// I don't need the server socket anymore
	closesocket(sServerListen);


	//////////////////////////////////////////////////////////////////////
	// Once all this is initialized, we can finally 
	// start sending() and receiving() ...
	//////////////////////////////////////////////////////////////////////
	do {
			// --------- Thread Synchronization. Start blocking. ---------
			EnterCriticalSection(&boyka_cs);
			//printf("[Listener Thread] Entered the critical section\n");

			// Recv() is blocking, we will be within the critical section 
			// (blocking the snapshot loop) until a TIMEOUT occurs

			//printf("[Debug] Expecting to RECV() something...\n");
			iRecv = recv(sClient, szRecvBuffer, sizeof(szRecvBuffer), 0);
			if (iRecv == SOCKET_ERROR)
			{
				int lastErrCode = WSAGetLastError();

				if (lastErrCode != WSAETIMEDOUT)
				{
					printf("[debug] Error: Recv() failed: %ld\n", lastErrCode);
					DisplayError();
					break;
				}
				else
				{
					// It TIMED OUT, this is somehow expected

					//printf("[Debug] RECV() TIMED OUT\n");
					LeaveCriticalSection(&boyka_cs);
					continue;
				}
			}	


			// Append trailing 0x00 byte to the string.
			szRecvBuffer[iRecv] = '\0';
			
			// Sending back kind of an ACK
			iSend = send(
					sClient,
					szACKBuffer,
					strlen(szACKBuffer),
					0
					);

			if (iSend == SOCKET_ERROR)
			{
				printf("[debug] Error: Send() failed: %ld\n", WSAGetLastError());
				DisplayError();
				break;
			}
			
			// DO SOMETHING with the bytes you just received :)
			unsigned int procData = ProcessIncomingData(szRecvBuffer);
			
			// TODO: Decide how to handle this...
			if(procData != BOYKA_PACKET_PROCESSED)
				printf("[debug] Oooppss! BoykaCommunication: Error processing packet.\n");


			// --------- Thread Synchronization. Stop blocking. ---------
			// NOTE: since the system is FAIR to all threads, I assume releasing the CS
			// will schedule the other thread (since it requested access before)
			// Source: "Windows via C/C++", 5th edition
			LeaveCriticalSection(&boyka_cs);
			
	} while(1);


	// Cleanup
	closesocket(sClient);
	WSACleanup();

	return 0;
}


unsigned int
ProcessIncomingData(char *szBuffer)
{
	// What's BoykaMonitor saying?
	// It parses the incoming string and accordingly instruct:
	//	1) to log the last packet, in case it resulted in an exception
	//	2) to restore the process state (send the next packet)
	char msgAV[] = "Access violation detected!";
	char msgSO[] = "Stack overflow detected!";
	char msgInitial[] = "Connection to console established!";


	////////////////////////////////////////////////////////////////////
	// Check the messages from BoykaMonitor and act accordingly
	if(strcmp(szBuffer, msgAV) == 0)
	{
		// access violation
		printf("-[ Access Violation detected ]-\n");
		printf("String test case: '%s'\n", testCase.szStringCase);
		printf("Integer test case: %08x\n", testCase.iIntegerCase);
	}
	else if(strcmp(szBuffer, msgAV) == 0)
	{
		// stack exhaustion
		printf("-[ Stack Exhaustion detected ]-\n");
		printf("String test case: '%s'\n", testCase.szStringCase);
		printf("Integer test case: %08x\n", testCase.iIntegerCase);
	}
	else if(strcmp(szBuffer, msgInitial) == 0)
	{
		// Just the initial message
		printf("%s\n", msgInitial);
	}
	else
	{
		// WTF is this?
		printf("[x]Received unknown message from BoykaMonitor: %s\n", szBuffer);
	}



	return BOYKA_PACKET_PROCESSED;
}