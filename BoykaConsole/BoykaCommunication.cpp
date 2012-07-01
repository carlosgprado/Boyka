//////////////////////////////////////////////////////////////////////////////////////
// Communications Module.
//
// This implements the TCP components that allow
// Server and Client side debuggers to talk to each other.
//////////////////////////////////////////////////////////////////////////////////////

#include <winsock.h>
#include <stdio.h>
#include "Boyka.h"

#pragma comment(lib, "ws2_32.lib")


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
		printf("[debug] Bound to 0.0.0.0:1337\n");

	// SETSOCKOPTIONS
	// I don't want recv() to block until something is received.
	// Instead of this, a TIMEOUT will be set for the case no exception
	// occurred on the server side (no feedback)
	timeval tv;
	tv.tv_usec = 500000;	// microseconds
	
	int sockOptRes = setsockopt(sServerListen, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
	if(sockOptRes == SOCKET_ERROR)
		printf("[debug - setsockopt] Recv() Timeout couldn't be set.\n");
	else
		printf("[debug - setsockopt] Recv() Timeout set to %u microseconds.\n", tv.tv_usec);
	

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

	// I don't need the server socket anymore
	closesocket(sServerListen);


	//////////////////////////////////////////////////////////////////////
	// Once all this is initialized, we can finally 
	// start sending() and receiving() ...
	//////////////////////////////////////////////////////////////////////
	do {
			// --------- Thread Synchronization. Start blocking. ---------
			EnterCriticalSection(&boyka_cs);

			// Recv() is blocking, we will be within the critical section 
			// (blocking the snapshot loop) until a TIMEOUT occurs
			iRecv = recv(sClient, szRecvBuffer, sizeof(szRecvBuffer), 0);
			if (iRecv == SOCKET_ERROR)
			{
				printf("[debug] Error: Recv() failed: %ld\n", WSAGetLastError());
				printf("iRecv: %d\n", iRecv);
				DisplayError();
				break;
			}

			// Append trailing 0x00 byte to the string.
			if(iRecv < 0) iRecv = 0;
			szRecvBuffer[iRecv] = '\0';
			
			// Sending back kind of an ACK
			iSend = send(
					sClient,
					szACKBuffer,
					sizeof(szACKBuffer),
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
			
	} while(iRecv > 0);


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

	printf("[debug] ProcessIncomingData() called.\n");

	return BOYKA_PACKET_PROCESSED;
}