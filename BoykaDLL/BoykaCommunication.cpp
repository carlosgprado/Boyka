//////////////////////////////////////////////////////////////////////////////////////
// Communications Module.
//
// This implements the TCP components that allow
// Server and Client side debuggers to talk to each other.
//
//////////////////////////////////////////////////////////////////////////////////////

#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include "Boyka.h"



///////////////////////////////////////////////////////////////////
// BoykaConsole Listener Module.
// This will launch a recv() infinite loop.
// TODO: recv() is blocking, maybe implement it in a separate thread?
///////////////////////////////////////////////////////////////////

DWORD WINAPI 
ListenerThread(LPVOID lpParam)
{
	// This function will be executed in a separate thread.

	UNREFERENCED_PARAMETER(lpParam);
	SOCKET		sServerListen, sClient;
	struct		sockaddr_in localaddr;
	HANDLE		hThread;
	DWORD		dwThreadId;
	int			iSize, iRecv, iSend;
	char		szRecvBuffer[BOYKA_BUFLEN];
	char*		szACKBuffer = "ALL_OK_NEXT_ONE";


	sServerListen = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sServerListen == SOCKET_ERROR)
	{
		OutputDebugString("[debug] Error: Can't load WinSock\n");
		closesocket(sServerListen);
		WSACleanup();
		return 1;
	}

	localaddr.sin_addr.s_addr = htonl(INADDR_ANY);	// Listens in all interfaces
	localaddr.sin_family = AF_INET;
	localaddr.sin_port = htons(1337);				// what else? :)

	if (bind(sServerListen, (struct sockaddr *)&localaddr,
			sizeof(localaddr)) == SOCKET_ERROR)
	{
		OutputDebugString("[debug] Error: Can't bind\n");
		closesocket(sServerListen);
		WSACleanup();
		return 1;
	}
	else
		OutputDebugString("[debug] Bound to 0.0.0.0:1337\n");


	// TODO: Blocking shit. Rewrite with non-blocking version?
	if(listen(sServerListen, 5) == SOCKET_ERROR)
	{
		OutputDebugString("[debug] Error: Listen failed (%d)\n", WSAGetLastError());
		closesocket(sServerListen);
		WSACleanup();
		return 1;
	}


	// NULL because I don't care about the connecting client address
	sClient = accept(sServerListen, NULL, NULL);
	if (sClient == INVALID_SOCKET)
	{
		OutputDebugString("[debug] Error: accept failed\n");
		closesocket(sServerListen);
		WSACleanup();
		return 1;
	}

	//////////////////////////////////////////////////////////////////////
	// Once all this is initialized, we can finally 
	// start sending() and receiving() ...
	//////////////////////////////////////////////////////////////////////
	do {
			// NOTE: Maybe a Sleep() here so that it doesn't leave and enter
			// the critical section continously (deadlock)?

			// --------- Thread Synchronization. Start blocking. ---------
			EnterCriticalSection(&boyka_cs);

			// Recv() is blocking, we will be within the critical section 
			// (blocking the snapshot loop) as long as no packet arrives
			iRecv = recv(sock, szRecvBuffer, BOYKA_BUFLEN, 0);
			if (iRecv == 0)
				break;
			else if (iRecv == SOCKET_ERROR)
			{
				OutputDebugString("[debug] Error: Receive failed\n");
				break;
			}

			// recv'd fine. Append trailing 0x00 byte to the string.
			szRecvBuffer[iRecv] == '\0';
			
			// Sending back kind of an ACK
			iSend = send(
					sock,
					szACKBuffer,
					sizeof(szACKBuffer),
					0
					);

			if (iSend == SOCKET_ERROR)
			{
				OutputDebugString("[debug] Error: Send failed\n");
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
			
	} while(iRecv > 0)

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

	return BOYKA_PACKET_PROCESSED;
}