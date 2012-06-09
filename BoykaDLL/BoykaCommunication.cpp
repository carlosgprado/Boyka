//////////////////////////////////////////////////////////////////////////////////////
// Communications Module.
//
// This implements the TCP components that allow
// Server and Client side debuggers to talk to each other.
//
// NOTE: This code is in a separate file for readability/maintenance sake
// 		 but actually is part of BoykaDLL.cpp
//////////////////////////////////////////////////////////////////////////////////////

#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>

#define BOYKA_BUFLEN 1024	// 1K would do :)



///////////////////////////////////////////////////////////////////
// BoykaConsole Listener Module.
// This will launch a recv() infinite loop.
// TODO: recv() is blocking, maybe implement it in a separate thread?
///////////////////////////////////////////////////////////////////

DWORD WINAPI ListenerThread(LPVOID lpParam)
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
			ProcessIncomingData(szRecvBuffer);

	} while(iRecv > 0)

	}
	// Cleanup
	closesocket(sClient);
	WSACleanup();

	return 0;
}


VOID
ProcessIncomingData(char *szBuffer)
{
	// What's BoykaMonitor saying?
	// It parses the incoming string and accordingly instruct:
	//	1) to log the last packet, in case it resulted in an exception
	//	2) to restore the process state (send the next packet)

	return 0;
}