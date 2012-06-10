/////////////////////////////////////////////////////////////////////////////////////
// BoykaConsole.cpp
//
// This program controls the DLL loading and the snapshot/restore process among others.
// All the heavy lifting is done here.
//
// COMPILE with:
// cl.exe /EHsc BoykaConsole.cpp advapi32.lib
/////////////////////////////////////////////////////////////////////////////////////

#undef UNICODE
#include <vector>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include "Boyka.h"


using std::string;
using std::vector;


// Needed for the process snapshot/restore
// TODO: There must be a better way that make this global...

vector<THOBJECT>	threadSnapshot; // Thread information at process snapshot
vector<VMOBJECT>	memorySnapshot;	// Memory blocks (and metadata) at process snaphot



int
main(int argc, char *argv[])
{
	vector<string>processNames;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32); // initialization.
	HANDLE hThisProcess = 0;
	HANDLE hProcess = 0;
	char* szExeName = NULL;
	DWORD Pid = 0;


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

	printf("[Debug - PrivEsc] Setting SeDebugPrivilege on this process...\n");

	if(SetPrivilege(hThisProcess, SE_DEBUG_NAME, TRUE))
		printf("[Debug - PrivEsc] Successfully set SeDebugPrivilege :)\n");
	else {
		printf("[Debug - PrivEsc] Unable to set SeDebugPrivilege :(\n");
		DisplayError();
		return 1;
	}



	/////////////////////////////////////////////////////////////////////////////////////
	// Look for a process to hook.
	// Gets the Pid and injects the "detouring" DLL.
	/////////////////////////////////////////////////////////////////////////////////////

	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	BOOL bProcess = Process32First(hTool32, &pe32);

	if(bProcess == TRUE)
	{
		while((Process32Next(hTool32, &pe32)) == TRUE)
		{
			processNames.push_back(pe32.szExeFile);
			if(strcmp(pe32.szExeFile, VICTIM_SOFTWARE) == 0)
			{
				// Found. Now we just need to inject the DLL.
				// We will use the CreateRemoteThread method.

				szExeName = pe32.szExeFile;
				Pid = pe32.th32ProcessID;

				printf("[Debug - Search Proc] Found %s\n", szExeName);
				printf("[Debug - Search Proc] PID: %d\n", Pid);

				char *DirPath = new char[MAX_PATH];
				char *FullPath = new char[MAX_PATH];
				GetCurrentDirectory(MAX_PATH, DirPath);
				sprintf_s(FullPath, MAX_PATH, "%s\\%s", DirPath, DLL_NAME);

				printf("[Debug - DLL inject] Proceding with DLL injection now...\n");

				if((hProcess = OpenProcess(PROCESS_ALL_ACCESS,
						FALSE, Pid)) == NULL)
					{
						printf("Couldn't open a handle to %s\n", szExeName);
						DisplayError();
					}


				/////////////////////////////////////////////////////////////////////////////
				// DLL injection sexiness starts here
				/////////////////////////////////////////////////////////////////////////////
				LPVOID LoadLibraryAddr =
						(LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

				LPVOID PathStringAlloc = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(FullPath),
						MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); // allocate memory for the path string.

				WriteProcessMemory(hProcess, PathStringAlloc, FullPath,
						strlen(FullPath), NULL); // write the string to the victim's memory space.

				HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddr,
						PathStringAlloc, NULL, NULL); // new thread, execs LoadLibraryA("PathStringAlloc").

				if(hRemoteThread != NULL) {
					printf("[Debug - DLL inject] Remote Thread created.\n");
					printf("[Debug - DLL inject] DLL %s injected.\n", FullPath);
				} else {
					printf("[Debug - DLL inject] Error! Remote Thread couldn't be created.\n");
					DisplayError();
					return 1;
				}

				// cleanup.
				delete [] DirPath;
				delete [] FullPath;

			} // if closing bracket
		}
	}

	CloseHandle(hTool32);

	if(Pid == 0)
		{
			printf("[Debug - Main] Couldn't find process %s\n", VICTIM_SOFTWARE);
			printf("[Debug - Main] Is the victim running?\n");
			return 1;
		}

	// Initialize CriticalSection (for thread synchronization)
	InitializeCriticalSection(&boyka_cs);


	/////////////////////////////////////////////////////////////////////////////////////
	// The LISTENER Thread
	/////////////////////////////////////////////////////////////////////////////////////

	/* Winsock initialization */
	WSADATA		wsd;
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("[debug] Error: Can't load WinSock");
		return 1;
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

	if(hListenerThread != NULL)
		printf("[debug] Listener Thread launched successfully! :)\n");
	else
		{
			printf("[debug] Failed to launch Listener Thread. Aborting.\n");
			DisplayError();
			return 1;
		}

	// Let's give some time to the listener thread, so it can 
	// EnterCriticalSection for the first time. Rudimentary, I know :)
	Sleep(1000);	// One second

	/////////////////////////////////////////////////////////////////////////////////////
	// The DEBUGGING Thread
	/////////////////////////////////////////////////////////////////////////////////////
	HANDLE	hDebuggingThread;
	DWORD	dwDebuggingThread;

	hDebuggingThread = CreateThread(
			NULL,
			0,
			DebuggingThread,	//  LPTHREAD_START_ROUTINE
			&Pid,				//	LPVOID lpParam
			0,
			&dwDebuggingThread
			);



	/////////////////////////////////////////////////////////////////////////////////////
	// We want main() to let the threads live...
	/////////////////////////////////////////////////////////////////////////////////////
	HANDLE	hTreads[] = {hListenerThread, hDebuggingThread};

	WaitForMultipleObjects(2, &hTreads, TRUE, INFINITE);


	// Cleanup
	DeleteCriticalSection(&boyka_cs);

	CloseHandle(hProcess);
	CloseHandle(hThisProcess);

	return 0;
}

