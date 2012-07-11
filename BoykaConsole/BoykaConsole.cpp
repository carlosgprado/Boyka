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

#include <Windows.h>
#include <vector>
#include <string>
#include <TlHelp32.h>
#include "Boyka.h"


using std::string;
using std::vector;



extern CRITICAL_SECTION	boyka_cs;

// Needed for the process snapshot/restore
// TODO: There must be a better way that make this global...

extern vector<THOBJECT>	threadSnapshot; // Thread information at process snapshot
extern vector<VMOBJECT>	memorySnapshot;	// Memory blocks (and metadata) at process snaphot



int
main(int argc, char *argv[])
{
	HANDLE hThisProcess = 0;
	BOYKAPROCESSINFO	bpiCon;

	if(argc < 2)
	{
		printf("Usage: %s <victim process name>\n", argv[0]);
		return 1;
	}
	
	char *victimSoftware = argv[1];


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

	
	// This snippet must be here (after Priv Escalation) since
	// it tries to get an ALL_ACCESS handle to the process.
	bpiCon = FindProcessByName(victimSoftware);
	if(bpiCon.Pid == 0)
	{
		printf("\n[debug] Process %s NOT found. Is it running?\n", victimSoftware);
		return 1;
	}


	char *DirPath = new char[MAX_PATH];
	char *FullPath = new char[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, DirPath);
	sprintf_s(FullPath, MAX_PATH, "%s\\%s", DirPath, DLL_NAME);

	printf("[Debug - DLL inject] Proceding with DLL injection now...\n");


	/////////////////////////////////////////////////////////////////////////////
	// DLL injection sexiness starts here
	/////////////////////////////////////////////////////////////////////////////
	LPVOID LoadLibraryAddr =
			(LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	LPVOID PathStringAlloc = (LPVOID)VirtualAllocEx(bpiCon.hProcess, NULL, strlen(FullPath),
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); // allocate memory for the path string.

	WriteProcessMemory(bpiCon.hProcess, PathStringAlloc, FullPath,
			strlen(FullPath), NULL); // write the string to the victim's memory space.

	HANDLE hRemoteThread = CreateRemoteThread(bpiCon.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddr,
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


	if(bpiCon.Pid == 0)
		{
			printf("[Debug - Main] Couldn't find process %s\n", victimSoftware);
			printf("[Debug - Main] Is the victim running?\n");
			return 1;
		}

	// Initialize CriticalSection (for thread synchronization)
	InitializeCriticalSection(&boyka_cs);


	/////////////////////////////////////////////////////////////////////////////////////
	// The LISTENER Thread
	/////////////////////////////////////////////////////////////////////////////////////

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
	Sleep(3000);	// One second

	/////////////////////////////////////////////////////////////////////////////////////
	// The DEBUGGING Thread
	/////////////////////////////////////////////////////////////////////////////////////
	HANDLE	hConsoleDebuggingThread;
	DWORD	dwConsoleDebuggingThread;

	hConsoleDebuggingThread = CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE) ConsoleDebuggingThread,	//  LPTHREAD_START_ROUTINE
			&bpiCon,				//	LPVOID? lpParam
			0,
			&dwConsoleDebuggingThread
			);


	if(hConsoleDebuggingThread != NULL)
		printf("[debug] Debugging Thread launched successfully! :)\n");
	else
		{
			printf("[debug] Failed to launch Debugging Thread. Aborting.\n");
			DisplayError();
			return 1;
		}


	/////////////////////////////////////////////////////////////////////////////////////
	// We want main() to let the threads live...
	/////////////////////////////////////////////////////////////////////////////////////
	HANDLE	hTreads[] = {hListenerThread, hConsoleDebuggingThread};

	WaitForMultipleObjects(2, hTreads, TRUE, INFINITE);


	// Cleanup
	DeleteCriticalSection(&boyka_cs);

	CloseHandle(bpiCon.hProcess);
	CloseHandle(hThisProcess);

	return 0;
}

