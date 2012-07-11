/////////////////////////////////////////////////////////////////////////////////////
// BoykaSystem.cpp
//
// This module contains functions dealing with system operations.
// The snapshotting (save and restore process state) is implemented here.
// Some other auxiliary functions to, for example elevate our privileges,
// are included here as well.
//
/////////////////////////////////////////////////////////////////////////////////////

#undef UNICODE

#include <Windows.h>
#include <vector>
#include <string>
#include <TlHelp32.h>
#include "Boyka.h"


using namespace std;


// Some global objects
vector<THOBJECT>	threadSnapshot;
vector<VMOBJECT>	memorySnapshot;


/////////////////////////////////////////////////////////////////////////////////////
// SaveProcessState()
//
// Desc: This method has been ripped off from Paimei's PyDBG
// It takes a memory & context snapshot of the debuggee.
/////////////////////////////////////////////////////////////////////////////////////

int
SaveProcessState(int pid)
{
	unsigned int cursor = 0;
	SYSTEM_INFO si;



	/////////////////////////////////////////////////////////////////////////////////////
	// IMPORTANT: SUSPEND ALL THREADS *BEFORE* DOING ANYTHING
	/////////////////////////////////////////////////////////////////////////////////////
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);


	// Retrieve a list of threads system wide
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if(hThreadSnap == INVALID_HANDLE_VALUE)
		{
			printf("[Debug - Save Proc] Couldn't take a handle Snapshot.\n");
			DisplayError();
			ExitProcess(1);
		} else {
			//printf("[Debug - Save Proc] Successfully got a Handle (CreateToolhelp32Snapshot)\n");
		}


	// Retrieve information about the first thread and exit if error
	if(!Thread32First(hThreadSnap, &te32))
		{
			printf("[Debug - Save Proc] Error enumerating Threads.\n");
			DisplayError();
			CloseHandle(hThreadSnap);
			ExitProcess(1);
		}


	while(Thread32Next(hThreadSnap, &te32))
		{
			if(te32.th32OwnerProcessID == pid)
				{
					// Get Thread Handles and store them in a vector
					HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, NULL, te32.th32ThreadID);
					THOBJECT thObject;
					thObject.th32ThreadID = te32.th32ThreadID;
					thObject.thHandle = threadHandle;
					threadSnapshot.push_back(thObject);
					SuspendThread(threadHandle);
				}
		}


	printf("[Debug - Save Proc] Found (and suspended) %d threads\n", threadSnapshot.size());

	// All threads must be suspended now. Let's go.
	printf("[Debug - Save Proc] Taking debuggee snapshot (mem & cpu state)...\n");

	// Save the threads CONTEXT (cpu registers, flags, etc.)
	for(unsigned int i=0; i < threadSnapshot.size(); i++)
		{
			CONTEXT threadContext;
			threadContext.ContextFlags = CONTEXT_ALL;
			GetThreadContext(threadSnapshot[i].thHandle, &threadContext);
			threadSnapshot[i].thContext = threadContext;
			printf("[Debug - Save Proc] Context for Thread ID %u saved\n", threadSnapshot[i].th32ThreadID);
		}



	// All thread contexts saved. Moving on to the memory.
	// First I need a process handle (via OpenProcess)
	HANDLE hProcess = OpenProcess(
				PROCESS_ALL_ACCESS,	// I may need to relax this :)
				FALSE,
				pid
				);

	if(!hProcess)
		{
			printf("[Debug - Save Proc] Error getting process handle\n");
			DisplayError();
			ExitProcess(1);
		}



	// Retrieving some system info for later
	GetSystemInfo(&si);

	while(cursor < (unsigned int)si.lpMaximumApplicationAddress)
		{
			VMOBJECT mem;

			try
			{
				VirtualQueryEx(	// Check the memory block protections
						hProcess,
						(void *)cursor,
						&(mem.mbi),
						sizeof(MEMORY_BASIC_INFORMATION)
						);
			}
			catch(int e)
			{
				printf("[Debug - Save Proc] Exception %d ocurred at VirtualQueryEx()\n", e);
				printf("[Debug - Save Proc] Skipping this memory chunk");
				cursor += 4096; // somehow arbitrary
				continue;
			}

			// TODO: Check if the MEM_IMAGE condition is necessary
			// (packed? self-modifying executable?)
			if((mem.mbi.State != MEM_COMMIT) || (mem.mbi.State == MEM_IMAGE))
				{
					cursor += mem.mbi.RegionSize;
					continue;
				}

			// It's not necessary to save pages with the following attributes:
			// PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS
			// Ugly construction, i miss Python :)
			if((mem.mbi.Protect & PAGE_READONLY) ||
					(mem.mbi.Protect & PAGE_EXECUTE_READ) ||
					(mem.mbi.Protect & PAGE_GUARD) ||
					(mem.mbi.Protect & PAGE_NOACCESS))
				{
					cursor += mem.mbi.RegionSize;
					continue;
				}

			// If all checks have resulted OK, let's save the memory region.
			// First reserve some place to save it.
			mem.data = VirtualAlloc(
					NULL,		// I don't care where
					mem.mbi.RegionSize,
					MEM_COMMIT,
					PAGE_READWRITE
					);

			if(mem.data == NULL)
				{
					printf("[Debug - Save Proc] Failed to allocate a memory chunk\n");
					DisplayError();
					printf("[Debug - Save Proc] Skipping this memory chunk");
					cursor += mem.mbi.RegionSize;
					continue;
				}

			// Read memory and write it to our previous allocated chunk.
			BOOL rpmSuccess = ReadProcessMemory(
					hProcess,
					(LPCVOID)cursor,
					mem.data,
					mem.mbi.RegionSize,
					NULL	// I don't care for the nr. of bytes read now.
					);

			if(rpmSuccess == FALSE)
				{
					printf("[Debug - Save Proc] Failed to save a memory chunk (0x%08x)\n", cursor);
					DisplayError();
					printf("[Debug - Save Proc] Skipping this memory chunk");
					cursor += mem.mbi.RegionSize;
					continue;
				} else {
					// printf("[Debug - Save Proc] Saved memory chunk at 0x%08x\n", cursor);
				}


			memorySnapshot.push_back(mem);
			cursor += mem.mbi.RegionSize;
		}

	// All data has been (hopefully) successfully saved.

	printf("[Debug - Save Proc] Memory SNAPSHOTED :)\n");
	printf("[Debug - Save Proc] Saved %d memory chunks\n", memorySnapshot.size());


	// At the end we must to resume all threads.
	for(unsigned int i=0; i < threadSnapshot.size(); i++)
		ResumeThread(threadSnapshot[i].thHandle);


	CloseHandle(hThreadSnap);

	return DBG_CONTINUE; // This means cool :)
}



/////////////////////////////////////////////////////////////////////////////////////
// RestoreProcessState()
//
// Desc: Copies the saved chunks back to the victim address space. After that it
// restores the threads and their contexts
/////////////////////////////////////////////////////////////////////////////////////
int
RestoreProcessState(int pid)
{
	vector<THOBJECT>	threadRestore;	// Thread information at this point

	/////////////////////////////////////////////////////////////////////////////////////
	// IMPORTANT: SUSPEND ALL THREADS *BEFORE* DOING ANYTHING
	/////////////////////////////////////////////////////////////////////////////////////
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);


	// Retrieve a list of threads system wide
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if(hThreadSnap == INVALID_HANDLE_VALUE)
		{
			printf("[Debug - Restore Proc] Couldn't take a handle Snapshot.\n");
			DisplayError();
			ExitProcess(1);
		} else {
			//printf("[Debug - Restore Proc] Successfully got a Handle (CreateToolhelp32Snapshot)\n");
		}


	// Retrieve information about the first thread and exit if error
	if(!Thread32First(hThreadSnap, &te32))
		{
			printf("[Debug - Restore Proc] Error enumerating Threads.\n");
			DisplayError();
			CloseHandle(hThreadSnap);
			ExitProcess(1);
		}


	while(Thread32Next(hThreadSnap, &te32))
		{
			// Check who's the owner.
			if(te32.th32OwnerProcessID == pid)
				{
					// Get Thread Handles and store them in a vector
					HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, NULL, te32.th32ThreadID);
					THOBJECT newthObject;
					newthObject.th32ThreadID = te32.th32ThreadID;
					newthObject.thHandle = threadHandle;
					threadRestore.push_back(newthObject);
					SuspendThread(newthObject.thHandle);

				}
		}


	printf("[Debug - Restore Proc] Found (and suspended) %d threads\n", threadRestore.size());

	/////////////////////////////////////////////////////////////////////////////////////
	// Threads and CONTEXTS
	// I need to compare the current thread list with the snapshoted one.
	// * if it is new, terminate it.
	// * if the thread doesn't exist anymore create it.
	/////////////////////////////////////////////////////////////////////////////////////

	// This checks: "is the new thread on the old thread list?"
	for(unsigned int i=0; i < threadRestore.size(); i++)
		{
			for(unsigned int j=0; j < threadSnapshot.size(); j++)
				{
					if(threadSnapshot[j].th32ThreadID == threadRestore[i].th32ThreadID)
						{
							// This thread has been there since the snapshot.
							// Check: reuse of handles?
							if (SetThreadContext(threadRestore[i].thHandle, &threadSnapshot[j].thContext) == 0)
								{
									printf("[Debug - Restore Proc] Error restoring context for thread ID %u.\n", threadRestore[i].th32ThreadID);
									DisplayError();
								}
							else {
									printf("[Debug - Restore Proc] Restored Context for thread ID %u.\n", threadRestore[i].th32ThreadID);
							}
							// TODO: Remove common values from both vectors ?
						}
				}

		}


	printf("[Debug - Restore Proc] All thread contexts should have been restored now.\n");

	/////////////////////////////////////////////////////////////////////////////////////
	// Restore debuggee Address Space
	// Copy back the memory chunks.
	/////////////////////////////////////////////////////////////////////////////////////

	// First I need a process handle (via OpenProcess)
	HANDLE hProcess = OpenProcess(
				PROCESS_ALL_ACCESS,	// I may need to relax this :)
				FALSE,
				pid
				);

	if(!hProcess)
		{
			printf("[Debug - Restore Proc] Error getting process handle\n");
			DisplayError();
			ExitProcess(1);
		}
	else {
		printf("[Debug - Restore Proc] Got process handle (ALL ACCESS)\n");
	}

	for (unsigned int i=0; i < memorySnapshot.size(); i++)
		{
			BOOL bRestoredMem = WriteProcessMemory(hProcess,
					memorySnapshot[i].mbi.BaseAddress,
					memorySnapshot[i].data,
					memorySnapshot[i].mbi.RegionSize,
					NULL
					);

			if(bRestoredMem == FALSE)
				{
					printf("[Debug - Restore Proc] Error restoring memory block.\n");
					DisplayError();
				}
		}


	// Don't forget to resume the threads at the end :P
	for(unsigned int i=0; i < threadRestore.size(); i++)
		{
			if(ResumeThread(threadRestore[i].thHandle) == -1)
				printf("[Debug - Restore Proc] Error resuming thread: 0x%x\n", threadRestore[i].th32ThreadID);
		}

	printf("[Debug - Restore Proc] All memory snapshots should have been restored now.\n");

	return DBG_CONTINUE; // This is cool
}



/////////////////////////////////////////////////////////////////////////////////////
// SetPrivilege()
//
// Desc: Auxiliary function. You need to set SeDebugPrivilege in order to
// open the process with OPEN_ALL_ACCESS privs.
/////////////////////////////////////////////////////////////////////////////////////
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp = {0};
	LUID luid;
	DWORD cb = sizeof(TOKEN_PRIVILEGES);

	if(!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) // finds LUID for privilege
		{
			printf("[Debug - Priv Esc] Error (LookupPrivilegeValue)");
			DisplayError();
			return FALSE;
		}

	// Get current privilege setting.
	tp.PrivilegeCount			= 1;
	tp.Privileges[0].Luid		= luid;

	if(bEnablePrivilege)
		{
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		}
	else {
			tp.Privileges[0].Attributes = 0;
	}

	AdjustTokenPrivileges(
			hToken,
			FALSE,
			&tp,
			cb,
			NULL,
			NULL
			);

	if(GetLastError() != ERROR_SUCCESS)
		{
			printf("[Debug - Priv Esc] Error (AdjustTokenPrivileges)\n");
			DisplayError();
			return FALSE;
		}


	return TRUE;
}



/////////////////////////////////////////////////////////////////////////////////////
// Look for a process using the executable name.
// Returns a BOYKAPROCESSINFO structure.
/////////////////////////////////////////////////////////////////////////////////////

BOYKAPROCESSINFO
FindProcessByName(char *szExeName)
{
	BOYKAPROCESSINFO bpi;
	// Structure initialization
	bpi.hProcess = NULL;
	bpi.Pid = 0;
	bpi.szExeName = (char *)malloc(BOYKA_BUFLEN);

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32); // initialization.

	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	BOOL bProcess = Process32First(hTool32, &pe32);

	if(bProcess == TRUE)
	{
		while((Process32Next(hTool32, &pe32)) == TRUE)
		{
			if(strcmp(pe32.szExeFile, szExeName) == 0)
			{
				// Found. Populate the struct.
				strncpy(bpi.szExeName, pe32.szExeFile, sizeof(pe32.szExeFile));
				bpi.Pid = pe32.th32ProcessID;

				printf("[Debug - FindProcessByName] Found %s\n", bpi.szExeName);
				printf("[Debug - FindProcessByName] PID: %d\n", bpi.Pid);


				if((bpi.hProcess = OpenProcess(PROCESS_ALL_ACCESS,
						FALSE, bpi.Pid)) == NULL)
					{
						printf("Couldn't open a handle to %s\n", bpi.szExeName);
						DisplayError();
						printf("ABORTING.");
						ExitProcess(1);
					}
				else
					printf("[Debug - FindProcessByName] Got an ALL_ACCESS handle to process.\n");


			} // if strcmp... closing bracket
		} // while closing bracket
	}
	// Cleanup
	CloseHandle(hTool32);

	return bpi;
}



/////////////////////////////////////////////////////////////////////////////////////
// Just a little nice auxiliary function.
// Allows for verbose debug info regarding errors.
/////////////////////////////////////////////////////////////////////////////////////
void DisplayError()
{
	LPTSTR MessageBuffer;
	DWORD dwBufferLength;

	dwBufferLength = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			GetLastError(),
			GetSystemDefaultLangID(),
			(LPTSTR) &MessageBuffer,
			0,
			NULL
			);

	if(dwBufferLength)
		printf("[Debug] Error %u: %s\n", GetLastError(), MessageBuffer);

}
