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
			ExitProcess(1);
		}

	printf("[Debug - PrivEsc] Setting SeDebugPrivilege on this process...\n");

	if(SetPrivilege(hThisProcess, SE_DEBUG_NAME, TRUE))
		printf("[Debug - PrivEsc] Successfully set SeDebugPrivilege :)\n");
	else {
		printf("[Debug - PrivEsc] Unable to set SeDebugPrivilege :(\n");
		DisplayError();
		ExitProcess(1);
	}



	/////////////////////////////////////////////////////////////////////////////////////
	// Look for a process to hook
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
					ExitProcess(1);
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
			ExitProcess(1);
		}


	/////////////////////////////////////////////////////////////////////////////////////
	// Attach to the process
	/////////////////////////////////////////////////////////////////////////////////////
	BOOL bAttach = DebugActiveProcess(Pid);
	if(bAttach == 0) {
		printf("[Debug - Attach] Couldn't attach to %s.\n", szExeName);
		DisplayError();
		ExitProcess(1);
	} else {
		printf("[Debug - Attach] Attached to %s!\n", szExeName);
	}

	/////////////////////////////////////////////////////////////////////////////////////
	// NOTE: Set a breakpoint at both ends of the fuzzing execution path.
	// For example, around the authentication process. The first breakpoint triggers
	// the snapshot process, the second restores the snapshot.
	/////////////////////////////////////////////////////////////////////////////////////
	BYTE originalByteBegin	= SetBreakpoint(hProcess, dwBeginLoopAddress);
	BYTE originalByteExit	= SetBreakpoint(hProcess, dwExitLoopAddress);


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

	/////////////////////////////////////////////////////////////////////////////////////
	// Here starts the action :)
	/////////////////////////////////////////////////////////////////////////////////////
	BoykaDebugLoop(hProcess, originalByteBegin);


	// Cleanup
	CloseHandle(hProcess);
	CloseHandle(hThisProcess);

	return 0;
}



/////////////////////////////////////////////////////////////////////////////////////
// This implements the actual debugging.
// Code in response of diverse events (breakpoint hit, exception raised, etc.)
// We already attached to the process and set breakpoints in main() function
/////////////////////////////////////////////////////////////////////////////////////
void
BoykaDebugLoop(HANDLE hProcess, BYTE originalByteBegin)
{
	unsigned int iterationNumber = 0;
	DEBUG_EVENT de = {0};
	DWORD dwContinueStatus = DBG_CONTINUE;


	while(1)
	{
		WaitForDebugEvent(&de, INFINITE);

		switch (de.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			switch(de.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:
				//////////////////////////////////////////////////////////////////////////////////////
				// At the begin of loop	-> restore bp and save process state (EIP = next instruction)
				// At the end of loop	-> restore process state (back to start of the loop)
				//////////////////////////////////////////////////////////////////////////////////////

				if(de.u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)dwExitLoopAddress)
					{
						printf("[Debug - DebugLoop] Hit RestoreProcessState Breakpoint!\n");
						printf("[Debug - DebugLoop] *** Iteration Number: %u ***\n", iterationNumber++);
						dwContinueStatus = RestoreProcessState(de.dwProcessId);	// debuggee's PID
					}
				else if(de.u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)dwBeginLoopAddress)
					{
						printf("[Debug - DebugLoop] Hit SaveProcessState Breakpoint!\n");
						// TODO: Here goes some kind of blocking function. Don't restore 
						// the breakpoint until you get the green light from the server :)
						RestoreBreakpoint(hProcess, de.dwThreadId, (DWORD)de.u.Exception.ExceptionRecord.ExceptionAddress, originalByteBegin);
						dwContinueStatus = SaveProcessState(de.dwProcessId);
					}

				break;

			default:	/* Unhandled exception. Just do some logging right now */
				if(de.u.Exception.dwFirstChance)
					{
						printf(
								"First chance exception at %x, exception-code: 0x%08x\n",
								de.u.Exception.ExceptionRecord.ExceptionAddress,
								de.u.Exception.ExceptionRecord.ExceptionCode
								);
					}

				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}

			break;  // This is the end of "case EXCEPTION_DEBUG_EVENT"

		// We are only interested in exceptions. The rest aren't processed (for now)
		// Just return DBG_EXCEPTION_NOT_HANDLED and continue
		default:
			dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
			break;
		} // End of outer switch (Event Code)

		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	} // End of while loop
}



/////////////////////////////////////////////////////////////////////////////////////
// Rather self explanatory :)
/////////////////////////////////////////////////////////////////////////////////////
BYTE
SetBreakpoint(HANDLE hProcess, DWORD dwAddress)
{
	BYTE originalByte;
	BYTE bpInstruction = 0xCC;

	BOOL bBPReadOK = ReadProcessMemory(
			hProcess,
			(void*)dwAddress,
			&originalByte,
			1,	// ONE BYTE to rule them all
			NULL
			);

	if(!bBPReadOK)
		{
			printf("[Debug - Set BP] Error reading the original byte at intended breakpoint address.\n");
			DisplayError();
		}

	// Replace the original byte with { INT 3 }

	BOOL bBPWriteOK = WriteProcessMemory(
			hProcess,
			(void*)dwAddress,
			&bpInstruction,
			1,
			NULL
			);

	if(!bBPWriteOK)
		{
			printf("[Debug - Set BP] Error writing {INT 3} at intended breakpoint address.\n");
			DisplayError();
		}
	else {
			printf("[Debug - Set BP] Substituted 0x%x with 0x%x at 0x%08x.\n", originalByte, bpInstruction, dwAddress);
	}

	FlushInstructionCache(	// In case instruction has been cached by CPU
			hProcess,
			(void*)dwAddress,
			1
			);

	return originalByte;	// 1 means cool
}



/////////////////////////////////////////////////////////////////////////////////////
// Rather self explanatory :)
/////////////////////////////////////////////////////////////////////////////////////
int
RestoreBreakpoint(HANDLE hProcess, DWORD dwThreadId, DWORD dwAddress, BYTE originalByte)
{
	CONTEXT thContext;
	thContext.ContextFlags = CONTEXT_ALL;
	HANDLE ThreadHandle = OpenThread(
			THREAD_ALL_ACCESS,
			FALSE,
			dwThreadId
			);

	GetThreadContext(ThreadHandle, &thContext);
	// move back EIP one byte
	thContext.Eip--;
	SetThreadContext(ThreadHandle, &thContext);

	// Revert the original byte
	BOOL bBPRestoreOK = WriteProcessMemory(
			hProcess,
			(void*)dwAddress,
			&originalByte,
			1,
			NULL
			);

	if(!bBPRestoreOK)
		{
			printf("[Debug - Restore BP] Error restoring original byte.\n");
			DisplayError();
		}
	else {
			printf("[Debug - Restore BP] Wrote back 0x%x to 0x%08x.\n", originalByte, dwAddress);
	}

	FlushInstructionCache(	// In case instruction has been cached by CPU
			hProcess,
			(void*)dwAddress,
			1
			);


	return 1;	// This means cool
}



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
	for(int i=0; i < threadSnapshot.size(); i++)
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
	for(int i=0; i < threadSnapshot.size(); i++)
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
	for(int i=0; i < threadRestore.size(); i++)
		{
			for(int j=0; j < threadSnapshot.size(); j++)
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

	for (int i=0; i < memorySnapshot.size(); i++)
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
	for(int i=0; i < threadRestore.size(); i++)
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
