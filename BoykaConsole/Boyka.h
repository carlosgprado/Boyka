/////////////////////////////////////////////////////////////////////////////////////
// Boyka.h
//
// Definitions and stuff.
/////////////////////////////////////////////////////////////////////////////////////

// Header guards are good ;)
#ifndef _BOYKA_H
#define _BOYKA_H

#include <Windows.h>

#define DLL_NAME "BoykaDLL.dll"

/////////////////////////////////////////////////////////////////////////////////////
// Very important stuff
// These two breakpoints define our execution (fuzzing) loop
/////////////////////////////////////////////////////////////////////////////////////
#define dwBeginLoopAddress	0x004115C8
#define dwExitLoopAddress	0x0041161A

#define dwDetouredFunctionAddress	0x00411720

/////////////////////////////////////////////////////////////////////////////////////
// IPC related defines.
/////////////////////////////////////////////////////////////////////////////////////
#define FULL_MAP_NAME	"Local\\BoykaFileMap"
#define MAP_SIZE		65536
#define VIEW_OFFSET		0
#define VIEW_SIZE		1024

/////////////////////////////////////////////////////////////////////////////////////
// Miscelaneous.
/////////////////////////////////////////////////////////////////////////////////////
#define Use_wprintf_Instead_Of_printf printf	// don't ask. Some dumb error relating CeLib.h
#define BOYKA_BUFLEN 1024	// 1K would do :)
#define BOYKA_PACKET_PROCESSED	0

/////////////////////////////////////////////////////////////////////////////////////
// Custom complex variables.
/////////////////////////////////////////////////////////////////////////////////////

// Virtual Memory Information Object
typedef struct
{
	MEMORY_BASIC_INFORMATION mbi;
	VOID* data;
} VMOBJECT;

// Thread Information Object
typedef struct
{
	DWORD	th32ThreadID;
	HANDLE	thHandle;
	CONTEXT	thContext;
} THOBJECT;

// Process information (short)
typedef struct
{
	char*	szExeName;
	DWORD	Pid;
	HANDLE	hProcess;
} BOYKAPROCESSINFO;

/////////////////////////////////////////////////////////////////////////////////////
// Custom function declarations.
/////////////////////////////////////////////////////////////////////////////////////
PBYTE CreateMessageServer(void);
PBYTE MessagingClient(void);

DWORD WINAPI ListenerThread(LPVOID);
void ConsoleDebuggingThread(LPVOID);
void MonitorDebuggingThread(LPVOID);

BYTE SetBreakpoint(HANDLE, DWORD);
int RestoreBreakpoint(HANDLE, DWORD, DWORD, BYTE);

BOYKAPROCESSINFO FindProcessByName(char *);
int SaveProcessState(int);
int RestoreProcessState(int);

unsigned int ProcessIncomingData(char *);

BOOL SetPrivilege(HANDLE, LPCTSTR, BOOL); // I love MSDN :)
void DisplayError(void);
char* GetFuzzStringCase(void);

unsigned int LogExceptionAccessViolation(void);
unsigned int LogExceptionStackOverflow(void);

int CommunicateToConsole(SOCKET, char *);


#endif	// _BOYKA_H