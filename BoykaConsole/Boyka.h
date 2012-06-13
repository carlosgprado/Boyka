/////////////////////////////////////////////////////////////////////////////////////
// Boyka.h
//
// Definitions and stuff.
/////////////////////////////////////////////////////////////////////////////////////

// Header guards are good
#ifndef BOYKA_H
#define BOYKA_H


#define DLL_NAME "BoykaDLL.dll"
#define VICTIM_SOFTWARE "DWRCC.exe"

/////////////////////////////////////////////////////////////////////////////////////
// Very important stuff
// These two breakpoints define our execution (fuzzing) loop
/////////////////////////////////////////////////////////////////////////////////////
#define dwBeginLoopAddress	0x0040DAC0	// cgp_ArithmeticSender01
#define dwExitLoopAddress	0x0040DC7A	// cgp_ArithmeticSender01+1ba


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

unsigned int ProcessIncomingData(char *)

BOOL SetPrivilege(HANDLE, LPCTSTR, BOOL); // I love MSDN :)
void DisplayError(void);
char* GetFuzzStringCase(void);


/////////////////////////////////////////////////////////////////////////////////////
// Simple GLOBAL vars.
/////////////////////////////////////////////////////////////////////////////////////

// This little thing will allow me to synchronize threads.
CRITICAL_SECTION	boyka_cs;


/////////////////////////////////////////////////////////////////////////////////////
// Custom complex variables.
/////////////////////////////////////////////////////////////////////////////////////

// Virtual Memory Information Object
struct VMOBJECT
{
	MEMORY_BASIC_INFORMATION mbi;
	VOID* data;
};


// Thread Information Object
struct THOBJECT
{
	DWORD	th32ThreadID;
	HANDLE	thHandle;
	CONTEXT	thContext;
};


// Process information (short)
typedef struct
{
	char*	szExeName;
	DWORD	Pid;
	HANDLE	hProcess;
}BOYKAPROCESSINFO;




/////////////////////////////////////////////////////////////////////////////////////
// Fuzz Test Cases.
/////////////////////////////////////////////////////////////////////////////////////

char* StringFuzzCases[] = {
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	"%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",
	"massive p0wnage",
	"It's full of stars..."
	};
	

int IntegerFuzzCases[] = { 
	0x00, 
	0x000000FF, 0x0000007F,
	0x0000FFFF, 0x00007FFF, 
	0xFFFFFFFF, 0x7FFFFFFF
	};


#endif	// BOYKA_H