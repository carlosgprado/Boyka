/////////////////////////////////////////////////////////////////////////////////////
// BoykaMonitor.cpp
//
// SERVER SIDE Fault Monitor.
// It coordinates the attack with the hijacked client.
//
// NOTE: This code is analogous to BoykaConsole (two threads: net and debug)
/////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <Windows.h>
#include <Boyka.h>


int
main(int argc, char *argv[])
{
	BOYKAPROCESSINFO bpiMon;

	if(argc < 2)
	{
		printf("Usage: %s <server process name>\n", argv[0]);
		return 1;
	}
	
	char *serverExeName = argv[1];

	// Find the process (command line argument)
	bpiMon = FindProcessByName(serverExeName);




	/////////////////////////////////////////////////////////////////////////////////////
	// Here starts the action :)
	/////////////////////////////////////////////////////////////////////////////////////
	MonitorDebuggingThread(&bpiMon);


	return 0;
}





