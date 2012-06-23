/////////////////////////////////////////////////////////////////////////////////////
// fuzzing.h
//
// Define the test cases to be used for fuzzing.
/////////////////////////////////////////////////////////////////////////////////////

// Header guards are good ;)
#ifndef _FUZZING_BOYKA_H
#define _FUZZING_BOYKA_H


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


#endif	// _FUZZING_BOYKA_H