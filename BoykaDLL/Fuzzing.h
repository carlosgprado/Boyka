/////////////////////////////////////////////////////////////////////////////////////
// Fuzzing.h
//
// Define the test cases to be used for fuzzing.
/////////////////////////////////////////////////////////////////////////////////////

// Header guards are good ;)
#ifndef _FUZZING_BOYKA_H
#define _FUZZING_BOYKA_H


/////////////////////////////////////////////////////////////////////////////////////
// Generator functions prototypes.
/////////////////////////////////////////////////////////////////////////////////////
char*	GetFuzzStringCase(void);
int		GetFuzzIntegerCase(void);
int		RandomInteger(void);
char *	RepeatedToken(char *, unsigned int, BOOL);


/////////////////////////////////////////////////////////////////////////////////////
// Fuzz Test Cases.
/////////////////////////////////////////////////////////////////////////////////////

char* StringFuzzCases[] = {
	/* strings ripped from Sulley */
	"/.../.../.../.../.../.../.../.../.../.../",
	"/../../../../../../../../../../../../etc/passwd",
	"/../../../../../../../../../../../../boot.ini",
	"..:..:..:..:..:..:..:..:..:..:..:..:..:",
	"\\\\*",
	"\\\\?\\",
	RepeatedToken("/\\", 5000, TRUE),
	RepeatedToken("/.", 5000, TRUE),
	"!@#$%%^#$%#$@#$%$$@#$%^^**(()",
	"%01%02%03%04%0a%0d%0aADSF",
	"%01%02%03@%04%0a%0d%0aADSF",
	// "/%00/",
	// "%00/",
	// "%00",
	"%\xfe\xf0%\x01\xff",
	RepeatedToken("%\xfe\xf0%\x01\xff", 20, TRUE),

	/* format strings. */
	RepeatedToken("%n", 100, TRUE),
	RepeatedToken("%n", 500, TRUE),
	RepeatedToken("\"%n\"", 500, TRUE),
	RepeatedToken("%s", 100, TRUE),
	RepeatedToken("%s", 500, TRUE),
	RepeatedToken("\"%s\"", 500, TRUE),

	/* command injection. */
	"|touch /tmp/BOYKA",
	";touch /tmp/BOYKA;",
	"|notepad",
	";notepad;",
	"\nnotepad\n",

	/* SQL injection. */
	"1;SELECT%20*",
	"'sqlattempt1",
	"(sqlattempt2)",
	"OR%201=1",

	/* some binary strings. */
	"\xde\xad\xbe\xef",
	RepeatedToken("\xde\xad\xbe\xef", 10, TRUE),
	RepeatedToken("\xde\xad\xbe\xef", 100, TRUE),
	RepeatedToken("\xde\xad\xbe\xef", 1000, TRUE),

	/* Some long strings
	   TODO: Set other lengths as well */
	RepeatedToken("A", 1000, TRUE),
	RepeatedToken("B", 1000, TRUE),
	RepeatedToken("1", 1000, TRUE),
	RepeatedToken("2", 1000, TRUE),
	RepeatedToken("3", 1000, TRUE),
	RepeatedToken("<", 1000, TRUE),
	RepeatedToken(">", 1000, TRUE),
	RepeatedToken("'", 1000, TRUE),
	RepeatedToken("\"", 1000, TRUE),
	RepeatedToken("/", 1000, TRUE),
	RepeatedToken("\\", 1000, TRUE),
	RepeatedToken("?", 1000, TRUE),
	RepeatedToken("=", 1000, TRUE),
	RepeatedToken("a=", 1000, TRUE),
	RepeatedToken("&", 1000, TRUE),
	RepeatedToken(".", 1000, TRUE),
	RepeatedToken(",", 1000, TRUE),
	RepeatedToken("(", 1000, TRUE),
	RepeatedToken(")", 1000, TRUE),
	RepeatedToken("]", 1000, TRUE),
	RepeatedToken("[", 1000, TRUE),
	RepeatedToken("%", 1000, TRUE),
	RepeatedToken("*", 1000, TRUE),
	RepeatedToken("-", 1000, TRUE),
	RepeatedToken("+", 1000, TRUE),
	RepeatedToken("{", 1000, TRUE),
	RepeatedToken("}", 1000, TRUE),
	RepeatedToken("\x14", 1000, TRUE),
	RepeatedToken("\xFE", 1000, TRUE),
	RepeatedToken("\xFF", 1000, TRUE),

	/* miscellaneous. */
	RepeatedToken("\r\n", 100, TRUE),
	RepeatedToken("<>", 500, TRUE)         // sendmail crackaddr
	};


int IntegerFuzzCases[] = {
	512, 1024, 1500, 2048, 2500,
	3000, 3500, 4096, 5000, 6000,
	8192, 10000, 12000, 14000,
	16384, 18000, 20000, 22000,
	//0x00, 0x10, 0x1000,
	//0x000000FF, 0x0000007F, 0x100,
	//0x0000FFFF, 0x00007FFF,
	//0xFFFFFFFF, 0x7FFFFFFF
	};


#endif	// _FUZZING_BOYKA_H