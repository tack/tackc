/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "TackRetval.h"
#include "TackExtension.h"
#include "TackOpenSSL.h"

void printUsage()
{
    printf(
"\n"
"commands:\n"
"  help\n"
"\n");
}

void exitError(char* errStr)
{
	printf("ERROR: %s\n", errStr);
	printUsage();
	exit(-1);	
}

TACK_RETVAL test(int argc, char* argv[])
{
	char* ifilename = argv[0];
    FILE* fin=0;
    uint32_t nbytes;    
    uint8_t inbuf[65536];

    if ((fin = fopen(ifilename, "rb")) == 0) {
		exitError("Can't open file");
	}

    memset(inbuf, 0, sizeof(inbuf));
    nbytes = (uint32_t)fread(inbuf, 1, sizeof(inbuf), fin);
    fclose(fin);
    if (nbytes == sizeof(inbuf)) {
		exitError("Input file too big");
 	}

	Tack tack;
	//TackBreakSig sig;
	//TackExtension tackExt;
	TACK_RETVAL retval;
	if ((retval=tackTackInit(&tack, inbuf))<0)
		return retval;	
	return tackTackVerifySignature(&tack, tackOpenSSLVerifyFunc);
}

int main(int argc, char* argv[]) 
{
    TACK_RETVAL retval;
    
    if (argc<2) {
        printUsage();
        return 0;
    }    
    else if (strcmp(argv[1], "help")==0) {
        printUsage();       
        return 0; 
    }    
    else if (strcmp(argv[1], "test")==0) {
        retval = test(argc-2, argv+2);
		printf("RESULT: %s\n", tackRetvalString(retval));
    }    
	return retval;
}	
