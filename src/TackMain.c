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
#include "TackFingerprints.h"

#ifdef TACKC_OPENSSL
#include "TackOpenSSL.h"
#endif

#ifdef TACKC_NSS
#include "TackNss.h"
#endif

void printUsage()
{
    printf(
"\n"
"commands:\n"
"  test TACK.dat"
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
	if ((retval=tackTackInit(&tack, inbuf, nbytes))<0) {
            printf("ERROR INIT'ING TACK: %s\n", tackRetvalString(retval));
            return TACK_ERR;
        }

        char fingerprint[30];
#ifdef TACKC_OPENSSL
	retval = tackTackVerifySignature(&tack, tackOpenSSLVerifyFunc);
        printf("OPENSSL RESULT: %s\n", tackRetvalString(retval));      
        tackGetKeyFingerprint(tack.publicKey, fingerprint, tackOpenSSLHashFunc);
        printf("OPENSSL FINGERPRINT: %s\n", fingerprint);  
#endif
#ifdef TACKC_NSS
	retval = tackTackVerifySignature(&tack, tackNssVerifyFunc);
        printf("NSS RESULT: %s\n", tackRetvalString(retval));
        tackGetKeyFingerprint(tack.publicKey, fingerprint, tackNssHashFunc);
        printf("NSS FINGERPRINT: %s\n", fingerprint);  
#endif
        return TACK_OK;
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
    }    
	return retval;
}	
