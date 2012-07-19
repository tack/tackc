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
#include "TackProcessing.h"
#include "TackUtil.h"
#include "TackTest.h"

#ifdef TACKC_OPENSSL
#include "TackOpenSSL.h"
#endif

#ifdef TACKC_NSS
#include "TackNss.h"
#endif

#ifdef TACKC_CPP
#include "TackStoreDefault.h"
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

void exitError(const char* errStr)
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

    TackCryptoFuncs* crypto = NULL;
#ifdef TACKC_OPENSSL
    crypto = tackOpenSSL;
#endif
#ifdef TACKC_NSS
    crypto = tackNss;
#endif
    
    TACK_RETVAL retval;
    
    retval=tackTestProcessWellFormed(crypto);
    printf("TEST WELLFORMED = %s\n", tackRetvalString(retval));
    
    retval=tackTestProcessStore(crypto);
    printf("TEST STORE = %s\n", tackRetvalString(retval));


#ifdef TACKC_CPP

    uint8_t outbuf[2048];
    uint32_t outbufLen;
    char label[] ="TACK EXTENSION";
    retval=tackDePem(label, inbuf, nbytes, outbuf, &outbufLen);

    uint8_t* tackExt = outbuf;
    uint32_t tackExtLen = outbufLen;
    
    TackStoreDefault store;
    store.setCryptoFuncs(tackOpenSSL);
    
    uint32_t currentTime = 123;

    uint8_t* tack = NULL;
    uint8_t* targetHash = NULL;

    tack = tackExtensionGetTack(tackExt);
    if (tack) {
        targetHash = tackTackGetTargetHash(tack);
    }
    
    TackProcessingContext ctx;
    retval = tackProcessWellFormed(tackExt, tackExtLen, targetHash,
                                   currentTime, &ctx, tackOpenSSL);
    printf("Well formed retval = %s\n", tackRetvalString(retval));

    retval = store.process(&ctx, "alpha.com",
                           currentTime, true);
    printf("retval = %s\n", tackRetvalString(retval));

    retval = store.process(&ctx, "alpha.com",
                           currentTime+100, true);
    printf("retval = %s\n", tackRetvalString(retval));

    retval = store.process(&ctx, "alpha.com",
                           currentTime+101, true);
    printf("retval = %s\n", tackRetvalString(retval));

    retval = store.process(&ctx, "alpha.com",
                           currentTime+1000, true);
    printf("retval = %s\n", tackRetvalString(retval));

    retval = store.process(&ctx, "alpha.com",
                           currentTime+1001, true);
    printf("retval = %s\n", tackRetvalString(retval));

    retval = store.process(&ctx, "alpha.com",
                           currentTime+1002, true);
    printf("retval = %s\n", tackRetvalString(retval));


    printf("store dump = \n%s\n", store.getStringDump().c_str());
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
