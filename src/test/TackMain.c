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
"  test"
"  help\n"
"\n");
}

void exitError(const char* errStr)
{
	printf("ERROR: %s\n", errStr);
	printUsage();
	exit(-1);	
}

TACK_RETVAL test()
{
    TackCryptoFuncs* crypto = NULL;
#ifdef TACKC_OPENSSL
    crypto = tackOpenSSL;
#endif
#ifdef TACKC_NSS
    crypto = tackNss;
#endif
    
    TACK_RETVAL retval;
    
    retval=tackTestProcessWellFormed(crypto);
    printf("TEST PROCESS WELLFORMED = %s\n", tackRetvalString(retval));
    
    retval=tackTestProcessStore(crypto);
    printf("TEST PROCESS STORE = %s\n", tackRetvalString(retval));

#ifdef __cplusplus
    retval=tackTestStore(crypto);
    printf("TEST STORE = %s\n", tackRetvalString(retval));
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
        return test();
    }    
    return retval;
}	
