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

#ifdef TACKC_CPP
#include "TackStore.h"
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

	//Tack tack;
	//TackBreakSig sig;
	//TackExtension tackExt;

	uint8_t* tack = inbuf;	
	TACK_RETVAL retval;
	if ((retval = tackTackSyntaxCheck(tack))<0) {
		printf("ERROR INIT'ING TACK: %s\n", tackRetvalString(retval));
    	return TACK_ERR;
	}

#ifdef TACKC_OPENSSL		
 	char fingerprintO[30];
    tackTackGetKeyFingerprint(tack, fingerprintO, tackOpenSSLHashFunc);
    printf("OPENSSL FINGERPRINT: %s\n", fingerprintO);
  	retval = tackTackVerifySignature(tack, tackOpenSSLVerifyFunc);
    printf("OPENSSL VERIFY: %s\n", tackRetvalString(retval));      
#endif
#ifdef TACKC_NSS
 	char fingerprintN[30];
    tackTackGetKeyFingerprint(tack, fingerprintN, tackNssHashFunc);
    printf("NSS FINGERPRINT: %s\n", fingerprintN);  
	retval = tackTackVerifySignature(tack, tackNssVerifyFunc);
    printf("NSS VERIFY: %s\n", tackRetvalString(retval));
#endif
#ifdef TACKC_CPP

    TackStore::KeyRecord kr1, kr2;
    kr1.minGeneration = 0;
    kr2.minGeneration = 7;
    
    TackStore::NameRecord nr1, nr2;
    nr1.keyFingerprint = "g5p5x.ov4vi.dgsjv.wxctt.c5iul";
    nr1.initialTime = 100;
    nr1.activePeriodEnd = 200; 
    
    nr2.keyFingerprint = "quxiz.kpldu.uuedc.j5znm.7mqst";
    nr2.initialTime = 1000;
    nr2.activePeriodEnd = 2000;

    std::string dn1 = "a.com";
    std::string dn2 = "b.com";

    TackStore::KeyRecord kr;
    TackStore::NameRecord nr;
    
    TackStore store;

    // Test addPin and getPin
    if (store.setPin(dn1, kr1, nr1) != TACK_OK)
        printf("ERROR! TackStore retval a\n");
    if (store.setPin(dn2, kr2, nr2) != TACK_OK)
        printf("ERROR! TackStore retval b\n");

    if (store.getPin(dn1, kr, nr) != TACK_OK)
        printf("ERROR! TackStore retval c\n");
    if (kr.minGeneration != kr1.minGeneration || nr.activePeriodEnd != nr1.activePeriodEnd)
        printf("ERROR! TackStore 1\n");

    if (store.getPin(dn2, kr, nr) != TACK_OK)
        printf("ERROR! TackStore retval d\n");
    if (kr.minGeneration != kr2.minGeneration || nr.activePeriodEnd != nr2.activePeriodEnd)
        printf("ERROR! TackStore 2\n");

    // Test getKeyRecord
    if (store.getKeyRecord(nr1.keyFingerprint, kr) != TACK_OK)
        printf("ERROR! TackStore retval e\n");
    if (kr.minGeneration != kr1.minGeneration)
        printf("ERROR! TackStore 3\n");    

    // Test deleteKeyRecord
    if (store.deleteKeyRecord(nr1.keyFingerprint) != TACK_OK)
        printf("ERROR! TackStore retval f\n");

    if (store.getPin(dn1, kr, nr) != TACK_OK_NOT_FOUND)
        printf("ERROR! TackStore retval g %s\n", tackRetvalString(retval));

    printf("TACK STORE OK\n");
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
