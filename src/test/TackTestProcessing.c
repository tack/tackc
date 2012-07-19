/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackProcessing.h"
#include "TackExtension.h"
#include "Tack.h"
#include "TackUtil.h"
#include "TackTest.h"


char Epem[] = "\
-----BEGIN TACK EXTENSION-----\
AAAAAQ==\
-----END TACK EXTENSION-----";
/*
activation_flag = enabled
 */

char ET1pem[] = "\
-----BEGIN TACK EXTENSION-----\
ptTsGt8EToRTmpeuY7DhgdMQSuvj2KTYvSUQj/2AnfDN9ms33d3TRmvctMhRpOop\
dTKyIRRsYuYUHQVLyrhHl90AAAFZGkAytktmcnogY+QGbzuVjLCq7ldqXs79lTOZ\
u4h0cx2Vh06geQcpV9a0Hhqgdao+ehk9CUcuA1nOreDpW9coCEcH+NHmONpNgSD9\
NNb/e7vwUH7MNu+SCDdVhMxLJVwHJEEAAAE=\
-----END TACK EXTENSION-----";
/*
key fingerprint = rnx3y.35xdl.hssy4.bop3v.zifgu
min_generation  = 0
generation      = 0
expiration      = 2013-01-01T00:00Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flag = enabled  
 */

char EB1pem[] = "\
-----BEGIN TACK EXTENSION-----\
AACA1Owa3wROhFOal65jsOGB0xBK6+PYpNi9JRCP/YCd8M32azfd3dNGa9y0yFGk\
6il1MrIhFGxi5hQdBUvKuEeX3WNu3E+jrPQANMkeWVYL72HAiHgmQPwACJUXFN4v\
2Yz0dy5JYLPJceMnsXfsFBSImOF8XzupD3SeynaITdarTnUB\
-----END TACK EXTENSION-----";
/*
Breaks key fingerprint  = rnx3y.35xdl.hssy4.bop3v.zifgu
activation_flag = enabled
 */

char EB1T2pem[] = "\
-----BEGIN TACK EXTENSION-----\
poiEksHxiHr4JEozYQW7Ah3x3Kkha/maSELeIEtHUs0SO/8pgKxeE+llsYNqDbb+\
U5u3Garg9Ed+os0fh3cYVSIAAAHJGVMytktmcnogY+QGbzuVjLCq7ldqXs79lTOZ\
u4h0cx2Vh1AVAkK48O1W03iKa3xENSWIKFyY+Ai3WW9JIZGr/EMfxwFG8z9EAvEr\
VFVKGuJySQs6vUqRtKjBYG8F/1KaNs0AgNTsGt8EToRTmpeuY7DhgdMQSuvj2KTY\
vSUQj/2AnfDN9ms33d3TRmvctMhRpOopdTKyIRRsYuYUHQVLyrhHl91jbtxPo6z0\
ADTJHllWC+9hwIh4JkD8AAiVFxTeL9mM9HcuSWCzyXHjJ7F37BQUiJjhfF87qQ90\
nsp2iE3Wq051AQ==\
-----END TACK EXTENSION-----";
/*
key fingerprint = vqhrw.sxivq.wyzxx.tguez.6okk2
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
Breaks key fingerprint  = rnx3y.35xdl.hssy4.bop3v.zifgu
activation_flag = enabled
 */

uint8_t tackExtE[2048];
uint32_t tackExtELen;

uint8_t tackExtET1[2048];
uint32_t tackExtET1Len;

uint8_t tackExtEB1[2048];
uint32_t tackExtEB1Len;

uint8_t tackExtEB1T2[2048];
uint32_t tackExtEB1T2Len;

#include <stdio.h>

TACK_RETVAL tackTestProcessInit()
{
    TACK_RETVAL retval;

    char label[] ="TACK EXTENSION";
    retval=tackDePem(label, 
                     (uint8_t*)Epem, strlen(Epem), tackExtE, &tackExtELen);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, 
                     (uint8_t*)ET1pem, strlen(ET1pem), tackExtET1, &tackExtET1Len);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, 
                     (uint8_t*)EB1pem, strlen(EB1pem), tackExtEB1, &tackExtEB1Len);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, 
                     (uint8_t*)EB1T2pem, strlen(EB1T2pem), tackExtEB1T2, &tackExtEB1T2Len);
    return retval;
}

#define ASSERT(x) if (!(x)) return TACK_ERR_ASSERTION;

TACK_RETVAL tackTestProcessWellFormed(TackCryptoFuncs* crypto) {
    
    TACK_RETVAL retval;
    TackProcessingContext ctx;
    uint8_t* keyHash;
    uint8_t* tack;
    uint32_t count=0;
    uint32_t expirationTime;

    TCHECK(tackTestProcessInit());

    tack = tackExtensionGetTack(tackExtET1);
    keyHash = tackTackGetTargetHash(tack);

    /* Test with NULL input */
    TCHECK(tackProcessWellFormed(NULL, 170, keyHash, 123, &ctx, crypto));
    ASSERT(ctx.tackExt == NULL);
    ASSERT(ctx.tack == NULL);
    ASSERT(strlen(ctx.tackFingerprint) == 0);
    ASSERT(ctx.breakSigFlags == 0);

    /* Test normal behavior */
    TCHECK(tackProcessWellFormed(
               tackExtET1, tackExtET1Len, keyHash, 123, &ctx, crypto));
    ASSERT(ctx.tackExt == tackExtET1);
    ASSERT(ctx.tack == tackExtensionGetTack(tackExtET1));
    ASSERT(ctx.breakSigFlags == 0);

    /* Test tack ext lengths (copied code for E, ET1, EB1, EB1T2 */
    /* Test that errors are returned for a range of bad lengths */
    TCHECK(tackProcessWellFormed(tackExtE, tackExtELen, keyHash, 123, &ctx, crypto));
    for (count=0; count < tackExtELen+10; count++) {
        if (count == tackExtELen) continue;
        TCHECK_VAL(tackProcessWellFormed(tackExtE, count, keyHash, 123, &ctx, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    TCHECK(tackProcessWellFormed(tackExtET1, tackExtET1Len, keyHash, 123, &ctx, crypto));
    for (count=0; count < tackExtET1Len+10; count++) {
        if (count == tackExtET1Len) continue;
        TCHECK_VAL(tackProcessWellFormed(tackExtET1, count, keyHash, 123, &ctx, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    TCHECK(tackProcessWellFormed(tackExtEB1, tackExtEB1Len, keyHash, 123, &ctx, 
                                 crypto));
    for (count=0; count < tackExtEB1Len+10; count++) {
        if (count == tackExtEB1Len) continue;
        TCHECK_VAL(tackProcessWellFormed(tackExtEB1, count, keyHash, 123, &ctx, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    TCHECK(tackProcessWellFormed(tackExtEB1T2, tackExtEB1T2Len, keyHash, 123, &ctx, 
                                 crypto));
    for (count=0; count < tackExtEB1T2Len+10; count++) {
        if (count == tackExtEB1T2Len) continue;
        TCHECK_VAL(tackProcessWellFormed(tackExtEB1T2, count, keyHash, 123, &ctx, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    /* Test bad tacklength */
    *tackExtET1 += 1;
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtET1, tackExtET1Len, keyHash, 123, &ctx, crypto),
               TACK_ERR_BAD_TACK_LENGTH);
    *tackExtET1 -= 1;
    
    /* Test bad breaksigs length */
    /* Modify the low-order byte of the 2-byte length to be non-multiple of 128 */
    tackExtEB1T2[2+TACK_LENGTH]++;
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtEB1T2, tackExtEB1T2Len, keyHash, 123, &ctx, crypto),
               TACK_ERR_BAD_BREAKSIGS_LENGTH);
    tackExtEB1T2[2+TACK_LENGTH]--;
    /* Modify the high-order byte of the 2-byte length to be 4 (=9 break sigs)  */
    tackExtEB1T2[1+TACK_LENGTH]=4;
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtEB1T2, tackExtEB1T2Len, keyHash, 123, &ctx, crypto),
               TACK_ERR_BAD_BREAKSIGS_LENGTH);
    tackExtEB1T2[1+TACK_LENGTH]=0;

    /* Test bad activation flag */
    tackExtET1[tackExtET1Len-1]+=1; /* 1->2 */
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtET1, tackExtET1Len, keyHash, 123, &ctx, crypto),
               TACK_ERR_BAD_ACTIVATION_FLAG);
    tackExtET1[tackExtET1Len-1]-=1;

    /* Test bad generation (mingeneration > generation) */
    tackExtET1[65]++;
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtET1, tackExtET1Len, keyHash, 123, &ctx, crypto),
               TACK_ERR_BAD_GENERATION);
    tackExtET1[65]--;

    /* Test good/bad expiration */
    tack = tackExtensionGetTack(tackExtET1);
    expirationTime = tackTackGetExpiration(tack);

    TCHECK(tackProcessWellFormed(
               tackExtET1, tackExtET1Len, keyHash, expirationTime-1, &ctx, crypto));
    
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtET1, tackExtET1Len, keyHash, expirationTime, &ctx, crypto),
               TACK_ERR_EXPIRED_EXPIRATION);
    
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtET1, tackExtET1Len, keyHash, expirationTime+1, &ctx, crypto),
               TACK_ERR_EXPIRED_EXPIRATION);
    
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtET1, tackExtET1Len, keyHash, 0xFFFFFFFF, &ctx, crypto),
               TACK_ERR_EXPIRED_EXPIRATION);

    /* Test bad targetHash */
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtET1, tackExtET1Len, keyHash+1, 123, &ctx, crypto),
               TACK_ERR_MISMATCHED_TARGET_HASH);

    /* Test bad signature */
    tackExtET1[160]++;
    TCHECK_VAL(tackProcessWellFormed(
                   tackExtET1, tackExtET1Len, keyHash, 123, &ctx, crypto),
        TACK_ERR_BAD_SIGNATURE);
    tackExtET1[160]--;

    return TACK_OK;
}

TACK_RETVAL tackTestProcessStore(TackCryptoFuncs* crypto) {
    
    TACK_RETVAL retval;
    TackProcessingContext ctxET1, ctxEB1, ctxEB1T2, nullCtx;
    uint8_t* keyHash;
    uint8_t* tack;
    uint32_t currentTime;
    TackPin pin, pinOut;
    uint8_t minGeneration;
    uint8_t minGenerationOut;
    TACK_RETVAL activationRetval;
    char fingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];


    TCHECK(tackTestProcessInit());

    tack = tackExtensionGetTack(tackExtET1);
    keyHash = tackTackGetTargetHash(tack);
    tackTackGetKeyFingerprint(tack, fingerprint, crypto);

    /* Prepare context for ET1, EB1, EB1T2 */
    TCHECK(tackProcessWellFormed(
               tackExtET1, tackExtET1Len, keyHash, 123, &ctxET1, crypto));

    TCHECK(tackProcessWellFormed(
               tackExtEB1, tackExtEB1Len, keyHash, 123, &ctxEB1, crypto));

    TCHECK(tackProcessWellFormed(
               tackExtEB1T2, tackExtEB1T2Len, keyHash, 123, &ctxEB1T2, crypto));

    memset(&nullCtx, 0, sizeof(TackProcessingContext));

    currentTime=123;
    minGeneration=0;
    activationRetval = TACK_ERR;

    /* Test none -> none (UNPINNED) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&nullCtx, currentTime, NULL, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    
    /* Test none -> inactive (UNPINNED) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime, NULL, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(pinOut.fingerprint, fingerprint) == 0);
    ASSERT(pinOut.minGeneration == 0);
    ASSERT(pinOut.initialTime == currentTime);
    ASSERT(pinOut.endTime == 0);
    memcpy(&pin, &pinOut, sizeof(TackPin));

    /* Test inactive pin -> active pin (UNPINNED) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+100, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);
    ASSERT(pinOut.endTime == currentTime+200);
    pin.endTime = pinOut.endTime;

    /* Test active pin -> active (ACCEPTED) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+101, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_ACCEPTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);
    ASSERT(pinOut.endTime == currentTime+202);
    pin.endTime = pinOut.endTime;

    /* Test active pin -> active (REJECTED, nonmatching tack) */
    memset(&pinOut, 0, sizeof(TackPin));
    ctxET1.tackFingerprint[0]++; /* r to s */
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+102, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_REJECTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    ctxET1.tackFingerprint[0]--; /* s back to r */
    
    /* Test active pin -> active (REJECTED, no tack) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&nullCtx, currentTime+102, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_REJECTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);

    /* Test active pin -> active/extended (UNPINNED) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+1000, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);
    ASSERT(pinOut.endTime == currentTime+2000);
    pin.endTime = pinOut.endTime;

    /* Test active pin (REVOKED GENERATION, minGen=1) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+1000, &pin, 1, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_ERR_REVOKED_GENERATION);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);

    /* Test inactive pin (REVOKED GENERATION, minGen=255) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+10000, &pin, 255, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_ERR_REVOKED_GENERATION);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);

    /* Test inactive -> deleted (because no tack) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&nullCtx, currentTime+10000, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_DELETE_PIN);

    /* Test inactive -> new/different pin (because nonmatching tack) */
    memset(&pinOut, 0, sizeof(TackPin));
    ctxET1.tackFingerprint[0]++; /* r to s */
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+10000, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(pinOut.fingerprint, ctxET1.tackFingerprint) == 0);
    ASSERT(pinOut.minGeneration == 0);
    ASSERT(pinOut.initialTime == currentTime+10000);
    ASSERT(pinOut.endTime == 0);

    /* OK rewinding back in time, recall that pin is active to currentTime+2002*/
    /* Let's try some break sigs! */
    /* Test inactive -> deleted (because no tack) */

    /* Test active -> breaksig (no new pin) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxEB1, currentTime, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);

    /* Test prev. case, but different minGeneration */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxEB1, currentTime, &pin, 255, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);

    /* Test inactive -> deleted (even with break sig, inactives should be deleted!) */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxEB1, currentTime+1000000, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_DELETE_PIN);

    
    /* OK let's try a breaksig along with a new tack! */

    /* Test active -> breaksig -> new inactive */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxEB1T2, currentTime, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(pinOut.fingerprint, ctxEB1T2.tackFingerprint) == 0);
    ASSERT(pinOut.minGeneration == 0);
    ASSERT(pinOut.initialTime == currentTime);
    ASSERT(pinOut.endTime == 0);

    /* Test inactive -> breaksig -> new inactive */
    memset(&pinOut, 0, sizeof(TackPin));
    TCHECK_VAL(tackProcessStore(&ctxEB1T2, currentTime+100000, &pin, 0, 
                                &activationRetval, &pinOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(pinOut.fingerprint, ctxEB1T2.tackFingerprint) == 0);
    ASSERT(pinOut.minGeneration == 0);
    ASSERT(pinOut.initialTime == currentTime+100000);
    ASSERT(pinOut.endTime == 0);

    /* TBD: minGen testing */

    /* TBD: activation flag testing */

    return TACK_OK;
}
