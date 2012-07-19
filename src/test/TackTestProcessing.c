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
    TackProcessingContext ctx;
    uint8_t* keyHash;
    uint8_t* tack;
    //uint32_t count=0;
    uint32_t currentTime;
    //uint32_t expirationTime;
    TackPin pin, pinOut;
    uint8_t minGeneration;
    uint8_t minGenerationOut;
    TACK_RETVAL activationRetval;

    TCHECK(tackTestProcessInit());

    tack = tackExtensionGetTack(tackExtET1);
    keyHash = tackTackGetTargetHash(tack);

    /* Test normal behavior */
    TCHECK(tackProcessWellFormed(
               tackExtET1, tackExtET1Len, keyHash, 123, &ctx, crypto));


 
    currentTime=123;
    minGeneration=0;
    activationRetval = TACK_ERR;

    TCHECK(tackProcessStore(&ctx, currentTime, &pin, minGeneration, 
                            &activationRetval, &pinOut, &minGenerationOut, crypto));
    
    return TACK_OK;
}

/*
TACK_RETVAL tackProcessWellFormed(uint8_t* tackExt, uint32_t tackExtLen,
                                  uint8_t keyHash[TACK_HASH_LENGTH],
                                  uint32_t currentTime,
                                  TackProcessingContext* ctx,
                                  TackCryptoFuncs* crypto);


TACK_RETVAL tackProcessStore(TackProcessingContext* ctx,
                             uint32_t currentTime,   
                             TackPin* pin,
                             uint8_t minGeneration,
                             TACK_RETVAL* activationRetval,
                             TackPin* pinOut,
                             uint8_t* minGenerationOut,
                             TackCryptoFuncs* crypto);
*/
