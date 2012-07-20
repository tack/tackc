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

char EBmaxT2pem[] = "\
-----BEGIN TACK EXTENSION-----\
poiEksHxiHr4JEozYQW7Ah3x3Kkha/maSELeIEtHUs0SO/8pgKxeE+llsYNqDbb+\
U5u3Garg9Ed+os0fh3cYVSIAAAHJGVMytktmcnogY+QGbzuVjLCq7ldqXs79lTOZ\
u4h0cx2Vh1AVAkK48O1W03iKa3xENSWIKFyY+Ai3WW9JIZGr/EMfxwFG8z9EAvEr\
VFVKGuJySQs6vUqRtKjBYG8F/1KaNs0EANTsGt8EToRTmpeuY7DhgdMQSuvj2KTY\
vSUQj/2AnfDN9ms33d3TRmvctMhRpOopdTKyIRRsYuYUHQVLyrhHl91jbtxPo6z0\
ADTJHllWC+9hwIh4JkD8AAiVFxTeL9mM9HcuSWCzyXHjJ7F37BQUiJjhfF87qQ90\
nsp2iE3Wq051Q+K1Wl6K4cC6/1T1hfkv/2HiupMdFRAmpiTVGwceHDFhvz6nILFD\
PjtnwEoKdFS3tVSfhDHxeU88i9lrRbs/Us2hpio5Yav8wb5etxZE+cdqzgQQvKSS\
+Q3NmmkJujVa0NIatdBBDcwcLp0vK1aw8fCmVAd6lgop0kCw+7iN92dS7WJ37akd\
cC7LRmyOiaUII4Ij2tgWL/siCIQR8zv65nDioBpeGokWHHDX6ZbU45Ixps0vLmny\
YRAJnUP1iDG9wFkU0t8200ErXq6vARdPWKc+vGc32Ba2252yuVAPgvuJDHui7Nlz\
wgt4W1WAS2nVRkbh6LYfkqA/IkuebjqfIl9zBfsoM7prCjWwgzfaJP0OI+anu2Em\
j42bcwrWR+O75fRoMGhlSNkembL7a9uJfHnJHFRSn3harIae/SZzVB8U1SK8uIKm\
BZuJHSqLmthrJf1LZXKukdDgX6vBdmCrtjiCtps5AGpjju6HpKlrgM9JY6F/r06O\
j9BLf7pXmzfAZ/TwBFCksmsstnJzYso8s64MtjnrWcMAbkmA7xIBeytMLIpLx+0C\
/uDbXF1AeVNr/ytfJdQfTgWEJ173yJPliTC+iWfT9xaCKmkUVt09CSk2hQUq5F5A\
qXKm1KxSLdkTSqsSFb8varMzXYX8HopjwqrSfX9uQ8y7a7e+fSSDf4fEo//ld5aa\
15s5wuhAEO4Ar9dSRuTkCZzXmz49lwY8epbcRd9vb7/R4YcXnS/6ARC+Cdi7OLtn\
4GaOXwGKU+dw6fZ7XEluuTA09Bwpy5UO/zzmuPZLJqfMoVYR+WC4m+bQ1Ri2Adgw\
4rVRSee+hiRQSBx28ZBDvQkqbLo/sByj6U5t0QzEuJnJLWnEtBL4hWhcg2Q+gjRP\
nwy/kyyVXyQ5EcxzONv6Ekzi7J8H9gxZrt0sAjnYTJU6vwM2DBec6l1argyxZ+io\
jhFWcTus5hdX8/EZxGMpayEC5f6xLEyRO7k6fm2GzrM35CwwHjOAO92dBfSjzJz2\
GMm1GBynjPZWOSPsOoDJJVYw4Ag0q9mAu01Wcy3nRWwb5tXRKK3rXRnpm/1AuL35\
Dbd1ZN7Qk1YVbHxGxrwKaGkJnoAtq6Y/yC/1d/CDOpLswWAHWaXt/+U9S0rsKufM\
mQhxL+LVWbu6Iko3HST65GVwz4Rq4M3mz+FY5X+fa0UqAlPMNpds2n0B\
-----END TACK EXTENSION-----";
/*
key fingerprint = vqhrw.sxivq.wyzxx.tguez.6okk2
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
Breaks key fingerprint  = rnx3y.35xdl.hssy4.bop3v.zifgu
Breaks key fingerprint  = cx5lg.epsgt.t7et5.q7zj4.57ljd
Breaks key fingerprint  = zwspz.mjsrj.jryrz.x6zbq.62sga
Breaks key fingerprint  = qaalr.b77je.2g2yh.bqhe5.nd4lh
Breaks key fingerprint  = heoey.swsc7.dvold.qndbh.vyqkv
Breaks key fingerprint  = hlxqj.qj4jr.s53f3.ogpqx.h4hhd
Breaks key fingerprint  = 2kskg.r6ndp.xdaxb.jdj45.dsk6h
Breaks key fingerprint  = he4bj.stary.av3r3.ucirw.uw3np
activation_flag = enabled
*/

char ET1Mpem[] = "\
-----BEGIN TACK EXTENSION-----\
ptTsGt8EToRTmpeuY7DhgdMQSuvj2KTYvSUQj/2AnfDN9ms33d3TRmvctMhRpOop\
dTKyIRRsYuYUHQVLyrhHl93+/wHJGVMytktmcnogY+QGbzuVjLCq7ldqXs79lTOZ\
u4h0cx2Vh/e7IjTdRUscPDW/YTXbTYIyYJCiKXiU3Eq1QPk1wlRhlHTT7W/fm34Z\
nxpC/WiqFu7fv0dP3px8BvJbOpvVHwsAAAE=\
-----END TACK EXTENSION-----";
/*
key fingerprint = rnx3y.35xdl.hssy4.bop3v.zifgu
min_generation  = 254
generation      = 255
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flag = disabled
*/

uint8_t tackExtE[2048];
uint32_t tackExtELen;

uint8_t tackExtET1[2048];
uint32_t tackExtET1Len;

uint8_t tackExtEB1[2048];
uint32_t tackExtEB1Len;

uint8_t tackExtEB1T2[2048];
uint32_t tackExtEB1T2Len;

uint8_t tackExtEBmaxT2[2048]; /* like EB1, but w/more extraneous break sigs*/
uint32_t tackExtEBmaxT2Len;

uint8_t tackExtET1M[2048]; /* like EB1, but w/more extraneous break sigs*/
uint32_t tackExtET1MLen;


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

    retval=tackDePem(label, 
                     (uint8_t*)EBmaxT2pem, strlen(EBmaxT2pem), 
                     tackExtEBmaxT2, &tackExtEBmaxT2Len);

    retval=tackDePem(label, 
                     (uint8_t*)ET1Mpem, strlen(ET1Mpem), 
                     tackExtET1M, &tackExtET1MLen);

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
    TackProcessingContext ctxET1, ctxEB1, ctxEB1T2, ctxEBmaxT2, ctxET1M, nullCtx;
    uint8_t* keyHash;
    uint8_t* tack;
    uint32_t currentTime;
    TackNameRecord nameRecord, nameRecordOut;
    uint8_t minGeneration;
    uint8_t minGenerationOut;
    TACK_RETVAL activationRetval;
    char fingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];


    TCHECK(tackTestProcessInit());

    tack = tackExtensionGetTack(tackExtET1);
    keyHash = tackTackGetTargetHash(tack);
    tackTackGetKeyFingerprint(tack, fingerprint, crypto);

    /* Prepare context for ET1, EB1, EB1T2, EBmaxT2, ET1M */
    TCHECK(tackProcessWellFormed(
               tackExtET1, tackExtET1Len, keyHash, 123, &ctxET1, crypto));

    TCHECK(tackProcessWellFormed(
               tackExtEB1, tackExtEB1Len, keyHash, 123, &ctxEB1, crypto));

    TCHECK(tackProcessWellFormed(
               tackExtEB1T2, tackExtEB1T2Len, keyHash, 123, &ctxEB1T2, crypto));

    TCHECK(tackProcessWellFormed(
               tackExtEBmaxT2, tackExtEBmaxT2Len, keyHash, 123, &ctxEBmaxT2, crypto));

    TCHECK(tackProcessWellFormed(
               tackExtET1M, tackExtET1MLen, keyHash, 123, &ctxET1M, crypto));

    memset(&nullCtx, 0, sizeof(TackProcessingContext));

    currentTime=123;
    minGeneration=0;
    activationRetval = TACK_ERR;

    /* Test none -> none (UNPINNED) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&nullCtx, currentTime, NULL, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);


    /* Test none -> new inactive (UNPINNED) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime, NULL, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(nameRecordOut.fingerprint, fingerprint) == 0);
    ASSERT(nameRecordOut.initialTime == currentTime);
    ASSERT(nameRecordOut.endTime == 0);
    memcpy(&nameRecord, &nameRecordOut, sizeof(TackNameRecord));

    /* (prev case, but FLAG DISABLED */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    *tackExtensionPostBreakSigs(tackExtET1) = 0;
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime, NULL, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    *tackExtensionPostBreakSigs(tackExtET1) = 1;

    /* Test inactive pin -> active pin (UNPINNED), FLAG DISABLED FIRST */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    *tackExtensionPostBreakSigs(tackExtET1) = 0;
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+100, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    *tackExtensionPostBreakSigs(tackExtET1) = 1;

    /* Test inactive pin -> active pin (UNPINNED) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+100, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);
    ASSERT(nameRecordOut.endTime == currentTime+200);
    nameRecord.endTime = nameRecordOut.endTime;

    /* Test active pin -> active (ACCEPTED), FLAG DISABLED FIRST */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    *tackExtensionPostBreakSigs(tackExtET1) = 0;
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+101, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_ACCEPTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    *tackExtensionPostBreakSigs(tackExtET1) = 1;

    /* Test active pin -> active (ACCEPTED) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+101, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_ACCEPTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);
    ASSERT(nameRecordOut.endTime == currentTime+202);
    nameRecord.endTime = nameRecordOut.endTime;

    /* Test active pin -> active (REJECTED, nonmatching tack), FLAG DISABLED FIRST */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    ctxET1.tackFingerprint[0]++; /* r to s */
    *tackExtensionPostBreakSigs(tackExtET1) = 0;
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+102, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_REJECTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    ctxET1.tackFingerprint[0]--; /* s back to r */
    *tackExtensionPostBreakSigs(tackExtET1) = 1;

    /* Test active pin -> active (REJECTED, nonmatching tack) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    ctxET1.tackFingerprint[0]++; /* r to s */
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+102, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_REJECTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    ctxET1.tackFingerprint[0]--; /* s back to r */
    
    /* Test active pin -> active (REJECTED, no tack) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&nullCtx, currentTime+102, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_REJECTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);

    /* Test active pin -> active/extended (UNPINNED), FLAG DISABLED FIRST */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    *tackExtensionPostBreakSigs(tackExtET1) = 0;
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+1000, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    *tackExtensionPostBreakSigs(tackExtET1) = 1;

    /* Test active nameRecord -> active/extended (UNPINNED) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+1000, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);
    ASSERT(nameRecordOut.endTime == currentTime+2000);
    nameRecord.endTime = nameRecordOut.endTime;

    /* Test active pin (REVOKED GENERATION, minGen=1) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    minGeneration = 1;
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+1000, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_ERR_REVOKED_GENERATION);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    minGeneration = 0;

    /* Test inactive pin (REVOKED GENERATION, minGen=255) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    minGeneration = 255;
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+10000, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_ERR_REVOKED_GENERATION);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    minGeneration = 0;

    /* Test inactive -> deleted (because no tack) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&nullCtx, currentTime+10000, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_DELETE_PIN);

    /* Test inactive -> deleted (because nonmatching tack) FLAG DISABLED FIRST */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    ctxET1.tackFingerprint[0]++; /* r to s */
    *tackExtensionPostBreakSigs(tackExtET1) = 0;
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+10000, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_DELETE_PIN);
    ctxET1.tackFingerprint[0]--; /* r to s */
    *tackExtensionPostBreakSigs(tackExtET1) = 1;

    /* Test inactive -> new/different pin (because nonmatching tack) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    ctxET1.tackFingerprint[0]++; /* r to s */
    TCHECK_VAL(tackProcessStore(&ctxET1, currentTime+10000, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(nameRecordOut.fingerprint, ctxET1.tackFingerprint) == 0);
    ASSERT(nameRecordOut.initialTime == currentTime+10000);
    ASSERT(nameRecordOut.endTime == 0);
    ctxET1.tackFingerprint[0]--; /* r to s */

    /* OK rewinding back in time, recall that pin is active to currentTime+2002*/
    /* Let's try some break sigs! */
    /* Test inactive -> deleted (because no tack) */

    /* Test active -> breaksig (no new pin) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxEB1, currentTime, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);

    /* Test prev. case, but different minGeneration */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    minGeneration = 255;
    TCHECK_VAL(tackProcessStore(&ctxEB1, currentTime, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK);
    minGeneration = 0;

    /* Test inactive -> deleted (even with break sig, inactives should be deleted!) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxEB1, currentTime+1000000, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_DELETE_PIN);

    
    /* OK let's try a breaksig along with a new tack! */

    /* Test active -> breaksig -> new inactive */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxEB1T2, currentTime, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(nameRecordOut.fingerprint, ctxEB1T2.tackFingerprint) == 0);
    ASSERT(nameRecordOut.initialTime == currentTime);
    ASSERT(nameRecordOut.endTime == 0);

    /* Test inactive -> breaksig -> new inactive */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxEB1T2, currentTime+100000, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(nameRecordOut.fingerprint, ctxEB1T2.tackFingerprint) == 0);
    ASSERT(nameRecordOut.initialTime == currentTime+100000);
    ASSERT(nameRecordOut.endTime == 0);

    /* OK let's try an ext with 8 break sigs! */

    /* Test active -> breaksig -> new inactive */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxEBmaxT2, currentTime, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_UNPINNED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_NEW_PIN);
    ASSERT(strcmp(nameRecordOut.fingerprint, ctxEBmaxT2.tackFingerprint) == 0);
    ASSERT(nameRecordOut.initialTime == currentTime);
    ASSERT(nameRecordOut.endTime == 0);

    /* OK, let's try updating a new generation (m254/g255) */

    /* If no key record, minGenerationOut doesn't get updated */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxET1M, currentTime, &nameRecord, NULL, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_ACCEPTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);

    /* If there is a key record, it does */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    TCHECK_VAL(tackProcessStore(&ctxET1M, currentTime, &nameRecord, &minGeneration, 
                                &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
               TACK_OK_ACCEPTED);
    ASSERT(minGenerationOut == 254);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);

    /* If it doesn't update minGeneration (Already 254) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    minGeneration = 254;
    TCHECK_VAL(tackProcessStore(&ctxET1M, currentTime, &nameRecord, &minGeneration, 
                              &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
             TACK_OK_ACCEPTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);

    /* If it doesn't update minGeneration (Already 255) */
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));
    minGeneration = 255;
    TCHECK_VAL(tackProcessStore(&ctxET1M, currentTime, &nameRecord, &minGeneration, 
                              &activationRetval, &nameRecordOut, &minGenerationOut, crypto),
             TACK_OK_ACCEPTED);
    ASSERT(minGenerationOut == 0);
    ASSERT(activationRetval == TACK_OK_UPDATE_PIN);

    return TACK_OK;
}
