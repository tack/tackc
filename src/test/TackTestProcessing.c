/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackProcessing.h"
#include "TackExtension.h"
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

TACK_RETVAL tackTestProcessWellFormed()
{
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
