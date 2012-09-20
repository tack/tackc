/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <stdio.h>
#include <string.h>
#include "TackFingerprints.h"

char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

/* inLen must be a multiple of 5 bytes (40 bits), and there
   must be space in the out buffer for an 8/5 expansion. */
TACK_RETVAL base32Encode(uint8_t* in, char* out, uint32_t inLen) 
{
    char* outptr = out;
    uint8_t outmask = 0x10;
    uint8_t* inptr = in;
    uint8_t inmask = 0x80;
    uint32_t count;

    if (inLen % 5 != 0)
        return TACK_ERR_ASSERTION;
    
    memset(out, 0, (inLen/5)*8);
    
    /* Fill the out buffer with integers from 0..31 */
    for (count=0; count < inLen*8; count++) {
        if (*inptr & inmask)
            *outptr |= outmask;
        if (outmask == 1) {
            outptr++;
            outmask = 0x10;
        }
        else
            outmask >>= 1;
        if (inmask == 1) {
            inptr++;
            inmask = 0x80;
        }
        else
            inmask >>= 1;
    }

    /* Convert the out buffer to base32 chars */
    for (count=0; count < (uint32_t)(outptr-out); count++) {
        if (out[count] >= 32)
            return TACK_ERR_ASSERTION;
        out[count] = alphabet[(uint8_t)(out[count])];
    }

    return TACK_OK;
}

TACK_RETVAL tackGetKeyFingerprint(uint8_t publicKey[TACK_PUBKEY_LENGTH], 
                                  char output[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1], 
                                  TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t keyHash[TACK_HASH_LENGTH];

    /* Hash the public key */
    if ((retval=crypto->hash(publicKey, TACK_PUBKEY_LENGTH, keyHash)) != TACK_OK)
        return retval;

    return tackGetKeyFingerprintFromHash(keyHash, output);
}

TACK_RETVAL tackGetKeyFingerprintFromHash(uint8_t keyHash[TACK_HASH_LENGTH], 
                                          char output[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1])
{
    TACK_RETVAL retval = TACK_ERR;
    char base32Result[TACK_HASH_LENGTH * 2];
    uint32_t count;

    /* Base32 encode the first 20 bytes of hash result.
       Why 20?  We need to encode the first 125 bits,
       but the base32 encoder works in 40 bit chunks,
       so we round 125 up to 160 bits. */
    if ((retval=base32Encode(keyHash, base32Result, 20)) != TACK_OK)
        return retval;

    /* Split into 5 groups, separated by '.' */
    for (count=0; count < 5; count++) {
        memcpy(output+(count*6), base32Result+(count*5), 5);
        if (count != 4)
            output[5+(count*6)] = '.';
    }
    output[29] = 0;

    return TACK_OK;    
}

TACK_RETVAL tackKeyFingerprintSyntaxCheck(char* fingerprint) {
    uint32_t count;
    char c;
    for (count = 0; count < 29; count ++) {
        c = fingerprint[count];    
        if (count == 5 || count == 11 || count == 17 || count == 23) {
            if (c != '.')
                return TACK_ERR_BAD_FINGERPRINT;
            continue;
        }
        if (c >= 'a' && c <= 'z')
            continue;
        if (c >= '2' && c <= '7')
            continue;
        return TACK_ERR_BAD_FINGERPRINT;
    }
    return TACK_OK;
}

