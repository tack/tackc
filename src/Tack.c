/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "Tack.h"
#include "TackUtil.h"


TACK_RETVAL tackTackInit(Tack* tack, uint8_t* data)
{
    memcpy(tack->dataForVerify, data, TACK_LENGTH - TACK_SIG_LENGTH);       

    memcpy(tack->publicKey, data, 64); data += 64;
    tack->minGeneration = *data++;
    tack->generation = *data++;
    tack->expiration = ptou32(data); data += 4;
    memcpy(tack->targetHash, data, 32); data += 32;
    memcpy(tack->signature, data, 64); data += 64;  
        
    if (tack->generation < tack->minGeneration)
        return TACK_ERR_BAD_GENERATION;

    return TACK_OK;
}

#define TACK_TAG "tack_sig"
#define TACK_TAG_LENGTH 8
#define TACK_SIGDATA_LENGTH TACK_TAG_LENGTH + TACK_LENGTH - TACK_SIG_LENGTH

TACK_RETVAL tackTackVerifySignature(Tack* tack, VerifyFunc func)
{
    char* tag = TACK_TAG;
    uint8_t data[TACK_SIGDATA_LENGTH];
    uint8_t* p = data;
    memcpy(p, tag, TACK_TAG_LENGTH); p += TACK_TAG_LENGTH;
    memcpy(p, tack->dataForVerify, TACK_LENGTH - TACK_SIG_LENGTH);
    return func(tack->publicKey, tack->signature, data, TACK_SIGDATA_LENGTH);
}
