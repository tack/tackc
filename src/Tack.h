/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_TACK_H__
#define __TACK_TACK_H__

#include <stdint.h>
#include "TackRetval.h"
#include "TackCryptoFuncs.h"

#define TACK_LENGTH 166

typedef struct {
    uint8_t publicKey[TACK_PUBKEY_LENGTH]; 
    uint8_t minGeneration;
    uint8_t generation;
    uint32_t expiration;
    uint8_t targetHash[TACK_HASH_LENGTH];
    uint8_t signature[TACK_SIG_LENGTH]; 
        
    uint8_t dataForVerify[TACK_LENGTH - TACK_SIG_LENGTH];
} Tack;

TACK_RETVAL tackTackInit(Tack* tack, uint8_t* data);
TACK_RETVAL tackTackVerifySignature(Tack* tack, VerifyFunc func);

#endif
