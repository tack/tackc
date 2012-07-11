/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_TACK_H__
#define __TACK_TACK_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"
#include "TackFingerprints.h"
#include "TackCryptoFuncs.h"

#define TACK_LENGTH 166

uint8_t* tackTackGetPublicKey(uint8_t* tack);
uint8_t  tackTackGetMinGeneration(uint8_t* tack);
uint8_t  tackTackGetGeneration(uint8_t* tack);
uint32_t tackTackGetExpiration(uint8_t* tack);
uint8_t* tackTackGetTargetHash(uint8_t* tack);
uint8_t* tackTackGetSignature(uint8_t* tack);

TACK_RETVAL tackTackSyntaxCheck(uint8_t* tack);
TACK_RETVAL tackTackGetKeyFingerprint(uint8_t* tack, 
                            char output[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1], 
                            TackCryptoFuncs* crypto);
TACK_RETVAL tackTackVerifySignature(uint8_t* tack, TackCryptoFuncs* crypto);

TACK_RETVAL tackTackProcess(uint8_t* tack,
                            uint8_t keyHash[TACK_HASH_LENGTH],
                            uint8_t* minGeneration,
                            uint32_t currentTime,
                            TackCryptoFuncs* crypto);


#ifdef __cplusplus
}
#endif
#endif


