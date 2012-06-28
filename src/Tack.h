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
#include "TackCryptoFuncs.h"

#define TACK_LENGTH 166

uint8_t* tackTackGetPublicKey(uint8_t* tack);
uint8_t  tackTackGetMinGeneration(uint8_t* tack);
uint8_t  tackTackGetGeneration(uint8_t* tack);
uint32_t tackTackGetExpiration(uint8_t* tack);
uint8_t* tackTackGetTargetHash(uint8_t* tack);
uint8_t* tackTackGetSignature(uint8_t* tack);

TACK_RETVAL tackTackSyntaxCheck(uint8_t* tack);
TACK_RETVAL tackTackVerifySignature(uint8_t* tack, TackVerifyFunc func);


#ifdef __cplusplus
}
#endif
#endif


