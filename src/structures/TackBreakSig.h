/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_BREAK_SIG_H__
#define __TACK_BREAK_SIG_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"
#include "TackCryptoFuncs.h"
#include "TackFingerprints.h"

#define TACK_BREAKSIG_LENGTH 128

uint8_t* tackBreakSigGetPublicKey(uint8_t* breakSig);
uint8_t* tackBreakSigGetSignature(uint8_t* breakSig);

TACK_RETVAL tackBreakSigGetKeyFingerprint(uint8_t* breakSig, 
                                          char output[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1], 
                                          TackCryptoFuncs* crypto);
TACK_RETVAL tackBreakSigVerifySignature(uint8_t* breakSig, TackCryptoFuncs* crypto);


#ifdef __cplusplus
}
#endif
#endif
