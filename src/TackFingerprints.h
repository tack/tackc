/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_FINGERPRINTS_H__
#define __TACK_FINGERPRINTS_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"
#include "TackCryptoFuncs.h"

#define TACK_KEY_FINGERPRINT_TEXT_LENGTH 29

TACK_RETVAL tackGetKeyFingerprint(uint8_t publicKey[TACK_PUBKEY_LENGTH], 
                                  char output[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1], 
                                  TackHashFunc func);

#ifdef __cplusplus
}
#endif
#endif


