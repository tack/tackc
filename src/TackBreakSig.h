/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_BREAK_SIG_H__
#define __TACK_BREAK_SIG_H__

#include <stdint.h>
#include "TackRetval.h"
#include "TackCryptoFuncs.h"

#define TACK_BREAK_SIG_LENGTH 128

typedef struct {
    uint8_t publicKey[TACK_PUBKEY_LENGTH]; 
    uint8_t signature[TACK_SIG_LENGTH];	
} TackBreakSig;

TACK_RETVAL tackBreakSigInit(TackBreakSig* sig, uint8_t* data);
TACK_RETVAL tackBreakSigVerifySignature(TackBreakSig* sig, VerifyFunc func);

#endif
