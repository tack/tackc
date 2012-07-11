/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackBreakSig.h"

uint8_t* tackBreakSigGetPublicKey(uint8_t* breakSig) {
    return breakSig; }
	
uint8_t* tackBreakSigGetSignature(uint8_t* breakSig) {
    return breakSig + TACK_PUBKEY_LENGTH; }

TACK_RETVAL tackBreakSigGetKeyFingerprint(uint8_t* breakSig, 
                                          char output[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1], 
                                          TackCryptoFuncs* crypto)
{
    return tackGetKeyFingerprint(tackBreakSigGetPublicKey(breakSig), output, crypto);
}


#define TACK_BREAKSIG_TAG "tack_break_sig"
#define TACK_BREAKSIG_TAG_LENGTH 14

TACK_RETVAL tackBreakSigVerifySignature(uint8_t* breakSig, TackCryptoFuncs* crypto)
{
    return crypto->verify(tackBreakSigGetPublicKey(breakSig),
                          tackBreakSigGetSignature(breakSig), 
                          (uint8_t*)TACK_BREAKSIG_TAG, 
                          TACK_BREAKSIG_TAG_LENGTH);
}
