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

#define TACK_BREAKSIG_TAG "tack_break_sig"
#define TACK_BREAKSIG_TAG_LENGTH 14

TACK_RETVAL tackBreakSigVerifySignature(uint8_t* breakSig, TackVerifyFunc func)
{
    return func(tackBreakSigGetPublicKey(breakSig),
                tackBreakSigGetSignature(breakSig), 
                (uint8_t*)TACK_BREAKSIG_TAG, 
                TACK_BREAKSIG_TAG_LENGTH);
}
