/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackBreakSig.h"

TACK_RETVAL tackBreakSigInit(TackBreakSig* sig, uint8_t* data, uint32_t len)
{
    if (len != TACK_BREAKSIG_LENGTH)
        return TACK_ERR_BAD_BREAKSIG_LENGTH;

    memcpy(sig->publicKey, data, TACK_PUBKEY_LENGTH); data += TACK_PUBKEY_LENGTH;
    memcpy(sig->signature, data, TACK_SIG_LENGTH); data += TACK_SIG_LENGTH; 
    return TACK_OK;
}

#define TACK_BREAKSIG_TAG "tack_break_sig"
#define TACK_BREAKSIG_TAG_LENGTH 14

TACK_RETVAL tackBreakSigVerifySignature(TackBreakSig* sig, TackVerifyFunc func)
{
    char* tag = TACK_BREAKSIG_TAG;
    return func(sig->publicKey, sig->signature, (uint8_t*)tag, 
                TACK_BREAKSIG_TAG_LENGTH);
}
