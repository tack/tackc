/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include "TackRetval.h"

char* tackRetvalString(TACK_RETVAL retval)
{
    switch (retval) {
    case TACK_OK: return "OK";
    case TACK_OK_SIGNATURE_GOOD: return "SIGNATURE GOOD";
    case TACK_ERR: return "GENERIC ERROR";
    case TACK_ERR_BAD_GENERATION: return "BAD GENERATION";
    case TACK_ERR_BAD_ACTIVATION_FLAG: return "BAD ACTIVATION FLAG";
    case TACK_ERR_BAD_PUBKEY: return "BAD PUBKEY";    
    case TACK_ERR_BAD_TACK_LENGTH: return "BAD TACK LENGTH";
    case TACK_ERR_BAD_BREAKSIGS_LENGTH: return "BAD BREAKSIGS LENGTH";
    case TACK_ERR_BAD_TACKEXT_LENGTH: return "BAD TACKEXT LENGTH";
    case TACK_ERR_SIGNATURE_BAD: return "SIGNATURE BAD";
    case TACK_ERR_CRYPTO_FUNC: return "CRYPTO FUNC";
    case TACK_ERR_ASSERTION: return "ASSERTION";
    default: return "uknown error?!";
    }
}	
