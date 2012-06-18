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
		case TACK_ERR_BAD_GENERATION: return "BAD_GENERATION";
		case TACK_ERR_BAD_ACTIVATION_FLAG: return "BAD_ACTIVATION_FLAG";
		case TACK_ERR_BAD_TACK_LENGTH: return "BAD_TACK_LENGTH";
		case TACK_ERR_BAD_BREAKSIGS_LENGTH: return "BAD_BREAKSIGS_LENGTH";
		case TACK_ERR_SIGNATURE_BAD: return "SIGNATURE BAD";
		case TACK_ERR_CRYPTO_FUNC: return "CRYPTO FUNC";
		default: return "uknown error?!";
	}
}	
