/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include "TackRetval.h"

const char* tackRetvalString(TACK_RETVAL retval)
{
    switch (retval) {
    case TACK_OK: return "OK";
    case TACK_OK_NOT_FOUND: return "OK NOT FOUND";
    case TACK_OK_INCOMPLETE_WRITE: return "OK INCOMPLETE WRITE";
    case TACK_OK_ACCEPTED: return "OK ACCEPTED";
    case TACK_OK_REJECTED: return "OK REJECTED";
    case TACK_OK_UNPINNED: return "OK UNPINNED";
    case TACK_OK_DELETE_PIN: return "OK DELETE PIN";
    case TACK_OK_UPDATE_PIN: return "OK UPDATE PIN";
    case TACK_OK_NEW_PIN: return "OK NEW PIN";
    case TACK_ERR: return "GENERIC ERROR";
    case TACK_ERR_BAD_GENERATION: return "BAD GENERATION";
    case TACK_ERR_BAD_ACTIVATION_FLAGS: return "BAD ACTIVATION FLAGS";
    case TACK_ERR_BAD_PUBKEY: return "BAD PUBKEY";    
    case TACK_ERR_BAD_TACKS_LENGTH: return "BAD TACKS LENGTH";
    case TACK_ERR_BAD_TACKEXT_LENGTH: return "BAD TACKEXT LENGTH";
    case TACK_ERR_BAD_SIGNATURE: return "BAD SIGNATURE";
    case TACK_ERR_CRYPTO_FUNC: return "CRYPTO FUNC";
    case TACK_ERR_ASSERTION: return "ASSERTION";
    case TACK_ERR_MISMATCHED_TARGET_HASH: return "MISMATCHED TARGET HASH";
    case TACK_ERR_REVOKED_GENERATION: return "REVOKED GENERATION";
    case TACK_ERR_EXPIRED_EXPIRATION: return "EXPIRED EXPIRATION";
    case TACK_ERR_EQUAL_TACK_KEYS: return "TACK_ERR_EQUAL_TACK_KEYS";
    case TACK_ERR_CORRUPTED_STORE: return "CORRUPTED STORE";
    case TACK_ERR_BAD_PEM: return "BAD PEM";
    case TACK_ERR_BAD_BASE64: return "BAD BASE64";
    case TACK_ERR_UNDERSIZED_BUFFER: return "UNDERSIZED BUFFER";
    case TACK_ERR_BAD_PINLIST: return "BAD PINLIST";
    case TACK_ERR_BAD_FINGERPRINT: return "BAD FINGERPRINT";
    default: return "uknown error?!";
    }
}	
