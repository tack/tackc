/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "Tack.h"
#include "TackUtil.h"

uint8_t* tackTackGetPublicKey(uint8_t* tack) {
    return tack; }

uint8_t tackTackGetMinGeneration(uint8_t* tack) {
    return *(tack + TACK_PUBKEY_LENGTH); }
	
uint8_t tackTackGetGeneration(uint8_t* tack) {
    return *(tack + TACK_PUBKEY_LENGTH + 1); }

uint32_t tackTackGetExpiration(uint8_t* tack) {
    return ptou32(tack + TACK_PUBKEY_LENGTH + 2); }

uint8_t* tackTackGetTargetHash(uint8_t* tack) {
    return tack + TACK_PUBKEY_LENGTH + 6; }

uint8_t* tackTackGetSignature(uint8_t* tack) {
    return tack + TACK_PUBKEY_LENGTH + 6 + TACK_HASH_LENGTH; }

TACK_RETVAL tackTackSyntaxCheck(uint8_t* tack)
{
    if (tackTackGetGeneration(tack) < tackTackGetMinGeneration(tack))
        return TACK_ERR_BAD_GENERATION;
    return TACK_OK;
}

TACK_RETVAL tackTackGetKeyFingerprint(uint8_t* tack, 
                                      char output[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1], 
                                      TackCryptoFuncs* crypto)
{
    return tackGetKeyFingerprint(tackTackGetPublicKey(tack), output, crypto);
}


#define TACK_TAG "tack_sig"
#define TACK_TAG_LENGTH 8
#define TACK_SIGDATA_LENGTH TACK_TAG_LENGTH + TACK_LENGTH - TACK_SIG_LENGTH

TACK_RETVAL tackTackVerifySignature(uint8_t* tack, TackCryptoFuncs* crypto)
{
    uint8_t signedData[TACK_SIGDATA_LENGTH];
    memcpy(signedData, TACK_TAG, TACK_TAG_LENGTH);
    memcpy(signedData + TACK_TAG_LENGTH, tack, TACK_LENGTH - TACK_SIG_LENGTH);
    
    return crypto->verify(tackTackGetPublicKey(tack), 
                          tackTackGetSignature(tack), 
                          signedData, TACK_SIGDATA_LENGTH);
}


TACK_RETVAL tackTackProcess(uint8_t* tack,
                            uint8_t keyHash[TACK_HASH_LENGTH],
                            uint8_t* minGeneration,
                            uint32_t currentTime,
                            TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;

    /* Check generation, expiration, target_hash */
    if (tackTackGetGeneration(tack) < *minGeneration)
        return TACK_ERR_REVOKED_GENERATION;

    if (tackTackGetExpiration(tack) < currentTime)
        return TACK_ERR_EXPIRED_EXPIRATION;

    if (memcmp(tackTackGetTargetHash(tack), keyHash, TACK_HASH_LENGTH) != 0)
        return TACK_ERR_MISMATCHED_TARGET_HASH;

    /* Verify signature (implicitly checks public_key) */
    if ((retval=tackTackVerifySignature(tack, crypto)) != TACK_OK)
        return retval;
    
    /* Update min_generation if tack's value is larger */
    if (tackTackGetMinGeneration(tack) > *minGeneration)
        *minGeneration = tackTackGetMinGeneration(tack);

    return TACK_OK;
}
