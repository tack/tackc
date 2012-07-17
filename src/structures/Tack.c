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
