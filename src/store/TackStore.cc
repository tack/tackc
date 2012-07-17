/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include "TackStore.h"
#include "TackProcessing.h"

void TackStore::setCryptoFuncs(TackCryptoFuncs* newCrypto) {crypto=newCrypto;}
TackCryptoFuncs* TackStore::getCryptoFuncs() {return crypto;}

void TackStore::setRevocationStore(TackStore* newRevocationStore) {
    revocationStore = newRevocationStore;}
bool TackStore::getRevocationStore() {return revocationStore;}

TackStore::TackStore():crypto(NULL),revocationStore(this) {}


TACK_RETVAL TackStore::process(TackProcessingContext* ctx,
                               std::string name,
                               uint32_t currentTime,
                               bool doPinActivation)
{
    TACK_RETVAL retval = TACK_ERR, resultRetval = TACK_ERR;

    TackPin pinStruct;
    TackPin* pin = NULL;
    uint8_t minGeneration = 0;
    TackPin pinOut;
    TACK_RETVAL activationRetval = TACK_ERR;
    uint8_t minGenerationOut = 0;
    std::string tackFingerprint;

    /* Get the relevant pin, if any */
    if ((retval=getPin(name, &pinStruct)) < TACK_OK)
        return retval;
    if (retval == TACK_OK)
        pin = &pinStruct;

    /* Get the key's stored minGeneration, if any */
    if (ctx->tack) {
        tackFingerprint = std::string(ctx->tackFingerprint);
        if ((retval=getMinGeneration(tackFingerprint, &minGeneration)) < TACK_OK)
            return retval;
    }

    /* Process everything */
    if ((retval=tackProcessStore(ctx, currentTime, pin, minGeneration, 
                                 &activationRetval, &pinOut, &minGenerationOut, 
                                 crypto)) < TACK_OK)
        return retval;
    resultRetval = retval;

    // Handle any revocation
    if (revocationStore && minGenerationOut > minGeneration) {
        revocationStore->setMinGeneration(tackFingerprint, minGenerationOut);
    }
    // Handle pin activation results
    if (doPinActivation) {
        // If a new pin was created (perhaps replacing an old one)
        if (activationRetval == TACK_OK_NEW_PIN) {
            if ((retval=newPin(name, &pinOut)) != TACK_OK)
                return retval;
        }
        // Or if a pin's activation period (endTime) was extended
        else if (activationRetval == TACK_OK_UPDATE_PIN) {
            if ((retval=updatePin(name, pinOut.endTime)) != TACK_OK)
                return retval;
        }
        // Or if an inactive pin was deleted
        else if (activationRetval == TACK_OK_DELETE_PIN) {
            if ((retval=deletePin(name)) != TACK_OK)
                return retval;
        }
    }
    return resultRetval;
}
