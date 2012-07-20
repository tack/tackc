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

    TackNameRecord nameRecordStruct;
    TackNameRecord* nameRecord = NULL;
    uint8_t minGenerationVal = 0;
    uint8_t* minGeneration = NULL;
    TACK_RETVAL activationRetval = TACK_ERR;
    TackNameRecord nameRecordOut;
    uint8_t minGenerationOut = 0;
    std::string tackFingerprint;

    /* Get the relevant name record, if any */
    if ((retval=getNameRecord(name, &nameRecordStruct)) < TACK_OK)
        return retval;
    if (retval == TACK_OK)
        nameRecord = &nameRecordStruct;

    /* Get the key's minGeneration, if any */
    if (ctx->tack) {
        tackFingerprint = std::string(ctx->tackFingerprint);
        if ((retval=getMinGeneration(tackFingerprint, &minGenerationVal)) < TACK_OK)
            return retval;
        if (retval == TACK_OK)
            minGeneration = &minGenerationVal;
    }

    /* Process everything */
    if ((retval=tackProcessStore(ctx, currentTime, nameRecord, minGeneration, 
                                 &activationRetval, &nameRecordOut, &minGenerationOut,
                                 crypto)) < TACK_OK)
        return retval;
    resultRetval = retval;

    // Handle any revocation
    if (revocationStore && minGeneration && minGenerationOut > *minGeneration) {
        if ((retval=revocationStore->setMinGeneration(tackFingerprint, 
                                                      minGenerationOut)) != TACK_OK)
            return retval;
    }
    // Handle pin activation results
    if (doPinActivation) {
        // If a new pin was created (perhaps replacing an old one)
        if (activationRetval == TACK_OK_NEW_PIN) {
            if ((retval=newNameRecord(name, &nameRecordOut)) != TACK_OK)
                return retval;
            if ((retval=setMinGeneration(tackFingerprint, minGenerationOut)) != TACK_OK)
                return retval;
        }
        // Or if a pin's activation period (endTime) was extended
        else if (activationRetval == TACK_OK_UPDATE_PIN) {
            if ((retval=updateNameRecord(name, nameRecordOut.endTime)) != TACK_OK)
                return retval;
        }
        // Or if an inactive pin was deleted
        else if (activationRetval == TACK_OK_DELETE_PIN) {
            if ((retval=deleteNameRecord(name)) != TACK_OK)
                return retval;
        }
    }
    return resultRetval;
}
