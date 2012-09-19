/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */
#include <string.h>
#include "TackUtil.h"
#include "TackProcessing.h"
#include "TackExtension.h"

TACK_RETVAL tackProcessWellFormed(TackProcessingContext* ctx,
                                  uint8_t* tackExt, uint32_t tackExtLen,
                                  uint8_t keyHash[TACK_HASH_LENGTH],
                                  uint32_t currentTime, TackCryptoFuncs* crypto)
{    
    uint8_t tackIndex = 0;
    uint8_t* tack;
    TACK_RETVAL retval = TACK_ERR;

    /* Clear TackProcessingContext */
    memset(ctx, 0, sizeof(TackProcessingContext));

    if (!tackExt)
        return TACK_OK;

    /* Check extension lengths and activation flags <= 3 */
    if ((retval = tackExtSyntaxCheck(tackExt, tackExtLen)) != TACK_OK)
        return retval;
    ctx->tackExt = tackExt;
    
    /* Check tack's generation, expiration, target_hash, and signature */
    ctx->numTacks = tackExtGetNumTacks(tackExt);
    for (tackIndex = 0; tackIndex < ctx->numTacks; tackIndex++) {
        tack = tackExtGetTack(tackExt, tackIndex);
        
        if (tackTackGetGeneration(tack) < tackTackGetMinGeneration(tack))
            return TACK_ERR_BAD_GENERATION;

        if (tackTackGetExpiration(tack) <= currentTime)
            return TACK_ERR_EXPIRED_EXPIRATION;

        if (memcmp(tackTackGetTargetHash(tack), keyHash, TACK_HASH_LENGTH) != 0)
            return TACK_ERR_MISMATCHED_TARGET_HASH;
        
        if ((retval=tackTackVerifySignature(tack, crypto)) != TACK_OK)
            return retval;  

        /* Store tack and fingerprint into context */
        ctx->tacks[tackIndex] = tack;
        if ((retval=tackTackGetKeyFingerprint(tack, ctx->fingerprints[tackIndex], 
                                              crypto)) != TACK_OK)
            return retval;
    }
    
    /* Check that there aren't two equal TACK keys */
    if (strcmp(ctx->fingerprints[0], ctx->fingerprints[1]) == 0)
        return TACK_ERR_EQUAL_TACK_KEYS;

    return TACK_OK;
}

TACK_RETVAL tackProcessStore(TackProcessingContext* ctx, const void* name,
                             uint32_t currentTime, uint8_t pinActivation,
                             TackStoreFuncs* store, void* storeArg, 
                             TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR, status = TACK_OK_UNPINNED;
    uint8_t p = 0, t = 0, minGeneration = 0, madeChanges = 0;
    uint8_t pinIsActive = 0, pinMatchesTack = 0, pinMatchesActiveTack = 0;
    uint8_t tackMatchesPin[2] = {0,0};
    uint32_t endTime = 0;
    TackPinPair pair, newPair;
    TackPin* pin = &(pair.pins[0]);
    memset(&pair, 0, sizeof(TackPinPair));
    memset(&newPair, 0, sizeof(TackPinPair));

    /* Check tack generations and update min_generations */
    for (t = 0; t < ctx->numTacks; t++) {
        retval = store->getMinGeneration(storeArg, ctx->fingerprints[t], &minGeneration);
        if (retval < TACK_OK) return retval;

        if (retval != TACK_OK_NOT_FOUND) {
            if (tackTackGetGeneration(ctx->tacks[t]) < minGeneration)
                return TACK_ERR_REVOKED_GENERATION;            
            else if (tackTackGetMinGeneration(ctx->tacks[t]) > minGeneration) {
                retval = store->setMinGeneration(storeArg, ctx->fingerprints[t], 
                                                 tackTackGetMinGeneration(ctx->tacks[t]));
                if (retval != TACK_OK) return retval;        
            } 
        } 
    }

    /* Iterate over pins and tacks, calculating the return status
       and handling the first step of pin activation (delete and activate) */
    if ((retval=store->getPinPair(storeArg, name, &pair)) < TACK_OK)
        return retval;
    for (p=0; p < pair.numPins; p++) {
        pin = &pair.pins[p];
        pinIsActive = pinMatchesTack = pinMatchesActiveTack = 0;

        /* Fill in variables indicating pin/tack matches */
        if (pin->endTime > currentTime)
            pinIsActive = 1;
        for (t=0; t < ctx->numTacks; t++) {
            if (strcmp(pin->fingerprint, ctx->fingerprints[t]) == 0) { 
                pinMatchesTack = 1;
                pinMatchesActiveTack = tackExtIsActive(ctx->tackExt, t);
                tackMatchesPin[t] = 1;
            } 
        }

        /* Determine the store's status */
        if (pinIsActive) {
            if (!pinMatchesTack)
                return TACK_OK_REJECTED; /* return immediately */
            status = TACK_OK_ACCEPTED;
        }

        /* Pin activation (first step: consider each pin for deletion / activation) */
        if (pinActivation) {
            if (!pinMatchesTack)
                madeChanges = 1; /* Delete pin (by not appending to newPair) */
            else {
                endTime = pin->endTime;
                if (pinMatchesActiveTack && currentTime > pin->initialTime) {
                    endTime = currentTime + (currentTime - pin->initialTime) - 1;
                    if (endTime > currentTime + 30*24*60) 
                        endTime = currentTime + 30*24*60;
                    if (endTime != pin->endTime)
                        madeChanges = 1; /* Activate pin */
                }
                /* Append old pin to newPair, possibly extending endTime */
                if (newPair.numPins > 1)
                    return TACK_ERR_ASSERTION;
                memcpy(&newPair.pins[newPair.numPins], pin, sizeof(TackPin));
                newPair.pins[newPair.numPins].endTime = endTime;
                newPair.numPins++;
            }
        }
    }

    /* Pin activation (second step: add new pins) */
    if (pinActivation) {
        for (t = 0; t < ctx->numTacks; t++) {
            if (tackExtIsActive(ctx->tackExt, t) && !tackMatchesPin[t]) {
                if (newPair.numPins > 1)
                    return TACK_ERR_ASSERTION;
                newPair.pins[newPair.numPins].initialTime = currentTime;
                newPair.pins[newPair.numPins].endTime = 0;            
                strcpy(newPair.pins[newPair.numPins].fingerprint, ctx->fingerprints[t]);
                newPair.numPins++;
                madeChanges = 1;
                retval=store->setMinGeneration(storeArg, ctx->fingerprints[t], 
                                               tackTackGetMinGeneration(ctx->tacks[t]));
                if (retval != TACK_OK)
                    return retval;
            }
        }
        /* Commit pin activation changes */
        if (madeChanges) {
            if ((retval=store->setPinPair(storeArg, name, &newPair)) != TACK_OK)
                return retval;
        }
    }
    return status;
}
