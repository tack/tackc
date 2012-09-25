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

TACK_RETVAL tackProcessStore(void* storeArg, TackStoreFuncs* store, 
                             TackProcessingContext* ctx,  uint8_t pinActivation,
                             const void* name, uint32_t currentTime, 
                             TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR, status = TACK_OK_UNPINNED;
    uint8_t p = 0, t = 0, minGeneration = 0, madeChanges = 0;
    uint8_t pinIsActive[2] = {0,0}, pinMatchesTack[2] = {0,0};
    uint8_t pinMatchesActiveTack[2] = {0,0}, tackMatchesPin[2] = {0,0};
    uint32_t endTime = 0;
    TackPinPair pair, newPair;
    TackPin* pin = &(pair.pins[0]);
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

	/* Determine the store's status */
    if ((retval=store->getPinPair(storeArg, name, &pair)) < TACK_OK)
        return retval;
    for (p=0; p < pair.numPins; p++) {
        pin = &pair.pins[p];

        if (pin->endTime > currentTime)
            pinIsActive[p] = 1;
        for (t=0; t < ctx->numTacks; t++) {
            if (strcmp(pin->fingerprint, ctx->fingerprints[t]) == 0) { 
                pinMatchesTack[p] = 1;
                pinMatchesActiveTack[p] = tackExtIsActive(ctx->tackExt, t);
                tackMatchesPin[t] = 1;
            } 
        }
        if (pinIsActive[p]) {
            if (!pinMatchesTack[p])
                return TACK_OK_REJECTED; /* return immediately */
            status = TACK_OK_ACCEPTED;
        }
    }

	/* Perform pin activation */
    if (pinActivation) {
   
        /* Delete unmatched pins and activate matched pins with active tacks */
        for (p=0; p < pair.numPins; p++) {
            pin = &pair.pins[p];
            
            if (!pinMatchesTack[p])
                madeChanges = 1; /* Delete pin (by not appending to newPair) */
            else {
                endTime = pin->endTime;
                if (pinMatchesActiveTack[p] && currentTime > pin->initialTime) {
                    endTime = currentTime + (currentTime - pin->initialTime) - 1;
                    if (endTime > currentTime + 30*24*60) 
                        endTime = currentTime + 30*24*60;
                    if (endTime != pin->endTime)
                        madeChanges = 1; /* Activate pin */
                }
                /* Append old pin to newPair, possibly extending endTime */
                retval = appendPin(&newPair, pin->initialTime, endTime, pin->fingerprint);
                if (retval != TACK_OK) return retval;
            }
        }
        /* Add new inactive pins for any unmatched active tacks */
        for (t = 0; t < ctx->numTacks; t++) {
            if (tackExtIsActive(ctx->tackExt, t) && !tackMatchesPin[t]) {
                retval=store->setMinGeneration(storeArg, ctx->fingerprints[t], 
                                               tackTackGetMinGeneration(ctx->tacks[t]));
                if (retval != TACK_OK) return retval;
                retval = appendPin(&newPair, currentTime, 0, ctx->fingerprints[t]);
                if (retval != TACK_OK) return retval;
                madeChanges = 1;
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
