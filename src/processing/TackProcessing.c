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
    if ((retval = tackExtensionSyntaxCheck(tackExt, tackExtLen)) != TACK_OK)
        return retval;
    ctx->tackExt = tackExt;
    
    /* Check tack's generation, expiration, target_hash, and signature */
    ctx->numTacks = tackExtensionGetNumTacks(tackExt);
    for (tackIndex = 0; tackIndex < ctx->numTacks; tackIndex++) {
        tack = tackExtensionGetTack(tackExt, tackIndex);
        
        if (tackTackGetGeneration(tack) < tackTackGetMinGeneration(tack))
            return TACK_ERR_BAD_GENERATION;

        if (tackTackGetExpiration(tack) <= currentTime)
            return TACK_ERR_EXPIRED_EXPIRATION;

        if (memcmp(tackTackGetTargetHash(tack), keyHash, TACK_HASH_LENGTH) != 0)
            return TACK_ERR_MISMATCHED_TARGET_HASH;
        
        if ((retval=tackTackVerifySignature(tack, crypto)) != TACK_OK)
            return retval;  

        /* Store tack and fingerprint into context */
        ctx->tack[tackIndex] = tack;
        if ((retval=tackTackGetKeyFingerprint(tack, ctx->tackFingerprint[tackIndex], 
                                              crypto)) != TACK_OK)
            return retval;
    }
    
    /* Check that there aren't two equal TACK keys */
    if (strcmp(ctx->tackFingerprint[0], ctx->tackFingerprint[1]) == 0)
        return TACK_ERR_EQUAL_TACK_KEYS;

    return TACK_OK;
}

TACK_RETVAL tackProcessStore(TackProcessingContext* ctx, const void* name,
                             uint32_t currentTime, uint8_t pinActivation,
                             TackStoreFuncs* store, void* storeArg, 
                             TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR, resultRetval = TACK_ERR;

    TackNameRecordPair pair;
    /* These values are doubled for a pair of pins */
    uint8_t pinIsActive[2] = {0,0};
    uint8_t pinMatchesTack[2] = {0,0};
    uint8_t pinMatchesActiveTack[2] = {0,0};
    /* These values are doubled for a pair of tacks */
    uint8_t tackMatchesPin[2] = {0,0};

    /* Handle tack min_generation and generation */
    if ((retval = tackProcessGeneration(ctx, store, storeArg)) != TACK_OK)
        return retval;

    /* Get the relevant pins.  Determine the store's status. */
    if ((retval = tackProcessPins(ctx, &pair, pinIsActive, pinMatchesTack, 
                                  pinMatchesActiveTack, tackMatchesPin, 
                                  currentTime, name, store, storeArg)) < TACK_OK)
        return retval;
    resultRetval = retval; /* Record status (ACCEPTED/REJECTED/UNPINNED) for return */

    /* Perform pin activation (optional) */
    if (pinActivation && resultRetval != TACK_OK_REJECTED)
        if ((retval=tackProcessPinActivation(ctx, &pair, pinIsActive, pinMatchesTack, 
                                         pinMatchesActiveTack, tackMatchesPin, 
                                         currentTime, name, store, storeArg)) != TACK_OK)
            return retval;
    
    return resultRetval;
}

TACK_RETVAL tackProcessGeneration(TackProcessingContext* ctx,
                                  TackStoreFuncs* store, void* storeArg) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t tackIndex = 0, minGeneration = 0;
    uint8_t* tack = NULL;
    char* tackFingerprint = NULL;

    for (tackIndex = 0; tackIndex < ctx->numTacks; tackIndex++) {
        tack = ctx->tack[tackIndex];
        tackFingerprint = ctx->tackFingerprint[tackIndex];
        
        retval = store->getMinGeneration(storeArg, tackFingerprint, &minGeneration);
        if (retval < TACK_OK)
            return retval;
        if (retval == TACK_OK_NOT_FOUND)
            continue;

        /* Check tack's generation against the store's min_generation */
        if (tackTackGetGeneration(tack) < minGeneration)
            return TACK_ERR_REVOKED_GENERATION;        
        
        /* If the tack's min_generation is greater, update the store */
        else if (tackTackGetMinGeneration(tack) > minGeneration) {
            retval = store->setMinGeneration(storeArg, tackFingerprint, 
                                             tackTackGetMinGeneration(tack));
            if (retval != TACK_OK)
                return retval;        
        }
    }
    return TACK_OK;
}

TACK_RETVAL tackProcessPins(TackProcessingContext* ctx, TackNameRecordPair* pair,
                            uint8_t pinIsActive[2], 
                            uint8_t pinMatchesTack[2], 
                            uint8_t pinMatchesActiveTack[2], 
                            uint8_t tackMatchesPin[2],
                            uint32_t currentTime, const void* name,
                            TackStoreFuncs* store, void* storeArg) 
{
    uint8_t pinIndex = 0, tackIndex = 0;
    uint8_t* tack = NULL;
    char* tackFingerprint = NULL;
    TackNameRecord* record = NULL;
    TACK_RETVAL retval = TACK_ERR;

    /* Get the relevant pin pair, if any */
    if ((retval=store->getNameRecordPair(storeArg, name, pair)) < TACK_OK)
        return retval;

    /* For each pin, do... */
    retval = TACK_OK_UNPINNED;
    for (pinIndex=0; pinIndex < pair->numPins; pinIndex++) {
        record = pair->records + pinIndex;

        /* Populate (pinIsActive, pinMatchesTack, pinMatchesActiveTack, tackMatchesPin) */
        if (record->endTime > currentTime)
            pinIsActive[pinIndex] = 1;

        for (tackIndex=0; tackIndex < ctx->numTacks; tackIndex++) {
            tack = ctx->tack[tackIndex];
            tackFingerprint = ctx->tackFingerprint[tackIndex];

            if (strcmp(record->fingerprint, tackFingerprint) == 0) { 
                pinMatchesTack[pinIndex] = 1;
                if (tackExtensionGetActivationFlag(ctx->tackExt, tackIndex))
                    pinMatchesActiveTack[pinIndex] = 1;
                tackMatchesPin[tackIndex] = 1;
            }
        }

        /* Determine connection status */
        if (pinIsActive[pinIndex]) {
            if (pinMatchesTack[pinIndex])
                retval = TACK_OK_ACCEPTED;
            else
                return TACK_OK_REJECTED; /* return immediately */
        }
    }
    return retval;
}

TACK_RETVAL tackProcessPinActivation(TackProcessingContext* ctx,
                                     TackNameRecordPair* pair,
                                     uint8_t pinIsActive[2],
                                     uint8_t pinMatchesTack[2],
                                     uint8_t pinMatchesActiveTack[2],
                                     uint8_t tackMatchesPin[2],
                                     uint32_t currentTime, const void* name,
                                     TackStoreFuncs* store, void* storeArg) 
{
    TACK_RETVAL retval = TACK_OK;
    uint32_t timeDelta = 0;
    uint8_t pinIndex = 0, tackIndex = 0, madeChanges = 0, deleteMask = 0;
    uint8_t* tack = NULL;
    char* tackFingerprint = NULL;
    TackNameRecord* nameRecord = NULL;

    /* The first step in pin activation is to evaluate each relevant pin */
    for (pinIndex = 0; pinIndex < pair->numPins; pinIndex++) {
        nameRecord = pair->records + pinIndex;

        /* If a pin has no matching tack, its handling will depend on whether the pin
           is active. If active, the connection will have been rejected, skipping pin
           activation. If inactive, the pin SHALL be deleted, since it is contradicted by
           the connection. */
        if (!pinMatchesTack[pinIndex]) {
            deleteMask |= (1 << pinIndex);  /* mark pin for deletion */
            madeChanges = 1;
        }

        /* If a pin has a matching tack, its handling will depend on whether the tack
           is active. If inactive, the pin is left unchanged. If active, the pin SHALL
           have its "end time" set based on the current, initial, and end times: */
        else if (pinMatchesActiveTack[pinIndex]) {            
            /* Ignore if current time < initialTime; would cause negative time delta */
            if (currentTime > nameRecord->initialTime) {
                
                /* It's OK to undercount but not overcount the delta, so subtract 1 */
                timeDelta = currentTime - nameRecord->initialTime - 1;
                if (timeDelta > (30 * 24 * 60))
                    timeDelta = (30 * 24 * 60);
                
                /* If the new endTime differs from existing, update it.*/
                if (currentTime + timeDelta != nameRecord->endTime) {            
                    nameRecord->endTime = currentTime + timeDelta;
                    madeChanges = 1;
                }
            }
        }
    }
    tackPairDeleteRecords(pair, deleteMask);

    /* The remaining step in pin activation is to add new inactive pins for
       any unmatched active tacks: */
    for (tackIndex = 0; tackIndex < ctx->numTacks; tackIndex++) {
        tack = ctx->tack[tackIndex];
        tackFingerprint = ctx->tackFingerprint[tackIndex];
        if (tackExtensionGetActivationFlag(ctx->tackExt, tackIndex) == 0)
            continue;

        if (!tackMatchesPin[tackIndex]) {
            /* There are always sufficient empty "slots" in the pin store for adding
               new pins without exceeding the limit of two pins per hostname */
            if (pair->numPins == 2)
                return TACK_ERR_ASSERTION;

            /* Add a new name record */
            nameRecord = pair->records + pair->numPins;
            nameRecord->initialTime = currentTime;
            nameRecord->endTime = 0;            
            strcpy(nameRecord->fingerprint, tackFingerprint);
            pair->numPins++;
            madeChanges = 1;

            /* Add a new key record (unless it already exists) */
            retval=store->setMinGeneration(storeArg, tackFingerprint, 
                                           tackTackGetMinGeneration(tack));
            if (retval != TACK_OK)
                return retval;
        }
    }

    if (madeChanges)
        retval=store->setNameRecordPair(storeArg, name, pair);

    return retval;
}
