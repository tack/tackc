/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */
#include <string.h>
#include "TackUtil.h"
#include "TackProcessing.h"
#include "TackExtension.h"
#include "TackStoreFuncs.h"

TACK_RETVAL tackProcessWellFormed(TackProcessingContext* ctx,
                                  uint8_t* tackExt, uint32_t tackExtLen,
                                  uint8_t keyHash[TACK_HASH_LENGTH],
                                  uint32_t tmin, uint32_t tmax, 
                                  TackCryptoFuncs* crypto)
{    
    uint8_t tackIndex = 0;
    uint8_t* tack;
    TACK_RETVAL retval = TACK_ERR;

    /* Clear TackProcessingContext */
    memset(ctx, 0, sizeof(TackProcessingContext));

    if (!tackExt)
        return TACK_OK;

    /* Check extension syntax */
    if ((retval = tackExtensionSyntaxCheck(tackExt, tackExtLen)) != TACK_OK)
        return retval;
    ctx->tackExt = tackExt;
    
    /* Check tack's expiration, target_hash, and signature */
    ctx->numTacks = tackExtensionGetNumTacks(tackExt);
    for (tackIndex = 0; tackIndex < ctx->numTacks; tackIndex++) {
        tack = tackExtensionGetTack(tackExt, tackIndex);

        if (tackTackGetExpiration(tack) < tmin)
            return TACK_ERR_EXPIRED_EXPIRATION;

        if (memcmp(tackTackGetTargetHash(tack), keyHash, TACK_HASH_LENGTH) != 0)
            return TACK_ERR_MISMATCHED_TARGET_HASH;
        
        if ((retval=tackTackVerifySignature(tack, crypto)) != TACK_OK)
            return retval;  

        /* Store tack and fingerprint into context */
        ctx->tack[tackIndex] = tack;
        if ((retval=tackTackGetKeyFingerprint(tack, ctx->tackFingerprint[0], 
                                              crypto)) != TACK_OK)
            return retval;
    }
    return TACK_OK;
}

TACK_RETVAL tackProcessStore(TackProcessingContext* ctx,
                             const void* name,
                             uint32_t tmin, uint32_t tmax,
                             uint8_t pinActivation,
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

    /* Delete pins based on break signatures */
    if (ctx->tackExt)
        if ((retval = tackProcessBreakSigs(ctx, store, storeArg, crypto)) != TACK_OK)
            return retval;

    /* Handle the tack's generation and min_generation (if any) */
    if (ctx->numTacks)
        if ((retval = tackProcessGeneration(ctx, store, storeArg)) != TACK_OK)
            return retval;

    /* Get the relevant pins.  Determine the store's status. */
    if ((retval = tackProcessPins(ctx, &pair, 
                                  pinIsActive, pinMatchesTack, pinMatchesActiveTack,
                                  tackMatchesPin, 
                                  tmin, tmax, 
                                  name, store, storeArg)) < TACK_OK)
        return retval;
    resultRetval = retval;

    /* Perform pin activation (optional) */
    if (pinActivation && resultRetval != TACK_OK_REJECTED)
        if ((retval=tackProcessPinActivation(ctx, tmin, tmax, &pair, 
                                             pinIsActive, pinMatchesTack, 
                                             pinMatchesActiveTack, tackMatchesPin,
                                             name, store, storeArg)) < TACK_OK)
            return retval;
    
    return resultRetval;
}

TACK_RETVAL tackProcessBreakSigs(TackProcessingContext* ctx,
                                        TackStoreFuncs* store, void* storeArg, 
                                        TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    char breakFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t* breakSig = NULL;
    uint8_t minGenerationVal = 0, mustDeleteKey = 0, count = 0;

    /* Iterate through break sigs */
    for (count = 0; count < tackExtensionGetNumBreakSigs(ctx->tackExt); count++) {
        /* Get the fingerprint for each break sig */
        breakSig = tackExtensionGetBreakSig(ctx->tackExt, count);
        retval=tackBreakSigGetKeyFingerprint(breakSig, breakFingerprint, crypto);
        if (retval != TACK_OK)
            return retval;

        /* Check if the store has a key for each break sig */
        if ((retval=store->getMinGeneration(storeArg, breakFingerprint, 
                                            &minGenerationVal)) < TACK_OK)
            return retval;

        /* If the store DOES have a key (ie not TACK_OK_NOT_FOUND): */
        if (retval == TACK_OK) {
            /* Use breakSigFlags to memorize which sigs have already been verified */
            mustDeleteKey = 0;
            if (ctx->breakSigFlags & (1<<count))
                mustDeleteKey = 1;
            else {
                if ((retval = tackBreakSigVerifySignature(breakSig, crypto)) != TACK_OK)
                    return retval;
                ctx->breakSigFlags |= (1<<count);
                mustDeleteKey = 1;
            }
            /* Delete the key and all associated pins */
            if (mustDeleteKey) {
                if ((retval = store->deleteKey(storeArg, breakFingerprint)) != TACK_OK)
                    return retval;
            }
        }
    }
    return TACK_OK;
}

TACK_RETVAL tackProcessGeneration(TackProcessingContext* ctx,
                                  TackStoreFuncs* store, void* storeArg) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t minGeneration = 0;
    uint8_t tackIndex = 0;
    uint8_t* tack = NULL;
    char* tackFingerprint = NULL;

    for (tackIndex = 0; tackIndex < ctx->numTacks; tackIndex++) {
        tack = ctx->tack[tackIndex];
        tackFingerprint = ctx->tackFingerprint[tackIndex];

        /* Check tack's generation against the store's min_generation */
        retval = store->getMinGeneration(storeArg, tackFingerprint, &minGeneration);
        if (retval < TACK_OK)
            return retval;        
        if (retval == TACK_OK_NOT_FOUND)
            return TACK_OK;
        
        if (tackTackGetGeneration(tack) < minGeneration)
            return TACK_ERR_REVOKED_GENERATION;
        
        /* If the tack's min_generation is greater, update the store */
        if (tackTackGetMinGeneration(tack) > minGeneration) {
            retval = store->setMinGeneration(storeArg, tackFingerprint, 
                                             tackTackGetMinGeneration(tack));
            if (retval != TACK_OK)
                return retval;        
        }
    }
    return TACK_OK;
}   

TACK_RETVAL tackProcessPins(TackProcessingContext* ctx,
                            TackNameRecordPair* pair,
                            uint8_t pinIsActive[2], 
                            uint8_t pinMatchesTack[2], 
                            uint8_t pinMatchesActiveTack[2], 
                            uint8_t tackMatchesPin[2],
                            uint32_t tmin, uint32_t tmax, const void* name,
                            TackStoreFuncs* store, void* storeArg) 
{
    uint8_t pinIndex = 0, tackIndex = 0;
    uint8_t* tack = NULL;
    char* tackFingerprint = NULL;
    TACK_RETVAL retval = TACK_ERR;

    /* Get the relevant pin pair, if any */
    if ((retval=store->getNameRecordPair(storeArg, name, pair)) < TACK_OK)
        return retval;

    /* For each pin, do... */
    retval = TACK_OK_UNPINNED;
    for (pinIndex=0; pinIndex < pair->numPins; pinIndex++) {
        TackNameRecord* record = pair->records + pinIndex;
        
        /* Record whether pin is active */
        if (record->endTime >= tmax)
            pinIsActive[pinIndex] = 1;
        
        /* Record whether pin and tacks match */
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
                return TACK_OK_REJECTED;
        }
    }
    return retval;
}

TACK_RETVAL tackProcessPinActivation(TackProcessingContext* ctx,
                                     uint32_t tmin, uint32_t tmax,
                                     TackNameRecordPair* pair,
                                     uint8_t pinIsActive[2],
                                     uint8_t pinMatchesTack[2],
                                     uint8_t pinMatchesActiveTack[2],
                                     uint8_t tackMatchesPin[2],
                                     const void* name,
                                     TackStoreFuncs* store, void* storeArg) 
{
    TACK_RETVAL retval = TACK_OK;
    uint32_t timeDelta = 0;
    uint8_t pinIndex = 0, tackIndex = 0;
    uint8_t madeChanges = 0;
    uint8_t deleteMask = 0;
    uint8_t* tack = NULL;
    char* tackFingerprint = NULL;
    TackNameRecord* newRecord = NULL;

    /* The first step in pin activation is to evaluate each relevant pin
       (there may be one or two): */
    for (pinIndex = 0; pinIndex < pair->numPins; pinIndex++) {
        TackNameRecord* nameRecord = pair->records + pinIndex;

        /* If a pin has no matching tacks [...] the pin SHALL be deleted, 
           since it is contradicted by the connection. */
        if (!pinMatchesTack[pinIndex]) {
            deleteMask |= (1 << pinIndex);  /* mark pin for deletion */
            madeChanges = 1;
        }

        /* If a pin has matching tacks, its handling will depend on whether
           at least one of the tacks is active.  [...] If so, then the pin SHALL have 
           its "end time" set based on the current, initial, and end times: */
        else if (pinMatchesActiveTack[pinIndex]) {            
            /* Ignore if current time < initialTime; would cause negative time delta */
            if (tmin > nameRecord->initialTime) {
                
                timeDelta = tmin - nameRecord->initialTime;
                if (timeDelta > (30 * 24 * 60))
                    timeDelta = (30 * 24 * 60);
                
                /* If the new endTime differs from existing, update it.*/
                if (tmin + timeDelta != nameRecord->endTime) {            
                    nameRecord->endTime = tmin + timeDelta;
                    madeChanges = 1;
                }        
            }
        }
    }
    tackPairDeleteRecords(pair, deleteMask);

    /* The remaining step in pin activation is to add new inactive pins for
       any unmatched tacks: */
    for (tackIndex = 0; tackIndex < ctx->numTacks; tackIndex++) {
        tack = ctx->tack[tackIndex];
        tackFingerprint = ctx->tackFingerprint[tackIndex];

        if (!tackMatchesPin[tackIndex]) {
            /* There are always sufficient empty "slots" in the pin store for adding
               new pins without exceeding the limit of two pins per hostname */
            if (pair->numPins == 2)
                return TACK_ERR_ASSERTION;

            /* Add a new name record */
            newRecord = pair->records + pair->numPins;
            newRecord->initialTime = tmax;
            newRecord->endTime = 0;            
            strcpy(newRecord->fingerprint, tackFingerprint);
            pair->numPins++;
            madeChanges = 1;

            /* Add a new key record */
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
