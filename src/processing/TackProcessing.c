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
    ctx->tack = tackExtensionGetTack(tackExt);
    if (ctx->tack) {        
        if (tackTackGetExpiration(ctx->tack) <= currentTime)
            return TACK_ERR_EXPIRED_EXPIRATION;

        if (memcmp(tackTackGetTargetHash(ctx->tack), keyHash, TACK_HASH_LENGTH) != 0)
            return TACK_ERR_MISMATCHED_TARGET_HASH;
        
        if ((retval=tackTackVerifySignature(ctx->tack, crypto)) != TACK_OK)
            return retval;  

        /* Store fingerprint into context */
        if ((retval=tackTackGetKeyFingerprint(ctx->tack, ctx->tackFingerprint, 
                                              crypto)) != TACK_OK)
            return retval;             
    }
    return TACK_OK;
}

TACK_RETVAL tackProcessStore(TackProcessingContext* ctx,
                             const void* name,
                             uint32_t currentTime,
                             uint8_t pinActivation,
                             TackStoreFuncs* store, void* storeArg, 
                             TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR, resultRetval = TACK_ERR;
    TackNameRecord nameRecordStruct;
    TackNameRecord* nameRecord = NULL;
    uint8_t pinIsActive = 0, tackMatchesPin = 0;

    /* Delete pins based on break signatures */
    if ((retval = tackProcessBreakSigs(ctx, store, storeArg, crypto)) != TACK_OK)
        return retval;

    /* Handle the tack's generation and min_generation (if any) */
    if ((retval = tackProcessGeneration(ctx, store, storeArg)) != TACK_OK)
        return retval;

    /* Get the relevant pin.  Determine the store's status. */
    if ((retval = tackProcessPin(ctx, &nameRecordStruct, &nameRecord, &pinIsActive, 
                                 &tackMatchesPin, currentTime, 
                                 name, store, storeArg)) < TACK_OK)
        return retval;
    resultRetval = retval;

    /* Perform pin activation (optional) */
    if (pinActivation)
        if ((retval=tackProcessPinActivation(ctx, currentTime, nameRecord, 
                                             pinIsActive, tackMatchesPin, 
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

        /* If it does... */
        if (retval == TACK_OK) {
            /* Use breakSigFlags to memorize which signatures have already been verified */
            mustDeleteKey = 0;
            if (ctx->breakSigFlags & (1<<count))
                mustDeleteKey = 1;
            else {
                retval = tackBreakSigVerifySignature(breakSig, crypto);
                if (retval != TACK_OK)
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

    if (ctx->tack) {
        /* If there's a tack, check its generation against the store's min_generation */
        retval = store->getMinGeneration(storeArg, ctx->tackFingerprint, &minGeneration);
        if (retval < TACK_OK)
            return retval;        
        if (retval == TACK_OK_NOT_FOUND)
            return TACK_OK;
        
        if (tackTackGetGeneration(ctx->tack) < minGeneration)
            return TACK_ERR_REVOKED_GENERATION;
        
        /* If the tack's min_generation is greater, update the store */
        if (tackTackGetMinGeneration(ctx->tack) > minGeneration) {
            retval = store->setMinGeneration(storeArg, ctx->tackFingerprint, 
                                             tackTackGetMinGeneration(ctx->tack));
            if (retval != TACK_OK)
                return retval;        
        }
    }
    return TACK_OK;
}   

TACK_RETVAL tackProcessPin(TackProcessingContext* ctx,
                           TackNameRecord* nameRecordStruct,
                           TackNameRecord** nameRecord,
                           uint8_t* pinIsActive, uint8_t* tackMatchesPin, 
                           uint32_t currentTime, const void* name,
                           TackStoreFuncs* store, void* storeArg) 
{
    TACK_RETVAL retval = TACK_ERR;

    /* Get the relevant pin, if any */
    if ((retval=store->getNameRecord(storeArg, name, nameRecordStruct)) < TACK_OK)
        return retval;
    if (retval == TACK_OK) {
        *nameRecord = nameRecordStruct;

        /* Is pin active? */
        if ((*nameRecord)->endTime > currentTime)
            *pinIsActive = 1;

        /* Does tack match pin? */
        if (ctx->tack && strcmp(ctx->tackFingerprint, (*nameRecord)->fingerprint)==0) 
            *tackMatchesPin = 1;
    }

    /* Determine the store's status */
    if (*pinIsActive) {
        if (*tackMatchesPin)
            return TACK_OK_ACCEPTED;
        else
            return TACK_OK_REJECTED;
    }
    return TACK_OK_UNPINNED;
}

TACK_RETVAL tackProcessPinActivation(TackProcessingContext* ctx,
                                     uint32_t currentTime,
                                     TackNameRecord* nameRecord,
                                     uint8_t pinIsActive,
                                     uint8_t tackMatchesPin,
                                     const void* name,
                                     TackStoreFuncs* store, void* storeArg) 
{
    TackNameRecord nameRecordNew;
    TACK_RETVAL retval = TACK_OK;
    uint32_t timeDelta = 0;
    uint32_t endTime = 0;

    /* The first step in pin activation is to delete a relevant but inactive
       pin unless there is a matching tack. */
    if (nameRecord && !pinIsActive && !tackMatchesPin) {
        nameRecord = NULL;
        if ((retval=store->deleteNameRecord(storeArg, name)) != TACK_OK)
            return retval;
    }
    
    /* If there is no tack, or if the activation flag is disabled, then this 
       completes the algorithm. */
    if (!ctx->tack || (tackExtensionGetActivationFlag(ctx->tackExt) == 0))
        return retval;

    if (tackMatchesPin) {
        /* If there is a relevant pin and matching tack, the pin's "end time"
           SHALL be set using the below formula: */

        /* Ignore if current time < initialTime; would cause negative time delta */
        if (currentTime > nameRecord->initialTime) {

            /* It's OK to undercount but not overcount the time delta, so subtract 1 */
            timeDelta = currentTime - nameRecord->initialTime - 1;
            if (timeDelta > (30 * 24 * 60))
                timeDelta = (30 * 24 * 60);

            /* If the new endTime differs from existing (larger or smaller), update it. */
            if (currentTime + timeDelta != nameRecord->endTime) {            
                endTime = currentTime + timeDelta;
                if ((retval=store->updateNameRecord(storeArg, name, endTime)) != TACK_OK)
                    return retval;
            }
        }
    }
    else if (!nameRecord)  {
        /* If there is no relevant pin a new pin SHALL be created: */
        strcpy(nameRecordNew.fingerprint, ctx->tackFingerprint);
        nameRecordNew.initialTime = currentTime;
        nameRecordNew.endTime = 0;
        if ((retval=tackStoreSetPin(store, storeArg, name, &nameRecordNew, 
                                    tackTackGetMinGeneration(ctx->tack))) != TACK_OK)
            return retval;
        return TACK_OK_NEW_PIN; /* overwriting TACK_OK or TACK_OK_DELETE_PIN */
    }
    return retval;
}
