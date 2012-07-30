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
                                  uint32_t currentTime,                                  
                                  TackCryptoFuncs* crypto)
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
    
    /* Check tack's expiration, target_hash, and signature (incl. public_key) */
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

static TACK_RETVAL tackProcessBreakSigs(TackProcessingContext* ctx,
                                        TackStoreFuncs* store, 
                                        void* storeArg, 
                                        TackCryptoFuncs* crypto);

TACK_RETVAL tackProcessStore(TackProcessingContext* ctx,
                             const void* name,
                             uint32_t currentTime,
                             uint8_t pinActivation,
                             TackStoreFuncs* store, 
                             void* storeArg, 
                             TackCryptoFuncs* crypto)
{

    TACK_RETVAL retval = TACK_ERR, resultRetval = TACK_ERR;

    TackNameRecord nameRecordStruct;
    TackNameRecord* nameRecord = NULL;
    uint8_t minGenerationVal = 0;
    uint8_t* minGeneration = NULL;
    TACK_RETVAL activationRetval = TACK_ERR;
    TackNameRecord nameRecordOut;
    uint8_t minGenerationOut = 0;

    memset(&nameRecordStruct, 0, sizeof(TackNameRecord));
    memset(&nameRecordOut, 0, sizeof(TackNameRecord));

    /* Delete pins based on break signatures */
    if ((retval = tackProcessBreakSigs(ctx, store, storeArg, crypto)) != TACK_OK)
        return retval;

    /* Get the relevant name record, if any */
    if ((retval=store->getNameRecord(storeArg, name, &nameRecordStruct)) < TACK_OK)
        return retval;
    if (retval == TACK_OK)
        nameRecord = &nameRecordStruct;

    /* Get the key's minGeneration, if any */
    if (ctx->tack) {
        if ((retval=store->getMinGeneration(storeArg, ctx->tackFingerprint, 
                                            &minGenerationVal)) < TACK_OK)
            return retval;
        if (retval == TACK_OK)
            minGeneration = &minGenerationVal;
    }

    /* Client processing logic */
    retval=tackProcessStoreHelper(ctx, currentTime, nameRecord, minGeneration, 
                                  &activationRetval, &nameRecordOut, &minGenerationOut,
                                  crypto);
    if (retval <= TACK_OK) /* only allow ACCEPTED, REJECTED, or UNPINNED */
        return retval;
    resultRetval = retval;

    /* Make store changes based on revocation */
    if (minGeneration && minGenerationOut > *minGeneration) {
        retval=store->setMinGeneration(storeArg, ctx->tackFingerprint, 
                                       minGenerationOut);
        if (retval != TACK_OK)
            return retval;
    }

    /* Make store changes based on pin activation */
    if (pinActivation) {
        /* If a new pin was created (perhaps replacing an old one) */
        if (activationRetval == TACK_OK_NEW_PIN) {
            retval=tackStoreSetPin(store, storeArg, name, &nameRecordOut, minGenerationOut);
            if (retval != TACK_OK)
                return retval;
        }
        /* Or if a pin's endTime was extended */
        else if (activationRetval == TACK_OK_UPDATE_PIN) {
            retval=store->updateNameRecord(storeArg, name, nameRecordOut.endTime);
            if (retval != TACK_OK)
                return retval;
        }
        /* Or if an inactive pin was deleted */
        else if (activationRetval == TACK_OK_DELETE_PIN) {
            retval=store->deleteNameRecord(storeArg, name);
            if (retval != TACK_OK)
                return retval;
        }
    }

    return resultRetval;
}


/* Helper functions used by tackProcessStoreHelper() */

static TACK_RETVAL tackProcessPinActivation(TackProcessingContext* ctx,
                                            uint32_t currentTime,
                                            TackNameRecord* nameRecord, 
                                            TackNameRecord* nameRecordOut,
                                            uint8_t* minGenerationOut,
                                            uint8_t tackMatchesPin,
                                            TackCryptoFuncs* crypto);

TACK_RETVAL tackProcessStoreHelper(TackProcessingContext* ctx,
                                   uint32_t currentTime,   
                                   TackNameRecord* nameRecord,
                                   uint8_t* minGeneration,
                                   TACK_RETVAL* activationRetval,
                                   TackNameRecord* nameRecordOut,
                                   uint8_t* minGenerationOut,
                                   TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;  
    uint8_t pinIsRelevant = 0;
    uint8_t tackMatchesPin = 0;

    /* Initialize outputs */ 
    *activationRetval = TACK_OK;
    *minGenerationOut = 0;

    /* Is pin active? */
    if (nameRecord && nameRecord->endTime > currentTime)
        pinIsRelevant = 1;

    /* Note if tack matches pin */
    if (nameRecord && ctx->tack)
        if (strcmp(ctx->tackFingerprint, nameRecord->fingerprint)==0) 
            tackMatchesPin = 1;

    /* Check the tack's generation and update min_generation */
    if (ctx->tack && minGeneration) {            
        if (tackTackGetGeneration(ctx->tack) < *minGeneration)
            return TACK_ERR_REVOKED_GENERATION;
        
        if (tackTackGetMinGeneration(ctx->tack) > *minGeneration)
            *minGenerationOut = tackTackGetMinGeneration(ctx->tack);
    }        
    
    /* Perform pin activation */
    if ((retval=tackProcessPinActivation(ctx, currentTime, nameRecord, nameRecordOut,
                                         minGenerationOut, tackMatchesPin, 
                                         crypto)) < TACK_OK)
        return retval;
    *activationRetval = retval;    

    /* Determine the store's status */
    if (pinIsRelevant) {
        if (tackMatchesPin)
            return TACK_OK_ACCEPTED;
        else
            return TACK_OK_REJECTED;
    }
    else
        return TACK_OK_UNPINNED;
}

static TACK_RETVAL tackProcessBreakSigs(TackProcessingContext* ctx,
                                        TackStoreFuncs* store, 
                                        void* storeArg, 
                                        TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t count = 0;
    char breakFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t* breakSig = NULL;
    uint8_t minGenerationVal;
    uint8_t mustDeleteKey = 0;

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
            if (mustDeleteKey) {
                if ((retval = store->deleteKey(storeArg, breakFingerprint)) != TACK_OK)
                    return retval;
            }
        }
    }
    return TACK_OK;
}

static TACK_RETVAL tackProcessPinActivation(TackProcessingContext* ctx,
                                            uint32_t currentTime,
                                            TackNameRecord* nameRecord, 
                                            TackNameRecord* nameRecordOut,
                                            uint8_t* minGenerationOut,
                                            uint8_t tackMatchesPin,
                                            TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_OK;
    uint32_t timeDelta = 0;

    /* The first step in pin activation is to delete a relevant but inactive
       pin unless there is a matching tack. */
    if (nameRecord && (nameRecord->endTime <= currentTime) && !tackMatchesPin) {
        nameRecord = NULL;
        retval = TACK_OK_DELETE_PIN;
    }
    
    /* If there is no tack, or if the activation flag is disabled, then this 
       completes the algorithm.  Otherwise, the following steps are executed:*/
    if (!ctx->tack || (tackExtensionGetActivationFlag(ctx->tackExt) == 0))
        return retval;
    
    if (tackMatchesPin) {
        /* If there is a relevant pin and matching tack, the name
           record's "end time" SHALL be set using the below formula: */

        /* If current time is before initialTime, that is weird, ignore it to
           avoid negative timeDelta in what follows. */
        if (currentTime > nameRecord->initialTime) {

            /* It's OK to undercount but not overcount the time delta,
               so we subtract 1 minute. */
            timeDelta = currentTime - nameRecord->initialTime - 1;
            if (timeDelta > (30 * 24 * 60))
                timeDelta = (30 * 24 * 60);

            /* If the new endTime differs from existing, update it.  Note
               that the new endTime may be smaller if the clock has been
               resync'd - that's desirable, to avoid mistakenly long periods. */
            if (currentTime + timeDelta != nameRecordOut->endTime) {            
                nameRecordOut->endTime = currentTime + timeDelta;
                return TACK_OK_UPDATE_PIN; /* overwriting TACK_OK */
            }
        }
    }
    if (!nameRecord)  {
        /* If there is no relevant pin a new pin SHALL be created: */
        strcpy(nameRecordOut->fingerprint, ctx->tackFingerprint);
        *minGenerationOut = tackTackGetMinGeneration(ctx->tack);
        nameRecordOut->initialTime = currentTime;
        nameRecordOut->endTime = 0;
        return TACK_OK_NEW_PIN; /* overwriting TACK_OK or TACK_OK_DELETE_PIN */
    }
    return retval;
}
