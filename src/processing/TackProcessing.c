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

TACK_RETVAL tackProcessStore(TackProcessingContext* ctx,
                             void* name,
                             uint32_t currentTime,
                             uint8_t doPinActivation,
                             TackStoreFuncs* store, 
                             void* storeArg, 
                             void* revocationStoreArg,
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
    if (retval < TACK_OK)
        return retval;
    resultRetval = retval;

    /* Make store changes based on revocation */
    if (minGeneration && minGenerationOut > *minGeneration) {
        retval=store->setMinGeneration(revocationStoreArg, ctx->tackFingerprint, 
                                       minGenerationOut);
        if (retval != TACK_OK)
            return retval;
    }

    /* Make store changes based on pin activation */
    if (doPinActivation) {
        /* If a new pin was created (perhaps replacing an old one) */
        if (activationRetval == TACK_OK_NEW_PIN) {
            /* Set key record before name record */
            retval=store->setMinGeneration(storeArg, ctx->tackFingerprint, 
                                           minGenerationOut);
            if (retval != TACK_OK)
                return retval;
            retval=store->setNameRecord(storeArg, name, &nameRecordOut);
            if (retval != TACK_OK)
                return retval;
        }
        /* Or if a pin's activation period (endTime) was extended */
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
static TACK_RETVAL tackProcessBreakSigs(TackProcessingContext* ctx,
                                        TackNameRecord** nameRecord,
                                        TackCryptoFuncs* crypto);

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
    TACK_RETVAL retval = TACK_ERR, resultRetval=TACK_ERR;  
    uint8_t tackMatchesPin = 0;

    /* Initialize outputs */ 
    *activationRetval = TACK_OK;
    *minGenerationOut = 0;

    /* If there's a TACK Extension, do: */
    if (ctx->tackExt) {

        /* If there is an active pin, see if it is broken by break signatures
           If it is, mask the pin (nameRecord = NULL) */
        if (nameRecord && nameRecord->endTime > currentTime) {
            if ((retval = tackProcessBreakSigs(ctx, &nameRecord, crypto)) != TACK_OK)
                return retval;
        }
        
        /* If there's a key record and tack, do generation processing */
        if (ctx->tack && minGeneration) {            
            if (tackTackGetGeneration(ctx->tack) < *minGeneration)
                return TACK_ERR_REVOKED_GENERATION;
            
            if (tackTackGetMinGeneration(ctx->tack) > *minGeneration)
                *minGenerationOut = tackTackGetMinGeneration(ctx->tack);
        }
        
        /* Note if tack matches pin */
        if (nameRecord && ctx->tack) {
            if (strcmp(ctx->tackFingerprint, nameRecord->fingerprint) == 0) 
                tackMatchesPin = 1;
        }
    }

    /* If there's a relevant active pin, determine if it accepts the connection */
    if (nameRecord && nameRecord->endTime > currentTime) {
        if (tackMatchesPin)
            resultRetval = TACK_OK_ACCEPTED;
        else
            resultRetval = TACK_OK_REJECTED;
    }
    else
        resultRetval = TACK_OK_UNPINNED;
    
    /* Calculate pin activation */
    if (resultRetval != TACK_OK_REJECTED) {
        if ((retval=tackProcessPinActivation(ctx, currentTime, nameRecord, nameRecordOut,
                                             minGenerationOut, 
                                             tackMatchesPin, crypto)) < TACK_OK)
            return retval;
        *activationRetval = retval;    
    }

    return resultRetval;
}

static TACK_RETVAL tackProcessBreakSigs(TackProcessingContext* ctx,
                                        TackNameRecord** nameRecord,
                                        TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t count = 0;
    char breakFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t* breakSig = NULL;

    /* Iterate through break sigs */
    for (count = 0; count < tackExtensionGetNumBreakSigs(ctx->tackExt); count++) {
        
        /* Get the fingerprint for each break sig */
        breakSig = tackExtensionGetBreakSig(ctx->tackExt, count);
        retval=tackBreakSigGetKeyFingerprint(breakSig, breakFingerprint, crypto);
        if (retval != TACK_OK)
            return retval;

        /* If the break sig matches the pin, verify it, then clear the pin */
        /* Use breakSigFlags to memorize which signatures have already been verified */
        if (strcmp((*nameRecord)->fingerprint, breakFingerprint) == 0) {
            if (ctx->breakSigFlags & (1<<count))
                *nameRecord = NULL;
            else if ((retval=tackBreakSigVerifySignature(breakSig, crypto)) == TACK_OK) {
                *nameRecord = NULL;
                ctx->breakSigFlags |= (1<<count);
            }
            return retval;
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

    /* The first step in pin activation is to delete a relevant but inactive
       pin unless there is a tack and the pin references the tack's key */
    if (nameRecord && (nameRecord->endTime <= currentTime) && !tackMatchesPin) {
        nameRecord = NULL;
        retval = TACK_OK_DELETE_PIN;
    }
    
    /* If there is no tack, or if the activation flag is disabled, then this 
       completes the algorithm.  Otherwise, the following steps are executed:*/
    if (!ctx->tack || (tackExtensionGetActivationFlag(ctx->tackExt) == 0))
        return retval;
    
    if (tackMatchesPin) {
        /* If there is a relevant pin referencing the tack's key, the name
           record's "end time" SHALL be set using the below formula: */
        nameRecordOut->endTime = currentTime + (currentTime - nameRecord->initialTime);
        return TACK_OK_UPDATE_PIN;
    }
    if (!nameRecord)  {
        /* If there is no relevant pin a new pin SHALL be created: */
        strcpy(nameRecordOut->fingerprint, ctx->tackFingerprint);
        *minGenerationOut = tackTackGetMinGeneration(ctx->tack);
        nameRecordOut->initialTime = currentTime;
        nameRecordOut->endTime = 0;
        return TACK_OK_NEW_PIN;
    }
    return retval;
}
