/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackUtil.h"
#include "TackProcessing.h"
#include "TackExtension.h"

static TACK_RETVAL tackProcessBreakSigs(TackProcessingContext* ctx,
                                        TackPin** pin,
                                        TackCryptoFuncs* crypto);

static TACK_RETVAL tackProcessPinActivation(TackProcessingContext* ctx,
                                            uint32_t currentTime,
                                            TackPin* pin, TackPin* pinOut,
                                            uint8_t tackMatchesPin,
                                            TackCryptoFuncs* crypto);


TACK_RETVAL tackProcessWellFormed(uint8_t* tackExt, uint32_t tackExtLen,
                                  uint8_t keyHash[TACK_HASH_LENGTH],
                                  uint32_t currentTime,
                                  TackProcessingContext* ctx,
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
        if (tackTackGetExpiration(ctx->tack) < currentTime)
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
                             uint32_t currentTime,   
                             TackPin* pin,
                             uint8_t minGeneration,
                             TACK_RETVAL* activationRetval,
                             TackPin* pinOut,
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
           If it is, mask the pin (pin = NULL) */
        if (pin && pin->endTime > currentTime) {
            if ((retval = tackProcessBreakSigs(ctx, &pin, crypto)) != TACK_OK)
                return retval;
        }
        
        /* Generation processing */
        if (ctx->tack) {            
            if (tackTackGetGeneration(ctx->tack) < minGeneration)
                return TACK_ERR_REVOKED_GENERATION;
            
            if (tackTackGetMinGeneration(ctx->tack) > minGeneration)
                *minGenerationOut = tackTackGetMinGeneration(ctx->tack);
        }
        
        /* Note if tack matches pin */
        if (pin && ctx->tack) {
            if (strcmp(ctx->tackFingerprint, pin->fingerprint) == 0) 
                tackMatchesPin = 1;
        }
    }

    /* If there's a relevant active pin, determine if it accepts the connection */
    if (pin && pin->endTime > currentTime) {
        if (tackMatchesPin)
            resultRetval = TACK_OK_ACCEPTED;
        else
            resultRetval = TACK_OK_REJECTED;
    }
    else
        resultRetval = TACK_OK_UNPINNED;
    
    /* Calculate pin activation */
    if (resultRetval != TACK_OK_REJECTED) {
        if ((retval=tackProcessPinActivation(ctx, currentTime, pin, pinOut,
                                             tackMatchesPin, crypto)) < TACK_OK)
            return retval;
        *activationRetval = retval;    
    }

    return resultRetval;
}

static TACK_RETVAL tackProcessBreakSigs(TackProcessingContext* ctx,
                                        TackPin** pin,
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
        if (strcmp((*pin)->fingerprint, breakFingerprint) == 0) {
            if (ctx->breakSigFlags & (1<<count))
                *pin = NULL;
            else if ((retval=tackBreakSigVerifySignature(breakSig, crypto)) == TACK_OK) {
                *pin = NULL;
                ctx->breakSigFlags |= (1<<count);
            }
            return retval;
        }
    }
    return TACK_OK;
}

static TACK_RETVAL tackProcessPinActivation(TackProcessingContext* ctx,
                                            uint32_t currentTime,
                                            TackPin* pin, TackPin* pinOut,
                                            uint8_t tackMatchesPin,
                                            TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_OK;

    /* The first step in pin activation is to delete a relevant but inactive
       pin unless there is a tack and the pin references the tack's key */
    if (pin && (pin->endTime <= currentTime) && !tackMatchesPin) {
        pin = NULL;
        retval = TACK_OK_DELETE_PIN;
    }
    
    /* If there is no tack, or if the activation flag is disabled, then this 
       completes the algorithm.  Otherwise, the following steps are executed:*/
    if (!ctx->tack || (tackExtensionGetActivationFlag(ctx->tackExt) == 0))
        return retval;
    
    if (tackMatchesPin) {
        /* If there is a relevant pin referencing the tack's key, the name
           record's "end time" SHALL be set using the below formula: */
        pinOut->endTime = currentTime + (currentTime - pin->initialTime);
        return TACK_OK_UPDATE_PIN;
    }
    if (!pin)  {
        /* If there is no relevant pin a new pin SHALL be created: */
        strcpy(pinOut->fingerprint, ctx->tackFingerprint);
        pinOut->minGeneration = tackTackGetMinGeneration(ctx->tack);
        pinOut->initialTime = currentTime;
        pinOut->endTime = 0;
        return TACK_OK_NEW_PIN;
    }
    return retval;
}
