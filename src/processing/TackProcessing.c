/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackUtil.h"
#include "TackProcessing.h"
#include "TackExtension.h"

static TACK_RETVAL tackProcessBreakSigs(uint8_t* tackExt,
                                        TackPinStruct** pin,
                                        TackStoreFuncs* store,
                                        TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t count = 0;
    char breakFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t* breakSig = NULL;

    /* Iterate through break sigs */
    for (count = 0; count < tackExtensionGetNumBreakSigs(tackExt); count++) {
        
        /* Get the fingerprint for each break sig */
        breakSig = tackExtensionGetBreakSig(tackExt, count);
        tackBreakSigGetKeyFingerprint(breakSig, breakFingerprint, crypto);

        /* If the break sig matches the pin, verify it, then clear the pin */
        if (strcmp((*pin)->keyFingerprint, breakFingerprint) == 0) {
            if ((retval=tackBreakSigVerifySignature(breakSig, crypto)) == TACK_OK)
                *pin = NULL;
            return retval;
        }
    }
    return TACK_OK;
}

static TACK_RETVAL tackProcessTack(uint8_t* tackExt, TackPinStruct* pin,
                            uint8_t keyHash[TACK_HASH_LENGTH],
                            uint32_t currentTime,
                            uint8_t* tack,
                            char* tackFingerprint,
                            uint8_t* tackMatchesPin,
                            TackStoreFuncs* store,
                            TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t krMinGeneration = 0;
    uint8_t tackMinGeneration = 0;
    uint8_t foundKeyRecord = 0;

    /* Determine fingerprint for tack key */
    if ((retval=tackTackGetKeyFingerprint(tack, tackFingerprint, crypto)) != TACK_OK)
        return retval;
    
    /* Lookup minGeneration based on tackFingerprint */
    if ((retval=store->getKeyRecord(store->arg, tackFingerprint, 
                                    &krMinGeneration)) < TACK_OK)
        return retval;
    if (retval == TACK_OK) /* else TACK_OK_NOT_FOUND */
        foundKeyRecord = 1;
    
    /* Verify all tack fields, check for minGeneration update */
    tackMinGeneration = krMinGeneration;
    retval = tackTackProcess(tack, keyHash, &tackMinGeneration, currentTime, crypto);
    if (retval != TACK_OK)
        return retval;
    
    /* If minGeneration was updated, set the keyRecord's value */
    if (foundKeyRecord && tackMinGeneration > krMinGeneration) {
        retval = store->updateKeyRecord(store->arg, tackFingerprint, 
                                        tackMinGeneration);
        if (retval != TACK_OK)
            return retval;
    }

    /* Determine if tack matches pin */
    if (pin && tack && (strcmp(tackFingerprint, pin->keyFingerprint)==0))
        *tackMatchesPin = 1;
    else
        *tackMatchesPin = 0;
    
    return TACK_OK;
}

static TACK_RETVAL tackProcessPinActivation(void* name, 
                                     uint8_t* tackExt,
                                     TackPinStruct* pin,
                                     uint32_t currentTime,
                                     uint8_t* tack,
                                     char* tackFingerprint,
                                     uint8_t tackMatchesPin,
                                     TackStoreFuncs* store,
                                     TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    TackPinStruct pinStruct;
    
    /* The first step in pin activation is to delete a relevant but inactive
       pin unless there is a tack and the pin references the tack's key */
    if (pin && (pin->endTime <= currentTime) && !tackMatchesPin) {
        if ((retval=store->deletePin(store->arg, name)) != TACK_OK)
            return retval;
        pin = NULL;
    }
    
    /* If there is no tack, or if the activation flag is disabled, then this 
       completes the algorithm.  Otherwise, the following steps are executed:*/
    if (!tack || (tackExtensionGetActivationFlag(tackExt) == 0))
        return TACK_OK;
    
    if (pin) {
        /* If there is a relevant pin referencing the tack's key, the name
           record's "end time" SHALL be set using the below formula: */
        if (tackMatchesPin) {
            retval = store->updatePin(store->arg, name, 
                                      currentTime + (currentTime - pin->initialTime));
            if (retval != TACK_OK)
                return retval;
        }
    }
    else  {
        /* If there is no relevant pin a new pin SHALL be created: */        
        pinStruct.minGeneration = tackTackGetMinGeneration(tack);
        strcpy(pinStruct.keyFingerprint, tackFingerprint);
        pinStruct.initialTime = currentTime;
        pinStruct.endTime = 0;
        if ((retval=store->newPin(store->arg, name, &pinStruct)) != TACK_OK)
            return retval;            
    }
    return TACK_OK;
}

TACK_RETVAL tackProcess(void* name, uint8_t* tackExt, uint32_t tackExtLen,
                        uint8_t keyHash[TACK_HASH_LENGTH],
                        uint32_t currentTime, uint8_t doPinActivation,
                        TackStoreFuncs* store, TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;  
    TackPinStruct pinStruct;
    TackPinStruct* pin = NULL;
    uint8_t* tack = NULL;
    char tackFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t tackMatchesPin = 0;

    /* Get the relevant pin, if any */
    if ((retval=store->getPin(store->arg, name, &pinStruct)) < TACK_OK)
        return retval;
    if (retval == TACK_OK)
        pin = &pinStruct;

    /* If there's a TACK Extension, do: */
    if (tackExt) {
        
        /* Check extension syntax */
        if ((retval = tackExtensionSyntaxCheck(tackExt, tackExtLen)) != TACK_OK)
            return retval;

        /* If there is a pin with break signatures, see if the pin is broken */
        if (pin && tackExtensionGetNumBreakSigs(tackExt)>0) {
            if ((retval = tackProcessBreakSigs(tackExt, &pin, store, crypto)) != TACK_OK)
                return retval;
        }
        
        /* If there's a tack, verify and process it, and see if it matches pin */
        if ((tack=tackExtensionGetTack(tackExt))) {
            if ((retval=tackProcessTack(tackExt, pin,
                                        keyHash, currentTime,
                                        tack,
                                        tackFingerprint,
                                        &tackMatchesPin,
                                        store, crypto)) != TACK_OK)
                return retval;
        }
    }
    
    /* Do pin activation if requested */
    if (doPinActivation) {
        if ((retval=tackProcessPinActivation(name, tackExt, pin, currentTime, 
                                             tack, tackFingerprint, tackMatchesPin,
                                             store, crypto)) != TACK_OK)
            return retval;
    }

    /* If there's a relevant active pin, determine if it accepts connection */
    if (pin && pin->endTime > currentTime) {
        if (tackMatchesPin)
            return TACK_OK_ACCEPTED;
        else
            return TACK_OK_REJECTED;
    }
    else
        return TACK_OK_UNPINNED;
}
