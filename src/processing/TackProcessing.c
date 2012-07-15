/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackUtil.h"
#include "TackProcessing.h"
#include "TackExtension.h"

/* Helper functions for tackProcess: */

static TACK_RETVAL tackProcessTack(uint8_t* tack,
                                   uint8_t keyHash[TACK_HASH_LENGTH],
                                   uint32_t currentTime,
                                   TackStoreFuncs* store,
                                   TackCryptoFuncs* crypto);

static TACK_RETVAL tackProcessBreakSigs(uint8_t* tackExt,
                                        TackStoreFuncs* store,
                                        TackCryptoFuncs* crypto);

static TACK_RETVAL tackProcessPinActivation(void* name,
                                            uint8_t* tackExt,
                                            uint32_t currentTime,
                                            TackStoreFuncs* store,
                                            TackCryptoFuncs* crypto); 

static TACK_RETVAL tackProcessResult(void* name,
                                     uint8_t* tackExt, 
                                     uint32_t currentTime,
                                     TackStoreFuncs* store, 
                                     TackCryptoFuncs* crypto);

static TACK_RETVAL tackProcessGetTackAndPin(void* name,
                                            uint8_t* tackExt, uint8_t** tack, 
                                            char* tackFingerprint, 
                                            TackPinStruct* pinStruct, 
                                            TackPinStruct**pin, 
                                            uint8_t* tackMatchesPin,
                                            TackStoreFuncs* store, 
                                            TackCryptoFuncs* crypto);

TACK_RETVAL tackProcess(void* name,
                        uint8_t* tackExt, uint32_t tackExtLen,
                        uint8_t keyHash[TACK_HASH_LENGTH],
                        uint32_t currentTime,
                        uint8_t doPinActivation,
                        TackStoreFuncs* store,
                        TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;  
    TACK_RETVAL result = TACK_ERR;
    
    /* If there's a TACK Extension, do: */
    if (tackExt) {
        
        /* Check extension syntax */
        if ((retval = tackExtensionSyntaxCheck(tackExt, tackExtLen)) != TACK_OK)
            return retval;
        
        /* Process the tack if present */
        if (tackExtensionGetTack(tackExt)) {
            if ((retval=tackProcessTack(tackExtensionGetTack(tackExt), 
                                        keyHash, currentTime,
                                        store, crypto)) != TACK_OK)
                return retval;
        }
        
        /* Process the break sigs if present */
        if (tackExtensionGetNumBreakSigs(tackExt) > 0) {
            if ((retval=tackProcessBreakSigs(tackExt, store, crypto)) != TACK_OK)
                return retval;
        }
    }

    /* Determine the result */
    result = tackProcessResult(name, tackExt, currentTime, store, crypto);
    
    /* Do pin activation if requested */
    if (doPinActivation) {
        if ((retval=tackProcessPinActivation(name, tackExt, currentTime,
                                             store, crypto)) != TACK_OK)
            return retval;
    }

    return result;
}


TACK_RETVAL tackProcessTack(uint8_t* tack,
                            uint8_t keyHash[TACK_HASH_LENGTH],
                            uint32_t currentTime,
                            TackStoreFuncs* store,
                            TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t krMinGeneration = 0;
    uint8_t tackMinGeneration = 0;
    uint8_t foundKeyRecord = 0;
    char tackFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];

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
        if (retval < TACK_OK)
            return retval;
        
        /* Ignore TACK_OK_NOT_FOUND in case the key was deleted out from 
           under us (e.g. due to multithreading) */
    }
    
    return TACK_OK;
}

TACK_RETVAL tackProcessBreakSigs(uint8_t* tackExt,
                                 TackStoreFuncs* store,
                                 TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t count = 0;
    char breakKeyFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t* breakSig = NULL;
    uint8_t krMinGeneration = 0;

    /* Iterate through break sigs */
    for (count = 0; count < tackExtensionGetNumBreakSigs(tackExt); count++) {
        
        /* Get the fingerprint for each break sig */
        breakSig = tackExtensionGetBreakSig(tackExt, count);
        tackBreakSigGetKeyFingerprint(breakSig, breakKeyFingerprint, crypto);

        /* Check if there's a matching key record in the key store */
        if ((retval = store->getKeyRecord(store->arg, breakKeyFingerprint, 
                                          &krMinGeneration)) < TACK_OK)
            return retval;
        
        /* If there's a matching key record, verify the break sig */
        if (retval == TACK_OK) {
            retval=tackBreakSigVerifySignature(breakSig, crypto);
            if (retval != TACK_OK)
                return retval;
            
            /* If verified, delete the key record */
            if ((retval=store->deleteKeyRecord(store->arg, 
                                               breakKeyFingerprint)) < TACK_OK)
                return retval;
            
            /* Ignore TACK_OK_NOT_FOUND in case the key was deleted out from 
               under us (e.g. due to multithreading) */
        }
    }
    return TACK_OK;
}

TACK_RETVAL tackProcessPinActivation(void* name, 
                                     uint8_t* tackExt,
                                     uint32_t currentTime,
                                     TackStoreFuncs* store,
                                     TackCryptoFuncs* crypto) 
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t* tack = NULL;
    char tackFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    TackPinStruct pinStruct;
    TackPinStruct* pin = NULL;
    uint8_t tackMatchesPin = 0;
    uint8_t count = 0;
    uint8_t* breakSig = NULL;
    char breakKeyFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t tackMatchesBreakSig = 0;

    /* Fetch tack and relevant pin (if any) */
    retval = tackProcessGetTackAndPin(name, tackExt, &tack, tackFingerprint, 
                                      &pinStruct, &pin, &tackMatchesPin,
                                      store, crypto);
    if (retval != TACK_OK)
        return retval;

    /* Determine whether tack matches any break sig */
    if (tack) {
        for (count = 0; count < tackExtensionGetNumBreakSigs(tackExt); count++) {
            
            /* Get the fingerprint for each break sig */
            breakSig = tackExtensionGetBreakSig(tackExt, count);
            tackBreakSigGetKeyFingerprint(breakSig, breakKeyFingerprint, crypto);
            
            if (strcmp(tackFingerprint, breakKeyFingerprint) == 0)
                tackMatchesBreakSig = 1;
        }
    }
    
    /* The first step in pin activation is to delete a relevant but inactive
       pin unless there is a tack and the pin references the tack's key */
    if (pin && (pin->endTime <= currentTime) && !tackMatchesPin) {
        if ((retval=store->deletePin(store->arg, name)) < TACK_OK)
            return retval;
        pin = NULL;
        
        /* Ignore TACK_OK_NOT_FOUND in case the pin was deleted out from 
           under us (e.g. due to multithreading) */
    }
    
    /* If there is no tack, or if the activation flag is disabled, then this 
       completes the algorithm.  Otherwise, the following steps are executed:*/
    if (!tack || (tackExtensionGetActivationFlag(tackExt) == 0))
        return TACK_OK;
    
    if (pin) {
        /* If there is a relevant pin referencing the tack's key, the name
           record's "active period end" SHALL be set using the below formula: */
        if (tackMatchesPin) {
            retval = store->updatePin(store->arg, name, 
                                      currentTime + (currentTime - pin->initialTime));
            if (retval != TACK_OK)
                return retval;
        }
    }
    else if (!tackMatchesBreakSig)  {
        /* If there is no relevant pin, and the tack's key is not equal to any
           break signature's key, a new pin SHALL be created: */

        pinStruct.minGeneration = tackTackGetMinGeneration(tack);
        strcpy(pinStruct.keyFingerprint, tackFingerprint);
        pinStruct.initialTime = currentTime;
        pinStruct.endTime = 0;
        retval = store->newPin(store->arg, name, &pinStruct);
        if (retval != TACK_OK)
            return retval;

    }
    return TACK_OK;
}

TACK_RETVAL tackProcessResult(void* name, uint8_t* tackExt, uint32_t currentTime,
                              TackStoreFuncs* store, 
                              TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t* tack = NULL;
    char tackFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    TackPinStruct pinStruct;
    TackPinStruct* pin = NULL;
    uint8_t tackMatchesPin = 0;

    /* Fetch tack and relevant pin (if any) */
    retval = tackProcessGetTackAndPin(name, tackExt, &tack, tackFingerprint, 
                                      &pinStruct, &pin, &tackMatchesPin,
                                      store, crypto);
    if (retval != TACK_OK)
        return retval;

    /* If there's a relevant active pin... */
    if (pin && pin->endTime > currentTime) {
        if (tackMatchesPin)
            return TACK_OK_ACCEPTED;
        else
            return TACK_OK_REJECTED;
    }
    return TACK_OK_UNPINNED;
}

TACK_RETVAL tackProcessGetTackAndPin(void* name,
                                     uint8_t* tackExt, uint8_t** tack, 
                                     char* tackFingerprint, 
                                     TackPinStruct* pinStruct, 
                                     TackPinStruct** pin, 
                                     uint8_t* tackMatchesPin,
                                     TackStoreFuncs* store, 
                                     TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;
    
    /* Get the relevant pin, if any */
    if ((retval=store->getPin(store->arg, name, pinStruct)) < TACK_OK)
        return retval;
    /* Set "pin" to point to the relevant pin, or NULL */
    if (retval == TACK_OK)
        *pin = pinStruct;

    if (!tackExt)
        return TACK_OK;
    
    /* Get tack fingerprint, if any */
    *tack = tackExtensionGetTack(tackExt);
    if (*tack) {
        if ((retval=tackTackGetKeyFingerprint(*tack, tackFingerprint, crypto)) != TACK_OK)
            return retval;
    }

    /* Determine whether tack matches pin */
    if (*pin && *tack && (strcmp(tackFingerprint, (*pin)->keyFingerprint)==0))
        *tackMatchesPin = 1;
    else
        *tackMatchesPin = 0;
    
    return TACK_OK;
}
