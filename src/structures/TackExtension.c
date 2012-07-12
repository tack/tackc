/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackUtil.h"
#include "TackExtension.h"

uint8_t* tackExtensionGetTack(uint8_t* tackExt) {
    if (*tackExt == TACK_LENGTH)
        return tackExt + 1;
    else
        return NULL;
}

/* The following two functions calculate offsets into the tackExt */
static uint8_t* tackExtensionPostTack(uint8_t* tackExt) {
    if (*tackExt == TACK_LENGTH)
        return tackExt + 1 + TACK_LENGTH;
    else	
        return tackExt + 1;
}

static uint8_t* tackExtensionPostBreakSigs(uint8_t* tackExt) {
    uint8_t* p = tackExtensionPostTack(tackExt);
    return p + 2 + ptou16(p);
}


uint8_t tackExtensionGetNumBreakSigs(uint8_t* tackExt) {
    uint8_t* p = tackExtensionPostTack(tackExt);
    return (uint8_t)(ptou16(p) / TACK_BREAKSIG_LENGTH);
}

uint8_t* tackExtensionGetBreakSig(uint8_t* tackExt, uint8_t index) {
    uint8_t* p = tackExtensionPostTack(tackExt);
    return p + 2 + (index * TACK_BREAKSIG_LENGTH);
}

uint8_t tackExtensionGetActivationFlag(uint8_t* tackExt) {
    return *(tackExtensionPostBreakSigs(tackExt));
}

TACK_RETVAL tackExtensionSyntaxCheck(uint8_t* tackExt, uint32_t tackExtLen)
{
    TACK_RETVAL retval = TACK_ERR;
    uint8_t tackLen = 0;
    uint8_t* tack = NULL;
    uint8_t* p = NULL;
    uint16_t breakSigsLen = 0;
    uint8_t activationFlag = 0;
    
    /* Check 1-byte tack length */
    tackLen = *tackExt;
    if (tackLen != 0 && tackLen != TACK_LENGTH)
        return TACK_ERR_BAD_TACK_LENGTH;
    
    /* Check tack */
    tack = tackExtensionGetTack(tackExt);
    if (tack) {
        retval = tackTackSyntaxCheck(tack);
        if (retval != TACK_OK)
            return retval;
    }
    
    /* Check 2-byte break sigs length */
    p = tackExtensionPostTack(tackExt);
    breakSigsLen = ptou16(p);
    if (breakSigsLen % TACK_BREAKSIG_LENGTH != 0)
        return TACK_ERR_BAD_BREAKSIGS_LENGTH;
    if (breakSigsLen / TACK_BREAKSIG_LENGTH > TACK_BREAKSIGS_MAXCOUNT)
        return TACK_ERR_BAD_BREAKSIGS_LENGTH;
    
    /* Nothing to check for break sigs */
    
    /* Check activation flag */
    activationFlag = tackExtensionGetActivationFlag(tackExt);
    if (activationFlag > 1)
        return TACK_ERR_BAD_ACTIVATION_FLAG;
    
    /* Check length */
    if (tackExt + tackExtLen != tackExtensionPostBreakSigs(tackExt)+1)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    
    return TACK_OK;
}


/* Helper functions for tackExtensionProcess: */

static TACK_RETVAL tackExtensionProcessTack(uint8_t* tack,
                                            uint8_t keyHash[TACK_HASH_LENGTH],
                                            uint32_t currentTime,
                                            TackStoreFuncs* store,
                                            TackCryptoFuncs* crypto);

static TACK_RETVAL tackExtensionProcessBreakSigs(uint8_t* tackExt,
                                                 TackStoreFuncs* store,
                                                 TackCryptoFuncs* crypto);

static TACK_RETVAL tackExtensionProcessPinActivation(uint8_t* tackExt,
                                                     uint32_t currentTime,
                                                     TackStoreFuncs* store,
                                                     TackCryptoFuncs* crypto); 

static TACK_RETVAL tackExtensionProcessResult(uint8_t* tackExt, 
                                              uint32_t currentTime,
                                              TackStoreFuncs* store, 
                                              TackCryptoFuncs* crypto);

static TACK_RETVAL tackExtensionProcessGetTackAndPin(uint8_t* tackExt, uint8_t** tack, 
                                                     char* tackFingerprint, 
                                                     TackPinStruct* pinStruct, 
                                                     TackPinStruct**pin, 
                                                     uint8_t* tackMatchesPin,
                                                     TackStoreFuncs* store, 
                                                     TackCryptoFuncs* crypto);

TACK_RETVAL tackExtensionProcess(uint8_t* tackExt, uint32_t tackExtLen,
                                 uint8_t keyHash[TACK_HASH_LENGTH],
                                 uint32_t currentTime,
                                 uint8_t doPinActivation,
                                 TackStoreFuncs* store,
                                 TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;  

    /* Check basic TACK_Extension syntax */
    if ((retval = tackExtensionSyntaxCheck(tackExt, tackExtLen)) != TACK_OK)
        return retval;

    /* Process the tack if present */
    if (tackExtensionGetTack(tackExt)) {
        if ((retval=tackExtensionProcessTack(tackExtensionGetTack(tackExt), 
                                             keyHash, currentTime,
                                             store, crypto)) != TACK_OK)
            return retval;
    }

    /* Process the break sigs if present */
    if (tackExtensionGetNumBreakSigs(tackExt) > 0) {
        if ((retval=tackExtensionProcessBreakSigs(tackExt, store, crypto)) != TACK_OK)
            return retval;
    }

    /* Do pin activation if requested */
    if (doPinActivation) {
        if ((retval=tackExtensionProcessPinActivation(tackExt, currentTime,
                                                      store, crypto)) != TACK_OK)
            return retval;
    }

    /* Determine the final result */
    return tackExtensionProcessResult(tackExt, currentTime, store, crypto);
}


TACK_RETVAL tackExtensionProcessTack(uint8_t* tack,
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

TACK_RETVAL tackExtensionProcessBreakSigs(uint8_t* tackExt,
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

TACK_RETVAL tackExtensionProcessPinActivation(uint8_t* tackExt,
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
    retval = tackExtensionProcessGetTackAndPin(tackExt, &tack, tackFingerprint, 
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
    if (pin && (pin->activePeriodEnd <= currentTime) && !tackMatchesPin) {
        if ((retval=store->deletePin(store->arg, store->argName)) < TACK_OK)
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
            retval = store->updatePin(store->arg, store->argName, 
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
        pinStruct.activePeriodEnd = 0;
        retval = store->newPin(store->arg, store->argName, &pinStruct);
        if (retval != TACK_OK)
            return retval;
    }
    return TACK_OK;
}

TACK_RETVAL tackExtensionProcessResult(uint8_t* tackExt, uint32_t currentTime,
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
    retval = tackExtensionProcessGetTackAndPin(tackExt, &tack, tackFingerprint, 
                                               &pinStruct, &pin, &tackMatchesPin,
                                               store, crypto);
    if (retval != TACK_OK)
        return retval;

    /* If there's a relevant active pin... */
    if (pin && pin->activePeriodEnd > currentTime) {
        if (tackMatchesPin)
            return TACK_OK_ACCEPTED;
        else
            return TACK_OK_REJECTED;
    }
    return TACK_OK_UNPINNED;
}

TACK_RETVAL tackExtensionProcessGetTackAndPin(uint8_t* tackExt, uint8_t** tack, 
                                              char* tackFingerprint, 
                                              TackPinStruct* pinStruct, 
                                              TackPinStruct** pin, 
                                              uint8_t* tackMatchesPin,
                                              TackStoreFuncs* store, 
                                              TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;

    /* Get the relevant pin, if any */
    if ((retval=store->getPin(store->arg, store->argName, pinStruct)) < TACK_OK)
        return retval;
    /* Set "pin" to point to the relevant pin, or NULL */
    if (retval == TACK_OK)
        *pin = pinStruct;

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
