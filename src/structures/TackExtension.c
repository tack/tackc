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
    
    // Check 1-byte tack length
    tackLen = *tackExt;
    if (tackLen != 0 && tackLen != TACK_LENGTH)
        return TACK_ERR_BAD_TACK_LENGTH;
    
    // Check tack
    tack = tackExtensionGetTack(tackExt);
    if (tack) {
        retval = tackTackSyntaxCheck(tack);
        if (retval != TACK_OK)
            return retval;
    }
    
    // Check 2-byte break sigs length
    p = tackExtensionPostTack(tackExt);
    breakSigsLen = ptou16(p);
    if (breakSigsLen % TACK_BREAKSIG_LENGTH != 0)
        return TACK_ERR_BAD_BREAKSIGS_LENGTH;
    if (breakSigsLen / TACK_BREAKSIG_LENGTH > TACK_BREAKSIGS_MAXCOUNT)
        return TACK_ERR_BAD_BREAKSIGS_LENGTH;
    
    // Nothing to check for break sigs
    
    // Check activation flag
    activationFlag = tackExtensionGetActivationFlag(tackExt);
    if (activationFlag > 1)
        return TACK_ERR_BAD_ACTIVATION_FLAG;
    
    // Check length
    if (tackExt + tackExtLen != tackExtensionPostBreakSigs(tackExt)+1)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    
    return TACK_OK;
}

TACK_RETVAL tackExtensionProcess(uint8_t* tackExt, uint32_t tackExtLen,
                                 uint8_t keyHash[TACK_HASH_LENGTH],
                                 uint32_t currentTime,
                                 void* krArg,
                                 TackGetKeyRecordFunc getKrFunc,
                                 TackUpdateKeyRecordFunc updateKrFunc,
                                 TackDeleteKeyRecordFunc deleteKrFunc,
                                 TackHashFunc hashFunc, 
                                 TackVerifyFunc verifyFunc)
{
    uint8_t* tack = NULL;
    TACK_RETVAL retval = TACK_ERR;  
    char keyFingerprintBuf[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t krMinGeneration = 0;
    uint8_t foundKeyRecord = 0;
    uint8_t tackMinGeneration = 0;
    uint8_t* breakSig = NULL;
    uint8_t count=0;

    /* Check basic TACK_Extension syntax */
    if ((retval = tackExtensionSyntaxCheck(tackExt, tackExtLen)) != TACK_OK)
        return retval;

    /* Convert keyHash -> keyFingerprint */ 
    if ((retval=tackGetKeyFingerprintFromHash(keyHash, keyFingerprintBuf)) != TACK_OK)
        return retval;

    /* Lookup keyFingerprint -> keyRecord's minGeneration */
    if ((retval=getKrFunc(krArg, keyFingerprintBuf, &krMinGeneration)) < TACK_OK)
        return retval;
    if (retval == TACK_OK) // could be TACK_OK_NOT_FOUND
        foundKeyRecord = 1;
   
    // Process the tack if present
    tack = tackExtensionGetTack(tackExt);
    if (tack) {

        // Verify the tack's target_hash, signature, expiration, generation
        tackMinGeneration = krMinGeneration;
        retval = tackTackProcess(tack, keyHash,
                            &tackMinGeneration,
                            currentTime,
                            verifyFunc);
        if (retval != TACK_OK)
            return retval;

        // If minGeneration was incremented, set the keyRecord's value
        if (foundKeyRecord && tackMinGeneration > krMinGeneration) {
            retval=updateKrFunc(krArg, keyFingerprintBuf, tackMinGeneration);
            if (retval != TACK_OK)
                return retval;
        }
    }

    // Process the break signatures if present
    for (count=0; count < tackExtensionGetNumBreakSigs(tackExt); count++) {
        
        // Get the fingerprint for each break sig
        breakSig = tackExtensionGetBreakSig(tackExt, count);
        tackBreakSigGetKeyFingerprint(breakSig, keyFingerprintBuf, hashFunc);

        // If there's no matching key record, skip to next break sig
        if ((retval = getKrFunc(krArg, keyFingerprintBuf, &krMinGeneration)) < TACK_OK)
            return retval;
        if (retval == TACK_OK_NOT_FOUND)
            continue;

        // If there's a matching key record, verify the break sig
        retval=tackBreakSigVerifySignature(breakSig, verifyFunc);
        if (retval != TACK_OK)
            return retval;
        
        // If verified, delete the key record
        if ((retval=deleteKrFunc(krArg, keyFingerprintBuf)) != TACK_OK)
            return retval;
    }

    return TACK_OK;
}
