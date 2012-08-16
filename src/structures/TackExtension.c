/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackUtil.h"
#include "TackExtension.h"

/* The following two functions calculate offsets into the tackExt 
 (assume a syntactically-correct TACK_Extension; check this prior) */
uint8_t* tackExtensionPostTacks(uint8_t* tackExt) {
    return tackExt + 2 + ptou16(tackExt);
}

uint8_t* tackExtensionPostBreakSigs(uint8_t* tackExt) {
    uint8_t* p = tackExtensionPostTacks(tackExt);
    return p + 2 + ptou16(p);
}

uint8_t tackExtensionGetNumTacks(uint8_t* tackExt) {
    return (uint8_t)(ptou16(tackExt) / TACK_LENGTH);
}

uint8_t* tackExtensionGetTack(uint8_t* tackExt, uint8_t index) {
    return tackExt + 2 + (index * TACK_LENGTH);
}

uint8_t tackExtensionGetNumBreakSigs(uint8_t* tackExt) {
    uint8_t* p = tackExtensionPostTacks(tackExt);
    return (uint8_t)(ptou16(p) / TACK_BREAKSIG_LENGTH);
}

uint8_t* tackExtensionGetBreakSig(uint8_t* tackExt, uint8_t index) {
    uint8_t* p = tackExtensionPostTacks(tackExt);
    return p + 2 + (index * TACK_BREAKSIG_LENGTH);
}

uint8_t tackExtensionGetActivationFlags(uint8_t* tackExt) {
    return *(tackExtensionPostBreakSigs(tackExt));
}

#include <stdio.h>

TACK_RETVAL tackExtensionSyntaxCheck(uint8_t* tackExt, uint32_t tackExtLen)
{
    TACK_RETVAL retval = TACK_ERR;
    uint16_t tackLen = 0;
    uint8_t tackIndex = 0;
    uint16_t breakSigsLen = 0;
    uint8_t activationFlags = 0;

    /* Check 2-byte tacks length */
    /* (decrement tackExtLen as we process each field, ensure it reaches 0 at end) */
    if (tackExtLen < 2)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    tackExtLen -= 2;

    tackLen = ptou16(tackExt);
    if (tackLen % TACK_LENGTH != 0)
        return TACK_ERR_BAD_TACK_LENGTH;
    if (tackLen / TACK_LENGTH > TACK_TACK_MAXCOUNT)
        return TACK_ERR_BAD_TACK_LENGTH;

    if (tackExtLen < tackLen)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    tackExtLen -= tackLen;
    
    /* Check tacks */
    for (tackIndex=0; tackIndex < tackLen / TACK_LENGTH; tackIndex++) {
        retval = tackTackSyntaxCheck(tackExtensionGetTack(tackExt, tackIndex));
        if (retval != TACK_OK)
            return retval;
    }
    
    /* Check 2-byte break sigs length */
    if (tackExtLen < 2)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    tackExtLen -= 2;

    breakSigsLen = ptou16( tackExtensionPostTacks(tackExt) );
    if (breakSigsLen % TACK_BREAKSIG_LENGTH != 0)
        return TACK_ERR_BAD_BREAKSIGS_LENGTH;
    if (breakSigsLen / TACK_BREAKSIG_LENGTH > TACK_BREAKSIGS_MAXCOUNT)
        return TACK_ERR_BAD_BREAKSIGS_LENGTH;

    if (tackExtLen < breakSigsLen)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    tackExtLen -= breakSigsLen;
    
    /* Nothing to check for break sigs */

    if (tackExtLen != 1)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    
    /* Check activation flag */
    activationFlags = tackExtensionGetActivationFlags(tackExt);
    if (activationFlags > 3)
        return TACK_ERR_BAD_ACTIVATION_FLAG;
    
    return TACK_OK;
}
