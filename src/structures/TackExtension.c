/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackUtil.h"
#include "TackExtension.h"

/* The following two functions calculate offsets into the tackExt */
uint8_t* tackExtensionPostTack(uint8_t* tackExt) {
    if (*tackExt == TACK_LENGTH)
        return tackExt + 1 + TACK_LENGTH;
    else	
        return tackExt + 1;
}

uint8_t* tackExtensionPostBreakSigs(uint8_t* tackExt) {
    uint8_t* p = tackExtensionPostTack(tackExt);
    return p + 2 + ptou16(p);
}


uint8_t* tackExtensionGetTack(uint8_t* tackExt) {
    if (*tackExt == TACK_LENGTH)
        return tackExt + 1;
    else
        return NULL;
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
    uint32_t breakSigsLen = 0;
    uint8_t activationFlag = 0;

    /* Check 1-byte tack length */
    /* (decrement tackExtLen as we process each field, ensure it reaches 0 at end) */
    if (tackExtLen < 1)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    tackExtLen--;

    tackLen = *tackExt;
    if (tackLen != 0 && tackLen != TACK_LENGTH)
        return TACK_ERR_BAD_TACK_LENGTH;
    
    /* Check tack */
    if (tackLen) {
        if (tackExtLen < TACK_LENGTH)
            return TACK_ERR_BAD_TACKEXT_LENGTH;
        tackExtLen -= TACK_LENGTH;

        retval = tackTackSyntaxCheck( tackExtensionGetTack(tackExt) );
        if (retval != TACK_OK)
            return retval;
    }
    
    /* Check 2-byte break sigs length */
    if (tackExtLen < 2)
        return TACK_ERR_BAD_TACKEXT_LENGTH;
    tackExtLen -= 2;

    breakSigsLen = ptou16( tackExtensionPostTack(tackExt) );
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
    activationFlag = tackExtensionGetActivationFlag(tackExt);
    if (activationFlag > 1)
        return TACK_ERR_BAD_ACTIVATION_FLAG;
    
    return TACK_OK;
}
