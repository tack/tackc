/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackUtil.h"
#include "TackExtension.h"

/* The following function calculates an offset into the tackExt 
 (assume a syntactically-correct TACK_Extension; check this prior) */
uint8_t* tackExtPostTacks(uint8_t* tackExt) {
    return tackExt + 2 + ptou16(tackExt);
}

uint8_t tackExtGetNumTacks(uint8_t* tackExt) {
    return (uint8_t)(ptou16(tackExt) / TACK_LENGTH);
}

uint8_t* tackExtGetTack(uint8_t* tackExt, uint8_t index) {
    return tackExt + 2 + (index * TACK_LENGTH);
}

uint8_t tackExtGetActivationFlags(uint8_t* tackExt) {
    return *(tackExtPostTacks(tackExt));
}

uint8_t tackExtGetActivationFlag(uint8_t* tackExt, uint8_t index) {
    return (*(tackExtPostTacks(tackExt))) & (1 << index);
}

TACK_RETVAL tackExtSyntaxCheck(uint8_t* tackExt, uint32_t tackExtLen)
{
    if (tackExtLen == 3 + TACK_LENGTH) {
        if (ptou16(tackExt) != TACK_LENGTH)
            return TACK_ERR_BAD_TACKS_LENGTH;
    }
    else if (tackExtLen == 3 + TACK_LENGTH*2) {
        if (ptou16(tackExt) != TACK_LENGTH*2)
            return TACK_ERR_BAD_TACKS_LENGTH;
    }
    else
        return TACK_ERR_BAD_TACKEXT_LENGTH;

    if (tackExtGetActivationFlags(tackExt) > 3)
        return TACK_ERR_BAD_ACTIVATION_FLAGS;

    return TACK_OK;
}
