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
uint8_t* tackExtensionPostTacks(uint8_t* tackExt) {
    return tackExt + 2 + ptou16(tackExt);
}

uint8_t tackExtensionGetNumTacks(uint8_t* tackExt) {
    return (uint8_t)(ptou16(tackExt) / TACK_LENGTH);
}

uint8_t* tackExtensionGetTack(uint8_t* tackExt, uint8_t index) {
    return tackExt + 2 + (index * TACK_LENGTH);
}

uint8_t tackExtensionGetActivationFlags(uint8_t* tackExt) {
    return *(tackExtensionPostTacks(tackExt));
}

uint8_t tackExtensionGetActivationFlag(uint8_t* tackExt, uint8_t index) {
    return (*(tackExtensionPostTacks(tackExt))) & (1 << index);
}

TACK_RETVAL tackExtensionSyntaxCheck(uint8_t* tackExt, uint32_t tackExtLen)
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

    if (tackExtensionGetActivationFlags(tackExt) > 3)
        return TACK_ERR_BAD_ACTIVATION_FLAGS;

    return TACK_OK;
}
