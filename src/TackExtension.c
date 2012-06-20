/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackUtil.h"
#include "TackExtension.h"

TACK_RETVAL tackExtensionInit(TackExtension* tackExt, uint8_t* data, uint32_t len)
{
    uint8_t tackLen = 0;
    uint16_t breakSigsLen = 0;
    uint8_t* dataEnd = data + len;
    TACK_RETVAL retval = TACK_OK;
    
    memset(tackExt, 0, sizeof(TackExtension));
    
    /* Parse Tack */
    tackLen = *data++;
    if ((tackLen != 0) && (tackLen != TACK_LENGTH))
        return TACK_ERR_BAD_TACK_LENGTH;
    
    if (tackLen == TACK_LENGTH) {
        if ((retval=tackTackInit(&(tackExt->tack), data, TACK_LENGTH)) != TACK_OK)
            return retval;
        data += TACK_LENGTH;
        tackExt->tackCount = 1;
    }
    
    /* Parse Break Sigs */
    breakSigsLen = ptou16(data); data += 2;
    if ((breakSigsLen % TACK_BREAKSIG_LENGTH != 0) || 
        (breakSigsLen > TACK_BREAKSIGS_MAXCOUNT * TACK_BREAKSIG_LENGTH))
        return TACK_ERR_BAD_BREAKSIGS_LENGTH;
    
    tackExt->breakSigsCount = breakSigsLen / TACK_BREAKSIG_LENGTH;	
    for (uint8_t count=0; count < tackExt->breakSigsCount; count++) {
        if ((retval=tackBreakSigInit(&(tackExt->breakSigs[count]), 
                                     data, TACK_BREAKSIG_LENGTH)) != TACK_OK)
            return retval;
        data += TACK_BREAKSIG_LENGTH;
    }
    
    /* Parse Activation Flag */
    tackExt->activationFlag = *data++;
    if (tackExt->activationFlag > 1)
        return TACK_ERR_BAD_ACTIVATION_FLAG;
    
    if (data != dataEnd)
        return TACK_ERR_BAD_TACKEXT_LENGTH;

    return retval;
}

TACK_RETVAL tackExtensionVerifySignatures(TackExtension* tackExt, VerifyFunc func)
{
    TACK_RETVAL retval = TACK_OK;
    
    if (tackExt->tackCount) {
        if ((retval=tackTackVerifySignature(&(tackExt->tack), func))<0)
            return retval;
    }
    
    for (int count=0; count < tackExt->breakSigsCount; count++) {
        if ((retval=tackBreakSigVerifySignature(&(tackExt->breakSigs[count]), func))<0)
            return retval;
    }
    return retval;
}
