/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <stdio.h>
#include <string.h>
#include "TackPinList.h"

TACK_RETVAL tackPinListWriteEntry(char* list, uint32_t* listLen, 
                                    const char* name, TackPin* pin, 
                                    uint8_t minGeneration)
{
    /* Write into a separate buffer first, so we can determine length of the 
       entry, and write the whole entry (or not) into the out buffer */
    char buf[1024];
    int bufLen = sizeof(buf);
    int ret = 0;

    ret = snprintf(buf, bufLen,
                   "\"%s\": [%u, %u, \"%s\", %u]", 
                   name, pin->initialTime, pin->endTime,
                   pin->fingerprint, minGeneration);
    if (ret >= bufLen)
        return TACK_ERR_UNDERSIZED_BUFFER;
    
    if (ret >= (int)*listLen)
        return TACK_OK_INCOMPLETE_WRITE;

    memcpy(list, buf, ret);
    *listLen -= ret;
    return TACK_OK;
}

TACK_RETVAL tackPinListParseEntry(const char* list, uint32_t* listLen, 
                                  char* name, TackPin* pin, 
                                  uint8_t* minGeneration)
{
    uint32_t initialTime = 0;
    uint32_t endTime = 0;
    uint8_t minGen = 0;
    int ret = 0;
    char nameBuf[256];
    char fingerprintBuf[30];  // 29 char fingerprint +1 for NULL
    int numChars;

    memset(nameBuf, 0, sizeof(nameBuf));
    memset(fingerprintBuf, 0, sizeof(fingerprintBuf));
    
    ret = sscanf(list, "\"%255[^\"]\": [%u, %u, \"%29c\", %hhu]%n", 
                 nameBuf, &initialTime, &endTime, fingerprintBuf, &minGen, &numChars);
    
    if (ret != 5) {
        return TACK_ERR_BAD_PINLIST;
    }
    
    if (strlen(nameBuf) > 255) {
        return TACK_ERR_ASSERTION;
    }
    
    if (strlen(fingerprintBuf) != 29)
        return TACK_ERR_BAD_PINLIST;
    
    strcpy(name, nameBuf);
    strcpy(pin->fingerprint, fingerprintBuf);
    pin->initialTime = initialTime;
    pin->endTime = endTime;
    *minGeneration = minGen;
    *listLen -= numChars;
    
    return TACK_OK;
}
