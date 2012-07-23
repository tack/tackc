/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <stdio.h>
#include <string.h>
#include "TackPinList.h"

TACK_RETVAL tackPinListWriteEntry(char* list, uint32_t* listLen, 
                                    const char* name, TackNameRecord* nameRecord, 
                                    uint8_t minGeneration)
{
    /* Write into a separate buffer first, so we can determine length of the 
       entry, and write the whole entry (or not) into the out buffer */
    char buf[1024];
    int bufLen = sizeof(buf);
    int ret = 0;

    ret = snprintf(buf, bufLen,
                   "\"%s\": [\"%s\", %u, %u, %u]", 
                   name, nameRecord->fingerprint,
                   nameRecord->initialTime, nameRecord->endTime, 
                   minGeneration);
    if (ret >= bufLen)
        return TACK_ERR_UNDERSIZED_BUFFER;
    
    if (ret >= (int)*listLen)
        return TACK_OK_INCOMPLETE_WRITE;

    memcpy(list, buf, ret);
    *listLen -= ret;
    return TACK_OK;
}

TACK_RETVAL tackPinListParseEntry(char* list, uint32_t* listLen, 
                                  char* name, TackNameRecord* nameRecord, 
                                  uint8_t* minGeneration)
{
    uint32_t initialTime = 0;
    uint32_t endTime = 0;
    uint8_t minGen = 0;
    int ret = 0;
    char nameBuf[256];
    char fingerprintBuf[30];  // 29 char fingerprint +1 for NULL

    memset(nameBuf, 0, sizeof(nameBuf));
    memset(fingerprintBuf, 0, sizeof(fingerprintBuf));
    
    ret = sscanf(list, "\"%255[^\"]\": [\"%29c\", %u, %u, %hhu]", 
                 nameBuf, fingerprintBuf, 
                 &initialTime, &endTime, &minGen);
    
    if (ret != 5) {
        return TACK_ERR_BAD_PINLIST_ENTRY;
    }
    
    if (strlen(nameBuf) > 255)
        return TACK_ERR_ASSERTION;
    
    if (strlen(fingerprintBuf) != 29)
        return TACK_ERR_BAD_PINLIST_ENTRY;
    
    strcpy(name, nameBuf);
    strcpy(nameRecord->fingerprint, fingerprintBuf);
    nameRecord->initialTime = initialTime;
    nameRecord->endTime = endTime;
    *minGeneration = minGen;
    
    return TACK_OK;
}
