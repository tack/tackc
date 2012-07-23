/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <stdio.h>
#include <string.h>
#include "TackPinList.h"

TACK_RETVAL tackPinListAddNameEntry(char* list, uint32_t* listLen, 
                                    const char* name, TackNameRecord* nameRecord, 
                                    uint8_t minGeneration)
{
    uint32_t ret = snprintf(list, *listLen, 
                            "\"%s\": [\"%s\", %u, %u, %u],\n", 
                            name, nameRecord->fingerprint,
                            nameRecord->initialTime, nameRecord->endTime, minGeneration);
    if (ret >= *listLen)
        return TACK_ERR_UNDERSIZED_BUFFER;
    *listLen -= ret;
    return TACK_OK;
}

TACK_RETVAL tackPinListAddKeyEntry(char* list, uint32_t* listLen,
                                   char* fingerprint, uint8_t minGeneration)
{
    uint32_t ret = snprintf(list, *listLen, ". %s %d", fingerprint, minGeneration);
    if (ret >= *listLen)
        return TACK_ERR_UNDERSIZED_BUFFER;
    *listLen -= ret;
    return TACK_OK;
}

TACK_RETVAL tackPinListParseEntry(char* list, uint32_t* listLen, 
                                  char* name, TackNameRecord* nameRecord, 
                                  uint8_t* minGeneration)
{
    unsigned int initialTime;
    unsigned int endTime;
    unsigned int minGen;
    char nameBuf[256];
    char fingerprintBuf[29];

    memset(nameBuf, 0, sizeof(nameBuf));
    memset(fingerprintBuf, 0, sizeof(fingerprintBuf));
    
    *listLen += sscanf(list, "%255s %29c %u %u %u", nameBuf, fingerprintBuf, 
                       &initialTime, &endTime, &minGen);

    return TACK_OK;
}
