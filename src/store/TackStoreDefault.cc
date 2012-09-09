#include "TackStoreDefault.h"
#include "TackPinList.h"
#include "TackStoreFuncs.h"

// These don't do anything but Chromium wants them:
TackStoreDefault::TackStoreDefault(){}
TackStoreDefault::~TackStoreDefault(){}


TACK_RETVAL TackStoreDefault::getMinGeneration(const std::string& keyFingerprint, 
                                           uint8_t* minGeneration)
{
    std::map<std::string, uint8_t>::iterator ki = keyRecords_.find(keyFingerprint);
    if (ki == keyRecords_.end())
        return TACK_OK_NOT_FOUND;

    *minGeneration = ki->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setMinGeneration(const std::string& keyFingerprint, 
                                               uint8_t minGeneration)
{
    std::map<std::string, uint8_t>::iterator ki = keyRecords_.find(keyFingerprint);
    if (ki == keyRecords_.end())
        keyRecords_[keyFingerprint] = minGeneration;
    else if (minGeneration > ki->second)
        ki->second = minGeneration;

    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::getNameRecordPair(const std::string& name, 
                                            TackNameRecordPair* pair)
{
    std::map<std::string, TackNameRecordPair>::iterator ni = nameRecords_.find(name);
    if (ni == nameRecords_.end()) {
        pair->numPins = 0;
        return TACK_OK_NOT_FOUND;
    }

    *pair = ni->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setNameRecordPair(const std::string& name, 
                                            const TackNameRecordPair* pair)
{
    if (pair->numPins == 0)
        nameRecords_.erase(name);
    else
        nameRecords_[name] = *pair;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::clear()
{
    nameRecords_.clear();
    keyRecords_.clear();
    return TACK_OK;
}


/* Specify the length of the buffer - will not be overwritten, but only
   listLen-1 chars can actually be stored, due to final NULL */
TACK_RETVAL TackStoreDefault::serialize(char* list, uint32_t* listLen)
{
    std::map<std::string, TackNameRecordPair>::iterator ni;
    uint32_t oldListLen = 0;
    uint8_t minGeneration = 0;
    uint8_t count = 0;
    TACK_RETVAL retval = TACK_OK; /* default return */

    if (*listLen < 2) /* account for the NULL */
        return TACK_ERR_UNDERSIZED_BUFFER;
    *list++ = '{';
    *listLen -= 1;

    bool firstTime = true;
    for (ni=nameRecords_.begin(); ni != nameRecords_.end(); ni++)  {

        // Iterate through all pin pairs, then each in pin the pair...
        for (count=0; count < ni->second.numPins; count++) {
            TackNameRecord* nameRecord = &(ni->second.records[count]);

            retval=getMinGeneration(nameRecord->fingerprint, &minGeneration);
            if (retval != TACK_OK)
                return retval;
            
            // Write comma prior to every entry but first
            if (firstTime)
                firstTime = false;
            else {
                if (*listLen < 2)
                    return TACK_ERR_UNDERSIZED_BUFFER;
                *list++ = ',';
                *listLen -= 1;
            }
            
            if (*listLen < 2)
                return TACK_ERR_UNDERSIZED_BUFFER;
            *list++ = '\n';
            *listLen -= 1;
            
            // Write the entry
            oldListLen = *listLen;
            if ((retval=tackPinListWriteEntry(list, listLen,
                                              ni->first.c_str(), nameRecord,
                                              minGeneration)) != TACK_OK)
                return retval;
            
            if (retval == TACK_OK_INCOMPLETE_WRITE)
                return TACK_ERR_UNDERSIZED_BUFFER;
            
            list += (oldListLen - *listLen);
        }    
    }
    
    if (*listLen < 4)
        return TACK_ERR_UNDERSIZED_BUFFER;
    *list++ = '\n';
    *list++ = '}';
    *list++ = '\n';
    *list++ = 0;
    *listLen -= 3;

    return retval;
}

TACK_RETVAL TackStoreDefault::deserialize(const char* list, uint32_t* listLen)
{
    uint8_t state = 0;
    /* 0 = Start (before '{')
       1 = Before entry (before entry or '}')
       2 = After entry (before ',' or '}')
    */

    TACK_RETVAL retval = TACK_ERR;
    char name[256]; // 255-char length plus NULL
    char prevName[256]; // " "
    TackNameRecord nameRecord;
    TackNameRecordPair pair;
    uint8_t minGeneration = 0;
    uint32_t oldListLen = 0;

    clear();
    memset(name, 0, sizeof(name));
    memset(prevName, 0, sizeof(prevName));
    memset(&nameRecord, 0, sizeof(TackNameRecord));
    memset(&pair, 0, sizeof(TackNameRecordPair));

    while (1) {

        // Check for end of string
        if ((*list == 0) || (*listLen == 0)) {
            if (state != 0)
                return TACK_ERR_BAD_PINLIST;
            break;
        }

        // Skip whitespace
        if (*list == ' ' || *list == '\n' || *list == '\t')
        {}

        else if (state == 0) { // Start
            if (*list == '{')
                state = 1;
            else {
                return TACK_ERR_BAD_PINLIST;
            }
        }

        else if (state == 1)  { // Before entry
            if (*list == '}') {
                break;
            }
            else {
                oldListLen = *listLen;
                strcpy(prevName, name);
                retval = tackPinListParseEntry(list, listLen,
                                               name, &nameRecord, &minGeneration);

                /* Set key record first */
                retval = setMinGeneration(nameRecord.fingerprint, minGeneration);
                if (retval != TACK_OK)
                    return retval;

                /* Add name record into pair */
                if (pair.numPins == 0) {                    
                    memcpy(pair.records, &nameRecord, sizeof(TackNameRecord));
                    pair.numPins = 1;
                }
                else if (pair.numPins == 1) {
                    /* Set existing unpaired element, replace with new one */
                    if (strcmp(prevName, name) != 0) {
                        if ((retval = setNameRecordPair(prevName, &pair)) != TACK_OK)
                            return retval;
                        memcpy(pair.records+0, &nameRecord, sizeof(TackNameRecord));
                    }
                    /* Set a pair of name records */
                    else {
                        memcpy(pair.records+1, &nameRecord, sizeof(TackNameRecord));
                        pair.numPins = 2;
                        if ((retval = setNameRecordPair(name, &pair)) != TACK_OK)
                            return retval;
                        pair.numPins = 0;
                    }
                }

                list += (oldListLen - *listLen);
                state = 2;
                continue;
            }
        }

        else if (state == 2) { // After entry
            if (*list == ',')
                state = 1;
            else if (*list == '}') {
                break;
            }
            else {
                return TACK_ERR_BAD_PINLIST;
            }
        }
        list++;
        *listLen -= 1;
    }
           
    if (pair.numPins) {
        if ((retval = setNameRecordPair(name, &pair)) != TACK_OK)
            return retval;
    }

    return TACK_OK;
}

uint32_t TackStoreDefault::numPinned()
{
    return nameRecords_.size();
}

uint32_t TackStoreDefault::numKeys()
{
    return keyRecords_.size();
}
