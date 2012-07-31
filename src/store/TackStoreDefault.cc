#include "TackStoreDefault.h"
#include "TackPinList.h"

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

TACK_RETVAL TackStoreDefault::deleteKey(const std::string& keyFingerprint)
{
    std::map<std::string, uint8_t>::iterator ki = keyRecords_.find(keyFingerprint);
    if (ki == keyRecords_.end())
        return TACK_OK_NOT_FOUND;

    std::map<std::string, TackNameRecord>::iterator ni = nameRecords_.begin();
    std::map<std::string, TackNameRecord>::iterator ni2;
    while (ni != nameRecords_.end()) {
        if (ni->second.fingerprint == keyFingerprint) {
            ni2 = ni;
            ni2++;
            nameRecords_.erase(ni);
            ni = ni2;
        }
        else
            ni++;
    }

    keyRecords_.erase(ki);
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::getNameRecord(const std::string& name, 
                                            TackNameRecord* nameRecord)
{
    std::map<std::string, TackNameRecord>::iterator ni = nameRecords_.find(name);
    if (ni == nameRecords_.end())
        return TACK_OK_NOT_FOUND;

    *nameRecord = ni->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setNameRecord(const std::string& name, 
                                            const TackNameRecord* nameRecord)
{
    nameRecords_[name] = *nameRecord;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::updateNameRecord(const std::string& name, 
                                               uint32_t newEndTime)
{
    std::map<std::string, TackNameRecord>::iterator ni = nameRecords_.find(name);
    if (ni == nameRecords_.end())
        return TACK_OK_NOT_FOUND;

    ni->second.endTime = newEndTime;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::deleteNameRecord(const std::string& name)
{
    std::map<std::string, TackNameRecord>::iterator ni = nameRecords_.find(name);
    if (ni == nameRecords_.end())
        return TACK_OK_NOT_FOUND;

    nameRecords_.erase(ni);
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
    std::map<std::string, TackNameRecord>::iterator ni;
    uint32_t oldListLen = 0;
    uint8_t minGeneration = 0;
    TACK_RETVAL retval = TACK_OK; /* default return */

    if (*listLen < 2) /* account for the NULL */
        return TACK_ERR_UNDERSIZED_BUFFER;
    *list++ = '{';
    *listLen -= 1;

    bool firstTime = true;
    for (ni=nameRecords_.begin(); ni != nameRecords_.end(); ni++)  {

        if ((retval=getMinGeneration(ni->second.fingerprint, &minGeneration)) != TACK_OK)
            return retval;

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

        oldListLen = *listLen;
        if ((retval=tackPinListWriteEntry(list, listLen,
                                          ni->first.c_str(), &ni->second,
                                          minGeneration)) != TACK_OK)
            return retval;

        /* If there's no more space in the out buffer, we're going to return
           (but use this as the retval) */
        if (retval == TACK_OK_INCOMPLETE_WRITE)
            break;

        list += (oldListLen - *listLen);
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
    TackNameRecord nameRecord;
    uint8_t minGeneration = 0;
    uint32_t oldListLen = 0;

    clear();

    while (*list && *listLen) {

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
            if (*list == '}')
                return TACK_OK;
            else {
                oldListLen = *listLen;
                retval = tackPinListParseEntry(list, listLen,
                                               name, &nameRecord, &minGeneration);
                list += (oldListLen - *listLen);

                if (retval != TACK_OK)
                    return retval;
                retval = setPin(name, &nameRecord, minGeneration);
                if (retval != TACK_OK)
                    return retval;

                state = 2;
                continue;
            }
        }
        else if (state == 2) { // After entry
            if (*list == ',')
                state = 1;
            else if (*list == '}')
                return TACK_OK;
            else {
                return TACK_ERR_BAD_PINLIST;
            }
        }
        list++;
        *listLen -= 1;
    }
    if (state == 0)
        return TACK_OK;
    return TACK_ERR_BAD_PINLIST;
}

uint32_t TackStoreDefault::numPins()
{
    return nameRecords_.size();
}

uint32_t TackStoreDefault::numKeys()
{
    return keyRecords_.size();
}
