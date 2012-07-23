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
    keyRecords_[keyFingerprint] = minGeneration;
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
                                            TackNameRecord* nameRecord)
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
    nameRecords_.erase(name);
    return TACK_OK; 
}

TACK_RETVAL TackStoreDefault::serialize(char* list, uint32_t* listLen)
{
    std::map<std::string, TackNameRecord>::iterator ni;
    uint32_t oldListLen = 0;
    uint8_t minGeneration = 0;
    TACK_RETVAL retval = TACK_ERR;

    if (*listLen < 2)
        return TACK_ERR_UNDERSIZED_BUFFER;
    *list++ = '{';
    *list++ = '\n';
    *listLen -= 2;

    for (ni=nameRecords_.begin(); ni != nameRecords_.end(); ni++)  {

        if ((retval=getMinGeneration(ni->second.fingerprint, &minGeneration)) != TACK_OK)
            return retval;

        oldListLen = *listLen;
        if ((retval=tackPinListAddNameEntry(list, listLen,
                                            ni->first.c_str(), &ni->second,
                                            minGeneration)) != TACK_OK)
            return retval;
        list += (oldListLen - *listLen);
    }

    if (*listLen < 3)
        return TACK_ERR_UNDERSIZED_BUFFER;
    *list++ = '}';
    *list++ = '\n';
    *list++ = '\0';
    *listLen -= 2;

    return TACK_OK;
}
