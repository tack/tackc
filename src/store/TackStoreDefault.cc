#include "TackStoreDefault.h"

// These don't do anything but Chromium wants them:
TackStoreDefault::TackStoreDefault(){}
TackStoreDefault::~TackStoreDefault(){}


TACK_RETVAL TackStoreDefault::getMinGeneration(std::string& keyFingerprint, 
                                           uint8_t* minGeneration)
{
    std::map<std::string, uint8_t>::iterator ki = keyRecords_.find(keyFingerprint);
    if (ki == keyRecords_.end())
        return TACK_OK_NOT_FOUND;

    *minGeneration = ki->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setMinGeneration(std::string& keyFingerprint, 
                                               uint8_t minGeneration)
{
    keyRecords_[keyFingerprint] = minGeneration;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::getNameRecord(std::string& name, TackNameRecord* nameRecord)
{
    std::map<std::string, TackNameRecord>::iterator ni = nameRecords_.find(name);
    if (ni == nameRecords_.end())
        return TACK_OK_NOT_FOUND;

    *nameRecord = ni->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setNameRecord(std::string& name, TackNameRecord* nameRecord)
{
    nameRecords_[name] = *nameRecord;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::updateNameRecord(std::string& name, uint32_t newEndTime)
{
    std::map<std::string, TackNameRecord>::iterator ni = nameRecords_.find(name);
    if (ni == nameRecords_.end())
        return TACK_OK_NOT_FOUND;

    ni->second.endTime = newEndTime;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::deleteNameRecord(std::string& name)
{
    nameRecords_.erase(name);
    return TACK_OK; 
}

/*
TACK_RETVAL TackStoreDefault::serialize(std::string& name)
{
    std::map<std::string, TackNameRecord>::iterator ni;
    for (ni=nameRecords_.begin(); ni != nameRecords_.end(); ni++)  {
        uint8_t minGeneration;
        if ((retval=getMinGeneration(ni->second.fingerprint, &minGeneration)) != TACK_OK)
            return retval;

        char entry[1024];
        uint32_t entryLen = 0;
        if ((retval=tackSerializeEntry(&ni->second, minGeneration, 
                                       entry, &entryLen)) != TACK_OK)
            return retval;
        
        name += std::string(entry, entryLen);
    }
    std::map<std::string, uint8_t>::iterator ki;
    for (ki=keyRecords_.begin(); ki != keyRecords_.end(); ki++)  {
        
    }
}
*/
