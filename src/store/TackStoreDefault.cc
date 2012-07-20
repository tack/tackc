
#include "TackStoreDefault.h"

// These don't do anything but Chromium wants them:
TackStoreDefault::TackStoreDefault(){}
TackStoreDefault::~TackStoreDefault(){}


TACK_RETVAL TackStoreDefault::getMinGeneration(std::string& keyFingerprint, 
                                           uint8_t* minGeneration)
{
    std::map<std::string, uint8_t>::iterator ki = keyRecords.find(keyFingerprint);
    if (ki == keyRecords.end())
        return TACK_OK_NOT_FOUND;

    *minGeneration = ki->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setMinGeneration(std::string& keyFingerprint, 
                                               uint8_t minGeneration)
{
    keyRecords[keyFingerprint] = minGeneration;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::getNameRecord(std::string& name, TackNameRecord* nameRecord)
{
    std::map<std::string, TackNameRecord>::iterator ni = nameRecords.find(name);
    if (ni == nameRecords.end())
        return TACK_OK_NOT_FOUND;
    *nameRecord = ni->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::newNameRecord(std::string& name, TackNameRecord* nameRecord)
{
    nameRecords[name] = *nameRecord;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::updateNameRecord(std::string& name, uint32_t newEndTime)
{
    std::map<std::string, TackNameRecord>::iterator ni = nameRecords.find(name);
    if (ni == nameRecords.end())
        return TACK_OK_NOT_FOUND;

    ni->second.endTime = newEndTime;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::deleteNameRecord(std::string& name)
{
    nameRecords.erase(name);
    return TACK_OK; 
}


std::string TackStoreDefault::getStringDump()
{   
    std::string result("");

    result += std::string("Name Records:\n");
    std::map<std::string, TackNameRecord>::iterator ni = nameRecords.begin();
    for (; ni != nameRecords.end(); ni++) {
        char nextLine[1000];
        sprintf(nextLine, "%s %d %s initial=%u end=%u\n", 
                ni->first.c_str(), 
                (uint32_t)ni->first.size(),
                ni->second.fingerprint,
                ni->second.initialTime,
                ni->second.endTime);
        result += std::string(nextLine);
    }
    return result;
}
