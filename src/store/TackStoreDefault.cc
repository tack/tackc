
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

TACK_RETVAL TackStoreDefault::getPin(std::string& name, TackPin* pin)
{
    std::map<std::string, TackPin>::iterator ni = nameRecords.find(name);
    if (ni == nameRecords.end())
        return TACK_OK_NOT_FOUND;
    *pin = ni->second;

    std::map<std::string, uint8_t>::iterator ki;
    ki = keyRecords.find(pin->fingerprint);
    if (ki == keyRecords.end())
        return TACK_ERR_CORRUPTED_STORE;
    pin->minGeneration = ki->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::newPin(std::string& name, TackPin* pin)
{
    std::string keyFingerprint(pin->fingerprint);

    std::map<std::string, uint8_t>::iterator ki;
    ki = keyRecords.find(keyFingerprint);
    if (ki == keyRecords.end())
        keyRecords[keyFingerprint] = pin->minGeneration; 
    
    nameRecords[name] = *pin;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::updatePin(std::string& name, uint32_t newEndTime)
{
    std::map<std::string, TackPin>::iterator ni = nameRecords.find(name);
    if (ni == nameRecords.end())
        return TACK_OK_NOT_FOUND;

    ni->second.endTime = newEndTime;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::deletePin(std::string& name)
{
    nameRecords.erase(name);
    return TACK_OK; 
}


std::string TackStoreDefault::getStringDump()
{   
    std::string result("");

    result += std::string("Name Records:\n");
    std::map<std::string, TackPin>::iterator ni = nameRecords.begin();
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
