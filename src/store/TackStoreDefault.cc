
#include "TackStoreDefault.h"

// KeyRecord and NameRecord constructors

TackStoreDefault::KeyRecord::KeyRecord():minGeneration(0){}

TackStoreDefault::KeyRecord::KeyRecord(uint8_t newMinGeneration):
    minGeneration(newMinGeneration){}

TackStoreDefault::NameRecord::NameRecord(){}

TackStoreDefault::NameRecord::NameRecord(std::string newKeyFingerprint,
                                         uint32_t newInitialTime,
                                         uint32_t newActivePeriodEnd):
    keyFingerprint(newKeyFingerprint),
    initialTime(newInitialTime),
    activePeriodEnd(newActivePeriodEnd){}

// TackStoreDefault methods

TACK_RETVAL TackStoreDefault::getKeyRecord(std::string& keyFingerprint, 
                                           uint8_t* minGeneration)
{
    std::map<std::string, KeyRecord>::iterator ki = keyRecords.find(keyFingerprint);
    if (ki == keyRecords.end())
        return TACK_OK_NOT_FOUND;

    *minGeneration = ki->second.minGeneration;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::updateKeyRecord(std::string& keyFingerprint, 
                                              uint8_t minGeneration)
{
    std::map<std::string, KeyRecord>::iterator ki = keyRecords.find(keyFingerprint);
    if (ki == keyRecords.end())
        return TACK_OK_NOT_FOUND;

    ki->second.minGeneration = minGeneration;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::deleteKeyRecord(std::string& keyFingerprint)
{
    std::map<std::string, KeyRecord>::iterator ki = keyRecords.find(keyFingerprint);
    if (ki == keyRecords.end())
        return TACK_OK_NOT_FOUND;

    // Delete all nameRecords referring to the keyRecord
    // Iterates through all nameRecords - O(N)
    std::map<std::string, NameRecord>::iterator ni;
    for (ni=nameRecords.begin(); ni != nameRecords.end();) {
        if (ni->second.keyFingerprint == keyFingerprint)
            nameRecords.erase(ni++);
        else
            ni++;
    }

    keyRecords.erase(ki);
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::getPin(std::string& name, TackPinStruct* pin)
{
    std::map<std::string, NameRecord>::iterator ni = nameRecords.find(name);
    if (ni == nameRecords.end())
        return TACK_OK_NOT_FOUND;
    NameRecord& nameRecord = ni->second;

    std::map<std::string, KeyRecord>::iterator ki;
    ki = keyRecords.find(nameRecord.keyFingerprint);
    if (ki == keyRecords.end())
        return TACK_ERR_CORRUPTED_STORE;
    KeyRecord& keyRecord = ki->second;

    strcpy(pin->keyFingerprint, nameRecord.keyFingerprint.c_str());
    pin->minGeneration = keyRecord.minGeneration;
    pin->initialTime = nameRecord.initialTime;
    pin->activePeriodEnd = nameRecord.activePeriodEnd;
    
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::newPin(std::string& name, TackPinStruct* pin)
{
    std::string keyFingerprint(pin->keyFingerprint);
    std::map<std::string, KeyRecord>::iterator ki;
    ki = keyRecords.find(keyFingerprint);
    if (ki != keyRecords.end())
        keyRecords[keyFingerprint] = KeyRecord(pin->minGeneration); 
    
    NameRecord nameRecord(keyFingerprint, pin->initialTime, pin->activePeriodEnd);
    nameRecords[name] = nameRecord;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::updatePin(std::string& name, uint32_t newActivePeriodEnd)
{
    std::map<std::string, NameRecord>::iterator ni = nameRecords.find(name);
    if (ni == nameRecords.end())
        return TACK_OK_NOT_FOUND;

    ni->second.activePeriodEnd = newActivePeriodEnd;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::deletePin(std::string& name)
{
    std::map<std::string, NameRecord>::iterator i = nameRecords.find(name);
    if (i == nameRecords.end())
        return TACK_OK_NOT_FOUND;

    nameRecords.erase(i);

    // Doesn't clean up any dangling key records    
    return TACK_OK; 
}
