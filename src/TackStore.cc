
#include "TackStore.h"

TackStore::KeyRecord::KeyRecord():minGeneration(0)
{}

TackStore::KeyRecord::KeyRecord(uint8_t newMinGeneration):minGeneration(newMinGeneration)
{}

TackStore::NameRecord::NameRecord()
{}

TackStore::NameRecord::NameRecord(std::string newKeyFingerprint,
                      uint32_t newInitialTime,
                      uint32_t newActivePeriodEnd):keyFingerprint(newKeyFingerprint),
                                                   initialTime(newInitialTime),
                                                   activePeriodEnd(newActivePeriodEnd)
{}

TACK_RETVAL TackStore::addPin(std::string hostName, 
                              KeyRecord keyRecord, 
                              NameRecord nameRecord)
{
    // If there's an existing name record, overwrite it
    nameRecords[hostName] = nameRecord;
    
    // If there's no existing key record, add one
    // If there an existing one, reuse it (ignoring the passed-in minGeneration)
    KeyRecord tempKeyRecord;
    TACK_RETVAL retval = getKeyRecord(nameRecord.keyFingerprint, tempKeyRecord);
    if (retval == TACK_ERR_NOT_FOUND) {
        keyRecords[nameRecord.keyFingerprint] = keyRecord;
        retval = TACK_OK;
    }
    
    return retval;
}

TACK_RETVAL TackStore::getPin(std::string hostName, 
                              KeyRecord& keyRecord, 
                              NameRecord& nameRecord)
{
    // Get nameRecord
    std::map<std::string, NameRecord>::iterator i = nameRecords.find(hostName);
    if (i == nameRecords.end())
        return TACK_ERR_NOT_FOUND;
    nameRecord = i->second;
    
    // Get keyRecord
    if (getKeyRecord(nameRecord.keyFingerprint, keyRecord) != TACK_OK)
        return TACK_ERR_ASSERTION;
    
    return TACK_OK;
}

TACK_RETVAL TackStore::getKeyRecord(std::string keyFingerprint, KeyRecord& keyRecord)
{
    std::map<std::string, KeyRecord>::iterator i = keyRecords.find(keyFingerprint);
    if (i == keyRecords.end())
        return TACK_ERR_NOT_FOUND;
    keyRecord = i->second;
    return TACK_OK;
}

TACK_RETVAL TackStore::deleteKeyRecord(std::string keyFingerprint)
{
    // Erase the entry from the keyRecords map
    std::map<std::string, TackStore::KeyRecord>::iterator ki;
    ki = keyRecords.find(keyFingerprint);
    if (ki != keyRecords.end()) {
        keyRecords.erase(ki);
        
        // Delete all nameRecords referring to the keyRecord
        // Requires iterating through all nameRecords
        std::map<std::string, TackStore::NameRecord>::iterator ni;
        for (ni=nameRecords.begin(); ni != nameRecords.end();) {
            if (ni->second.keyFingerprint == keyFingerprint)
                nameRecords.erase(ni++);
            else
                ++ni;
        }
        return TACK_OK;
    }
    else
        return TACK_ERR_NOT_FOUND;
}
