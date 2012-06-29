
#include "TackStore.h"

TACK_RETVAL TackStore::addPin(std::string& hostName, 
                              KeyRecord* keyRecord, 
                              NameRecord* nameRecord)
{
    // If there's an existing name record, overwrite it
    nameRecords[hostName] = *nameRecord;
    
    // If there's an existing key record, reuse it
    KeyRecord tempKeyRecord;
    TACK_RETVAL retval = getKeyRecord(nameRecord->keyFingerprint, &tempKeyRecord);
    if (retval == TACK_ERR_NOT_FOUND) {
        keyRecords[nameRecord->keyFingerprint] = *keyRecord;
        retval = TACK_OK;
    }
    
    return retval;
}

TACK_RETVAL TackStore::getPin(std::string& hostName, 
                              KeyRecord* keyRecord, 
                              NameRecord* nameRecord)
{
    // Get nameRecord
    std::map<std::string, NameRecord>::iterator i = nameRecords.find(hostName);
    if (i == nameRecords.end())
        return TACK_ERR_NOT_FOUND;
    *nameRecord = i->second;
    
    // Get keyRecord
    if (getKeyRecord(nameRecord->keyFingerprint, keyRecord) != TACK_OK)
        return TACK_ERR_ASSERTION;
    
    return TACK_OK;
}

TACK_RETVAL TackStore::getKeyRecord(std::string& keyFingerprint, KeyRecord* keyRecord)
{
    std::map<std::string, KeyRecord>::iterator i = keyRecords.find(keyFingerprint);
    if (i == keyRecords.end())
        return TACK_ERR_NOT_FOUND;
    *keyRecord = i->second;
    return TACK_OK;
}

TACK_RETVAL TackStore::deleteKeyRecord(std::string& keyFingerprint)
{
    std::map<std::string, TackStore::KeyRecord>::iterator ki;
    ki = keyRecords.find(keyFingerprint);
    if (ki != keyRecords.end()) {
        keyRecords.erase(ki);
        
        // Delete all nameRecords referring to the keyRecord
        std::map<std::string, TackStore::NameRecord>::iterator ni;
        for (ni=nameRecords.begin(); ni != nameRecords.end();) {
            if (ni->first == keyFingerprint)
                nameRecords.erase(ni++);
            else
                ++ni;
        }
        return TACK_OK;
    }
    else
        return TACK_ERR_NOT_FOUND;
}
