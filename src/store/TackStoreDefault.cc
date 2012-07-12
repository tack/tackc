
#include "TackStoreDefault.h"

TACK_RETVAL TackStoreDefault::getKeyRecord(std::string keyFingerprint, 
                                           KeyRecord& keyRecord)
{
    std::map<std::string, KeyRecord>::iterator i = keyRecords.find(keyFingerprint);
    if (i == keyRecords.end())
        return TACK_OK_NOT_FOUND;
    keyRecord = i->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::updateKeyRecord(std::string keyFingerprint, 
                                              KeyRecord keyRecord)
{
    std::map<std::string, KeyRecord>::iterator i = keyRecords.find(keyFingerprint);
    if (i == keyRecords.end())
        return TACK_OK_NOT_FOUND;
    keyRecords[keyFingerprint] = keyRecord;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::deleteKeyRecord(std::string keyFingerprint)
{
    // Erase the entry from the keyRecords map
    std::map<std::string, TackStore::KeyRecord>::iterator ki;
    ki = keyRecords.find(keyFingerprint);
    if (ki != keyRecords.end()) {
        
        // Delete all nameRecords referring to the keyRecord
        // Iterates through all nameRecords - O(N)
        std::map<std::string, TackStore::NameRecord>::iterator ni;
        for (ni=nameRecords.begin(); ni != nameRecords.end();) {
            if (ni->second.keyFingerprint == keyFingerprint)
                nameRecords.erase(ni++);
            else
                ni++;
        }
        
        // Delete the keyRecord
        keyRecords.erase(ki);
        return TACK_OK;
    }
    return TACK_OK_NOT_FOUND;
}

TACK_RETVAL TackStoreDefault::getPin(std::string hostName, 
                              KeyRecord& keyRecord, 
                              NameRecord& nameRecord)
{
    // Get nameRecord
    std::map<std::string, NameRecord>::iterator i = nameRecords.find(hostName);
    if (i == nameRecords.end())
        return TACK_OK_NOT_FOUND;
    nameRecord = i->second;
    
    // Get keyRecord
    if (getKeyRecord(nameRecord.keyFingerprint, keyRecord) != TACK_OK) {
        // Store is corrupted! - there should always be a key record per name record
        return TACK_ERR_MISSING_KEY_RECORD;
    }
    
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setPin(std::string hostName, 
                              KeyRecord keyRecord, 
                              NameRecord nameRecord)
{
    // If there's an existing name record, overwrite it
    nameRecords[hostName] = nameRecord;
    
    // If there's no existing key record, add one
    // If there an existing one, reuse it (ignoring the passed-in minGeneration)
    KeyRecord tempKeyRecord;
    TACK_RETVAL retval = TACK_ERR;
    if ((retval=getKeyRecord(nameRecord.keyFingerprint, tempKeyRecord)) < TACK_OK)
        return retval;
    if (retval == TACK_OK_NOT_FOUND)
        keyRecords[nameRecord.keyFingerprint] = keyRecord;
    
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::deletePin(std::string hostName)
{
    std::map<std::string, NameRecord>::iterator i = nameRecords.find(hostName);
    if (i == nameRecords.end())
        return TACK_OK_NOT_FOUND;
    nameRecords.erase(i);    
    return TACK_OK; 
}
