
#include "TackStore.h"
#include "TackExtension.h"

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

TACK_RETVAL TackStore::setPin(std::string hostName, 
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

TACK_RETVAL TackStore::getPin(std::string hostName, 
                              KeyRecord& keyRecord, 
                              NameRecord& nameRecord)
{
    // Get nameRecord
    std::map<std::string, NameRecord>::iterator i = nameRecords.find(hostName);
    if (i == nameRecords.end())
        return TACK_OK_NOT_FOUND;
    nameRecord = i->second;
    
    // Get keyRecord
    if (getKeyRecord(nameRecord.keyFingerprint, keyRecord) != TACK_OK)
        return TACK_ERR_ASSERTION;
    
    return TACK_OK;
}

TACK_RETVAL TackStore::deletePin(std::string hostName)
{
    std::map<std::string, NameRecord>::iterator i = nameRecords.find(hostName);
    if (i == nameRecords.end())
        return TACK_OK_NOT_FOUND;
    nameRecords.erase(i);    
    return TACK_OK; 
}

TACK_RETVAL TackStore::updateKeyRecord(std::string keyFingerprint, KeyRecord keyRecord)
{
    KeyRecord tempKeyRecord;
    if (getKeyRecord(keyFingerprint, tempKeyRecord) != TACK_OK)
        return TACK_ERR_ASSERTION;
    keyRecords[keyFingerprint] = keyRecord;
    return TACK_OK;
}

TACK_RETVAL TackStore::getKeyRecord(std::string keyFingerprint, KeyRecord& keyRecord)
{
    std::map<std::string, KeyRecord>::iterator i = keyRecords.find(keyFingerprint);
    if (i == keyRecords.end())
        return TACK_OK_NOT_FOUND;
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
        return TACK_OK_NOT_FOUND;
}

TACK_RETVAL TackStore::pinActivation(uint8_t* tack,
                                     std::string hostName,
                                     uint32_t currentTime,
                                     TackHashFunc func)
{
    TACK_RETVAL retval = TACK_ERR;
    KeyRecord keyRecord;
    NameRecord nameRecord;
    
    // Lookup relevant pin (if any)
    bool foundPin = false;
    if ((retval = getPin(hostName, keyRecord, nameRecord)) < TACK_OK)
        return retval;
    if (retval == TACK_OK) // could be TACK_OK_NOT_FOUND
        foundPin = true;

    // Calculate tack's key fingerprint (if any)
    std::string keyFingerprint;
    if (tack) {
        char keyFingerprintBuf[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
        if ((retval=tackTackGetKeyFingerprint(tack, keyFingerprintBuf, func)) != TACK_OK)
            return retval;
        keyFingerprint = std::string(keyFingerprintBuf);
    }

    if (foundPin) {

        // Delete relevant but inactive pin
        if (nameRecord.activePeriodEnd < currentTime)
            if ((retval = deletePin(hostName)) != TACK_OK)
                return retval;
        
        // If relevant pin reference's tack's key, extend activation
        if (tack && keyFingerprint == nameRecord.keyFingerprint) {
            uint32_t initialTime = nameRecord.initialTime;
            nameRecord.activePeriodEnd = currentTime + (currentTime - initialTime);
            if ((retval=setPin(hostName, keyRecord, nameRecord)) != TACK_OK)
                return retval;
        }   
    }
    // If no relevant pin but a tack, create new inactive pin
    else if (tack) {
        keyRecord.minGeneration = tackTackGetMinGeneration(tack);
        nameRecord.keyFingerprint = keyFingerprint;
        nameRecord.initialTime = currentTime;
        nameRecord.activePeriodEnd = 0;
        if ((retval=setPin(hostName, keyRecord, nameRecord)) != TACK_OK)
            return retval;
    }
    return TACK_OK;
}

TACK_RETVAL TackStore::processTackExtension(uint8_t* tackExt, uint32_t tackExtLen,
                                            uint8_t keyHash[TACK_HASH_LENGTH],
                                            uint32_t currentTime,
                                            TackHashFunc hashFunc, 
                                            TackVerifyFunc verifyFunc)
{
    uint8_t* tack;
    TACK_RETVAL retval = TACK_ERR;  

    // Check basic TACK_Extension syntax
    if ((retval = tackExtensionSyntaxCheck(tackExt, tackExtLen)) != TACK_OK)
        return retval;

    // Convert keyHash -> keyFingerprint 
    char keyFingerprintBuf[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    if ((retval=tackGetKeyFingerprintFromHash(keyHash, keyFingerprintBuf)) != TACK_OK)
        return retval;
    std::string keyFingerprint(keyFingerprintBuf);

    // Lookup keyFingerprint -> keyRecord
    TackStore::KeyRecord keyRecord;
    bool foundKeyRecord = false;
    if ((retval=getKeyRecord(keyFingerprint, keyRecord)) < TACK_OK)
        return retval;
    if (retval == TACK_OK) // could be TACK_OK_NOT_FOUND
        foundKeyRecord = true;
   
    // Process the tack if present
    tack = tackExtensionGetTack(tackExt);
    if (tack) {

        // Verify the tack's target_hash, signature, expiration, generation
        uint8_t minGeneration = keyRecord.minGeneration;
        retval = tackTackProcess(tack, keyHash,
                            &minGeneration,
                            currentTime,
                            verifyFunc);
        if (retval != TACK_OK)
            return retval;

        // If minGeneration was incremented, set the new value in keyRecord
        if (foundKeyRecord && minGeneration > keyRecord.minGeneration) {
            keyRecord.minGeneration = minGeneration;
            if ((retval=updateKeyRecord(keyFingerprint, keyRecord)) != TACK_OK)
                return retval;
        }
    }

    // Process the break signatures if present
    if ((retval=processBreakSigs(tackExt, hashFunc, verifyFunc)) != TACK_OK)
        return retval;

    return TACK_OK;
}



TACK_RETVAL TackStore::processBreakSigs(uint8_t* tackExt, 
                                        TackHashFunc hashFunc, 
                                        TackVerifyFunc verifyFunc)
{
    TACK_RETVAL retval = TACK_ERR;
    for (uint8_t count=0; count < tackExtensionGetNumBreakSigs(tackExt); count++) {
        
        // Get the fingerprint for each break sig
        uint8_t* breakSig = tackExtensionGetBreakSig(tackExt, count);
        char keyFingerprintBuf[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
        tackBreakSigGetKeyFingerprint(breakSig, keyFingerprintBuf, hashFunc);

        // If there's no matching key record, skip to next break sig
        std::string keyFingerprint(keyFingerprintBuf);
        KeyRecord keyRecord;
        if ((retval = getKeyRecord(keyFingerprint, keyRecord)) < TACK_OK)
            return retval;
        if (retval == TACK_OK_NOT_FOUND)
            continue;

        // If there's a matching key record, verify the break sig
        retval=tackBreakSigVerifySignature(breakSig, verifyFunc);
        if (retval != TACK_OK)
            return retval;
        
        // If verified, delete the key record
        if ((retval=deleteKeyRecord(keyFingerprint)) != TACK_OK)
            return retval;
    }
    return TACK_OK;
}
