
#include "TackStore.h"
#include "TackExtension.h"

// C Callbacks

TACK_RETVAL tackTackStoreGetKeyRecord(void* krArg, char* keyFingerprintBuf, 
                                  uint8_t* minGeneration)
{
    TACK_RETVAL retval = TACK_ERR;
    TackStore* store = (TackStore*)krArg;
    std::string keyFingerprint(keyFingerprintBuf);
    TackStore::KeyRecord keyRecord;

    if ((retval=store->getKeyRecord(keyFingerprint, keyRecord)) != TACK_OK)
        return retval;
    *minGeneration = keyRecord.minGeneration;
    return TACK_OK;
}

TACK_RETVAL tackTackStoreUpdateKeyRecord(void* krArg, char* keyFingerprintBuf, 
                                     uint8_t minGeneration)
{
    TackStore* store = (TackStore*)krArg;
    std::string keyFingerprint(keyFingerprintBuf);
    TackStore::KeyRecord keyRecord(minGeneration);

    return store->updateKeyRecord(keyFingerprint, keyRecord);
}

TACK_RETVAL tackTackStoreDeleteKeyRecord(void* krArg, char* keyFingerprintBuf)
{
    TackStore* store = (TackStore*)krArg;
    std::string keyFingerprint(keyFingerprintBuf);

    return store->deleteKeyRecord(keyFingerprint);
}

// KeyRecord and NameRecord constructors

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

// TackStore member funcs

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
