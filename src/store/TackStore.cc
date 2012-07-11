
#include "TackStore.h"
#include "TackExtension.h"

// C Callbacks

TACK_RETVAL tackStoreGetKeyRecord(void* arg, char* keyFingerprintBuf, 
                                  uint8_t* minGeneration)
{
    TACK_RETVAL retval = TACK_ERR;
    TackStore* store = (TackStore*)arg;
    std::string keyFingerprint(keyFingerprintBuf);
    TackStore::KeyRecord keyRecord;

    if ((retval=store->getKeyRecord(keyFingerprint, keyRecord)) != TACK_OK)
        return retval;
    *minGeneration = keyRecord.minGeneration;
    return TACK_OK;
}

TACK_RETVAL tackStoreUpdateKeyRecord(void* arg, char* keyFingerprintBuf, 
                                     uint8_t minGeneration)
{
    TackStore* store = (TackStore*)arg;
    std::string keyFingerprint(keyFingerprintBuf);
    TackStore::KeyRecord keyRecord(minGeneration);

    return store->updateKeyRecord(keyFingerprint, keyRecord);
}

TACK_RETVAL tackStoreDeleteKeyRecord(void* arg, char* keyFingerprintBuf)
{
    TackStore* store = (TackStore*)arg;
    std::string keyFingerprint(keyFingerprintBuf);

    return store->deleteKeyRecord(keyFingerprint);
}

TACK_RETVAL tackStoreGetPin(void* arg, void* argHostName, TackPinStruct* pin)
{
    TACK_RETVAL retval = TACK_ERR;
    TackStore::KeyRecord keyRecord;
    TackStore::NameRecord nameRecord;
    TackStore* store = (TackStore*)arg;
    std::string* hostName = (std::string*)argHostName;

    /* See if there's a relevant pin */
    if ((retval=store->getPin(*hostName, keyRecord, nameRecord)) < TACK_OK)
        return retval;

    /* If there's a relevant pin, populate the structure, else leave it zeroed */
    memset(pin, 0, sizeof(TackPinStruct));
    if (retval == TACK_OK) {
        strcpy(pin->keyFingerprint, nameRecord.keyFingerprint.c_str());
        pin->minGeneration = keyRecord.minGeneration;
        pin->initialTime = nameRecord.initialTime;
        pin->activePeriodEnd = nameRecord.activePeriodEnd;
        return TACK_OK;
    }
    return TACK_OK_NOT_FOUND;
}

TACK_RETVAL tackStoreSetPin(void* arg, void* argHostName, TackPinStruct* pin)
{
    TackStore::KeyRecord keyRecord;
    TackStore::NameRecord nameRecord;
    TackStore* store = (TackStore*)arg;
    std::string* hostName = (std::string*)argHostName;

    keyRecord = TackStore::KeyRecord(pin->minGeneration);
    nameRecord = TackStore::NameRecord(pin->keyFingerprint, pin->initialTime, 
                                       pin->activePeriodEnd);
    return store->setPin(*hostName, keyRecord, nameRecord);    
}

TACK_RETVAL tackStoreDeletePin(void* arg, void* argHostName)
{
    TackStore* store = (TackStore*)arg;
    std::string* hostName = (std::string*)argHostName;

    return store->deletePin(*hostName);    
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

TACK_RETVAL TackStore::process(uint8_t* tackExt, uint32_t tackExtLen,
                               std::string hostName,
                               uint8_t keyHash[TACK_HASH_LENGTH],
                               uint32_t currentTime,
                               uint8_t doPinActivation,
                               TackCryptoFuncs* crypto)
{
    TACK_RETVAL retval = TACK_ERR;
    TackStoreFuncs store;

    /* Prepare the C structure containing store callbacks */
    if ((retval=getStoreFuncs(&store, &hostName)) != TACK_OK)
        return retval;

    /* Execute client processing */
    return tackExtensionProcess(tackExt, tackExtLen, keyHash, currentTime, doPinActivation,
                                &store, crypto);
}

TACK_RETVAL TackStore::getStoreFuncs(TackStoreFuncs* store, std::string* hostName)
{
    store->arg = this;
    store->argHostName = hostName;
    store->getKeyRecord = tackStoreGetKeyRecord;
    store->updateKeyRecord = tackStoreUpdateKeyRecord;
    store->deleteKeyRecord = tackStoreDeleteKeyRecord;
    store->getPin = tackStoreGetPin;
    store->setPin = tackStoreSetPin;
    store->deletePin = tackStoreDeletePin;
    return TACK_OK;
}


