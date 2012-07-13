
#include "TackStore.h"
#include "TackProcessing.h"

// C Callbacks

TACK_RETVAL tackStoreGetKeyRecord(void* arg, char* keyFingerprint, 
                                  uint8_t* minGeneration)
{
    TackStore* store = (TackStore*)arg;
    std::string fingerprint(keyFingerprint);
    return store->getKeyRecord(fingerprint, minGeneration);
}

TACK_RETVAL tackStoreUpdateKeyRecord(void* arg, char* keyFingerprint, 
                                     uint8_t minGeneration)
{
    TackStore* store = (TackStore*)arg;
    std::string fingerprint(keyFingerprint);
    return store->updateKeyRecord(fingerprint, minGeneration);
}

TACK_RETVAL tackStoreDeleteKeyRecord(void* arg, char* keyFingerprint)
{
    TackStore* store = (TackStore*)arg;
    std::string fingerprint(keyFingerprint);
    return store->deleteKeyRecord(fingerprint);
}

TACK_RETVAL tackStoreGetPin(void* arg, void* argName, TackPinStruct* pin)
{
    TackStore* store = (TackStore*)arg;
    std::string* name = (std::string*)argName;
    return store->getPin(*name, pin);
}

TACK_RETVAL tackStoreNewPin(void* arg, void* argName, TackPinStruct* pin)
{
    TackStore* store = (TackStore*)arg;
    std::string* name = (std::string*)argName;
    return store->newPin(*name, pin);
}

TACK_RETVAL tackStoreUpdatePin(void* arg, void* argName, uint32_t newActivePeriodEnd)
{
    TackStore* store = (TackStore*)arg;
    std::string* name = (std::string*)argName;
    return store->updatePin(*name, newActivePeriodEnd);    
}

TACK_RETVAL tackStoreDeletePin(void* arg, void* argName)
{
    TackStore* store = (TackStore*)arg;
    std::string* name = (std::string*)argName;
    return store->deletePin(*name);    
}

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
    return tackProcess(tackExt, tackExtLen, keyHash, currentTime, doPinActivation,
                       &store, crypto);
}

TACK_RETVAL TackStore::getStoreFuncs(TackStoreFuncs* store, std::string* name)
{
    store->arg = this;
    store->argName = name;
    store->getKeyRecord = tackStoreGetKeyRecord;
    store->updateKeyRecord = tackStoreUpdateKeyRecord;
    store->deleteKeyRecord = tackStoreDeleteKeyRecord;
    store->getPin = tackStoreGetPin;
    store->newPin = tackStoreNewPin;
    store->updatePin = tackStoreUpdatePin;
    store->deletePin = tackStoreDeletePin;
    return TACK_OK;
}


