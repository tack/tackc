/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include "TackStore.h"
#include "TackProcessing.h"
#include "TackStoreFuncs.h"

// Callbacks for bridging between C functions and the C++ interface

static TACK_RETVAL tackStoreGetMinGeneration(const void* arg, const char* keyFingerprint, 
                                             uint8_t* minGeneration)
{
    TackStore* store = (TackStore*)arg;
    std::string fingerprint(keyFingerprint);
    return store->getMinGeneration(fingerprint, minGeneration);
}

static TACK_RETVAL tackStoreSetMinGeneration(const void* arg, const char* keyFingerprint, 
                                             uint8_t minGeneration)
{
    TackStore* store = (TackStore*)arg;
    std::string fingerprint(keyFingerprint);
    TACK_RETVAL retval = store->setMinGeneration(fingerprint, minGeneration);
    if (retval == TACK_OK)
        store->setDirtyFlag(true);
    return retval;
}

static TACK_RETVAL tackStoreGetNameRecord(const void* arg, const void* name, 
                                          TackNameRecord* nameRecord)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    return store->getNameRecord(*nameStr, nameRecord);
}

static TACK_RETVAL tackStoreSetNameRecord(const void* arg, const void* name, 
                                          TackNameRecord* nameRecord)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    TACK_RETVAL retval = store->setNameRecord(*nameStr, nameRecord);
    if (retval == TACK_OK)
        store->setDirtyFlag(true);
    return retval;
}

static TACK_RETVAL tackStoreUpdateNameRecord(const void* arg, const void* name, 
                                             uint32_t newEndTime)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    TACK_RETVAL retval = store->updateNameRecord(*nameStr, newEndTime);
    if (retval == TACK_OK)
        store->setDirtyFlag(true);
    return retval;    
}

static TACK_RETVAL tackStoreDeleteNameRecord(const void* arg, const void* name)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    TACK_RETVAL retval = store->deleteNameRecord(*nameStr);    
    if (retval == TACK_OK)
        store->setDirtyFlag(true);
    return retval;
}

// TackStore methods

TackStore::TackStore():pinActivation_(false),crypto_(NULL){}

void TackStore::setPinActivation(bool pinActivation) {
    pinActivation_ = pinActivation; }
bool TackStore::getPinActivation() {return pinActivation_;}

void TackStore::setCryptoFuncs(TackCryptoFuncs* crypto) {
    crypto_ = crypto;}
TackCryptoFuncs* TackStore::getCryptoFuncs() {return crypto_;}

void TackStore::setDirtyFlag(bool dirtyFlag) {
    dirtyFlag_ = dirtyFlag;}
bool TackStore::getDirtyFlag() {return dirtyFlag_;}


static TackStoreFuncs storeFuncs = {
    tackStoreGetMinGeneration,
    tackStoreSetMinGeneration,
    tackStoreGetNameRecord,    
    tackStoreSetNameRecord,
    tackStoreUpdateNameRecord,
    tackStoreDeleteNameRecord
};

TACK_RETVAL TackStore::process(TackProcessingContext* ctx,
                               const std::string& name,
                               uint32_t currentTime,
                               bool invalidateOnly)
{
    return tackProcessStore(ctx, &name, currentTime, 
                            (uint8_t)pinActivation_, 
                            (uint8_t)invalidateOnly, 
                            &storeFuncs, 
                            this, crypto_);
}

TACK_RETVAL TackStore::getPin(const std::string& name, TackNameRecord* nameRecord, 
                   uint8_t *minGeneration)
{
    TACK_RETVAL retval = TACK_ERR;
    if ((retval = getNameRecord(name, nameRecord)) != TACK_OK)
        return retval;

    std::string fingerprint(nameRecord->fingerprint);
    if ((retval = getMinGeneration(fingerprint, minGeneration)) != TACK_OK)
        return retval;
    return TACK_OK;
}

TACK_RETVAL TackStore::setPin(const std::string& name, TackNameRecord* nameRecord, 
                              uint8_t minGeneration)
{
    TACK_RETVAL retval = TACK_ERR;
    // Set key record first to leave things in consistent state if interrupted
    std::string fingerprint(nameRecord->fingerprint);
    if ((retval = setMinGeneration(fingerprint, minGeneration)) != TACK_OK)
        return retval;
    if ((retval = setNameRecord(name, nameRecord)) != TACK_OK)
        return retval;
    return TACK_OK;
}
