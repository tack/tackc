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

static TACK_RETVAL tackStoreDeleteKey(const void* arg, const char* keyFingerprint)
{
    TackStore* store = (TackStore*)arg;
    std::string fingerprint(keyFingerprint);
    TACK_RETVAL retval = store->deleteKey(fingerprint);
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
                                          const TackNameRecord* nameRecord)
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
    tackStoreDeleteKey,
    tackStoreGetNameRecord,    
    tackStoreSetNameRecord,
    tackStoreUpdateNameRecord,
    tackStoreDeleteNameRecord
};

TACK_RETVAL TackStore::process(TackProcessingContext* ctx,
                               const std::string& name,
                               uint32_t currentTime)
{
    return tackProcessStore(ctx, &name, currentTime, 
                            (uint8_t)pinActivation_, 
                            &storeFuncs, 
                            this, crypto_);
}

TACK_RETVAL TackStore::getPin(const std::string& name, TackNameRecord* nameRecord, 
                   uint8_t *minGeneration)
{
    return tackStoreGetPin(&storeFuncs, this, &name, nameRecord, minGeneration);
}

TACK_RETVAL TackStore::setPin(const std::string& name, const TackNameRecord* nameRecord, 
                              uint8_t minGeneration)
{
    return tackStoreSetPin(&storeFuncs, this, &name, nameRecord, minGeneration);
}
