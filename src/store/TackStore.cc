/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include "TackStore.h"
#include "TackProcessing.h"
#include "TackStoreFuncs.h"

// Callbacks for bridging between C functions and the C++ interface

static TACK_RETVAL tackStoreGetMinGeneration(void* arg, char* keyFingerprint, 
                                             uint8_t* minGeneration)
{
    TackStore* store = (TackStore*)arg;
    std::string fingerprint(keyFingerprint);
    return store->getMinGeneration(fingerprint, minGeneration);
}

static TACK_RETVAL tackStoreSetMinGeneration(void* arg, char* keyFingerprint, 
                                             uint8_t minGeneration)
{
    TackStore* store = (TackStore*)arg;
    std::string fingerprint(keyFingerprint);
    return store->setMinGeneration(fingerprint, minGeneration);
}

static TACK_RETVAL tackStoreGetNameRecord(void* arg, void* name, TackNameRecord* nameRecord)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    return store->getNameRecord(*nameStr, nameRecord);
}

static TACK_RETVAL tackStoreSetNameRecord(void* arg, void* name, TackNameRecord* nameRecord)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    return store->setNameRecord(*nameStr, nameRecord);
}

static TACK_RETVAL tackStoreUpdateNameRecord(void* arg, void* name, uint32_t newEndTime)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    return store->updateNameRecord(*nameStr, newEndTime);    
}

static TACK_RETVAL tackStoreDeleteNameRecord(void* arg, void* name)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    return store->deleteNameRecord(*nameStr);    
}

// TackStore methods

void TackStore::setCryptoFuncs(TackCryptoFuncs* newCrypto) {
    crypto = newCrypto;}
TackCryptoFuncs* TackStore::getCryptoFuncs() {return crypto;}

void TackStore::setRevocationStore(TackStore* newRevocationStore) {
    revocationStore = newRevocationStore;}
bool TackStore::getRevocationStore() {return revocationStore;}

TackStore::TackStore():crypto(NULL),revocationStore(this) {}

static TackStoreFuncs storeFuncs = {
    tackStoreGetMinGeneration,
    tackStoreSetMinGeneration,
    tackStoreGetNameRecord,    
    tackStoreSetNameRecord,
    tackStoreUpdateNameRecord,
    tackStoreDeleteNameRecord
};

TACK_RETVAL TackStore::process(TackProcessingContext* ctx,
                               std::string name,
                               uint32_t currentTime,
                               bool doPinActivation)
{
    return tackProcessStore(ctx, &name, currentTime, doPinActivation, &storeFuncs, 
                            this, revocationStore, crypto);
}
