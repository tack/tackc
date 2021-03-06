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

static TACK_RETVAL tackStoreGetPinPair(const void* arg, const void* name, 
                                       TackPinPair* pair)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    return store->getPinPair(*nameStr, pair);
}

static TACK_RETVAL tackStoreSetPinPair(const void* arg, const void* name, 
                                       const TackPinPair* pair)
{
    TackStore* store = (TackStore*)arg;
    std::string* nameStr = (std::string*)name;
    TACK_RETVAL retval = store->setPinPair(*nameStr, pair);
    if (retval == TACK_OK) {
        store->setDirtyFlag(true);
    }
    return retval;
}

// TackStore methods

TackStore::TackStore() : pinActivation_(false), crypto_(NULL),
                       dirtyFlag_(false), dirtyFlagEnabled_(false) {}

void TackStore::setPinActivation(bool pinActivation) {
    pinActivation_ = pinActivation; }
bool TackStore::getPinActivation() {return pinActivation_;}

void TackStore::setCryptoFuncs(TackCryptoFuncs* crypto) {
    crypto_ = crypto;}
TackCryptoFuncs* TackStore::getCryptoFuncs() {return crypto_;}

void TackStore::setDirtyFlag(bool dirtyFlag) {
    if (dirtyFlagEnabled_) dirtyFlag_ = dirtyFlag;}
bool TackStore::getDirtyFlag() {return dirtyFlag_;}

void TackStore::setDirtyFlagEnabled(bool dirtyFlagEnabled) {
    dirtyFlagEnabled_ = dirtyFlagEnabled;}
bool TackStore::getDirtyFlagEnabled() { return dirtyFlagEnabled_;}



static TackStoreFuncs storeFuncs = {
    tackStoreGetMinGeneration,
    tackStoreSetMinGeneration,
    tackStoreGetPinPair,
    tackStoreSetPinPair,
};

TACK_RETVAL TackStore::process(TackProcessingContext* ctx,
                               const std::string& name,
                               uint32_t currentTime)
{
    if (!crypto_) return TACK_ERR_ASSERTION;
    return tackProcessStore(this, &storeFuncs, ctx, (uint8_t)pinActivation_, &name, 
                            currentTime, crypto_);
}
