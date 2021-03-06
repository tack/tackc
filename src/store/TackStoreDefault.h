
/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_STORE_DEFAULT_H__
#define __TACK_STORE_DEFAULT_H__

#include "TackStore.h"

// For Chromium
#include "base/compiler_specific.h"

class TackStoreDefault : public TackStore {

public:
    TackStoreDefault();
    ~TackStoreDefault();

    virtual TACK_RETVAL getMinGeneration(const std::string& keyFingerprint,
                                         uint8_t* minGeneration) OVERRIDE;
    virtual TACK_RETVAL setMinGeneration(const std::string& keyFingerprint, 
                                         uint8_t minGeneration) OVERRIDE;
    virtual TACK_RETVAL getPinPair(const std::string& name, 
                                   TackPinPair* pair) OVERRIDE;
    virtual TACK_RETVAL setPinPair(const std::string& name, 
                                   const TackPinPair* pair) OVERRIDE;

    virtual TACK_RETVAL serialize(char* list, uint32_t* listLen) OVERRIDE;
    virtual TACK_RETVAL deserialize(const char* list, uint32_t* listLen) OVERRIDE;

    virtual TACK_RETVAL clear() OVERRIDE;

    virtual uint32_t numPinned() OVERRIDE;
    virtual uint32_t numKeys() OVERRIDE;

private:

    // Used by deserialize()
    TACK_RETVAL addPin(const std::string& name, const TackPin* pin);
    
    // Maps names to pin pairs
    std::map<std::string, TackPinPair> pins_;
    
    // Maps key fingerprints to minGenerations
    std::map<std::string, uint8_t> keys_;
};

#endif
