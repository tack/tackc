
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
    virtual TACK_RETVAL getNameRecordPair(const std::string& name, 
                                          TackNameRecordPair* pair) OVERRIDE;
    virtual TACK_RETVAL setNameRecordPair(const std::string& name, 
                                          const TackNameRecordPair* pair) OVERRIDE;

    virtual TACK_RETVAL serialize(char* list, uint32_t* listLen) OVERRIDE;

    virtual TACK_RETVAL deserialize(const char* list, uint32_t* listLen) OVERRIDE;

    virtual TACK_RETVAL clear() OVERRIDE;

    virtual uint32_t numPinned() OVERRIDE;
    virtual uint32_t numKeys() OVERRIDE;

private:
    
    // Maps names to name record pairs
    std::map<std::string, TackNameRecordPair> nameRecords_;
    
    // Maps key fingerprints to minGenerations
    std::map<std::string, uint8_t> keyRecords_;
};

#endif
