
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
    
    virtual TACK_RETVAL getNameRecord(const std::string& name, 
                                      TackNameRecord* nameRecord) OVERRIDE;
    virtual TACK_RETVAL setNameRecord(const std::string& name, 
                                      TackNameRecord* nameRecord) OVERRIDE;  
    virtual TACK_RETVAL updateNameRecord(const std::string& name, 
                                  uint32_t newEndTime) OVERRIDE;  
    virtual TACK_RETVAL deleteNameRecord(const std::string& name) OVERRIDE;

    virtual TACK_RETVAL serialize(char* list, uint32_t* listLen) OVERRIDE;

private:
    
    // Maps names to name records
    std::map<std::string, TackNameRecord> nameRecords_;
    
    // Maps key fingerprints to minGenerations
    std::map<std::string, uint8_t> keyRecords_;
};

#endif
