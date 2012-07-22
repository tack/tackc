
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

    virtual TACK_RETVAL getMinGeneration(std::string& keyFingerprint,
                                         uint8_t* minGeneration) OVERRIDE;
    virtual TACK_RETVAL setMinGeneration(std::string& keyFingerprint, 
                                         uint8_t minGeneration) OVERRIDE;
    
    virtual TACK_RETVAL getNameRecord(std::string& name, 
                                      TackNameRecord* nameRecord) OVERRIDE;
    virtual TACK_RETVAL setNameRecord(std::string& name, 
                                      TackNameRecord* nameRecord) OVERRIDE;  
    virtual TACK_RETVAL updateNameRecord(std::string& name, 
                                  uint32_t newEndTime) OVERRIDE;  
    virtual TACK_RETVAL deleteNameRecord(std::string& name) OVERRIDE;

//private:
    
    // Maps names to name records
    std::map<std::string, TackNameRecord> nameRecords_;
    
    // Maps key fingerprints to minGenerations
    std::map<std::string, uint8_t> keyRecords_;
};

#endif
