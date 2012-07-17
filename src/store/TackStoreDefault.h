
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
    
    virtual TACK_RETVAL getPin(std::string& name, TackPin* pin) OVERRIDE;
    virtual TACK_RETVAL newPin(std::string& name, TackPin* pin) OVERRIDE;  
    virtual TACK_RETVAL updatePin(std::string& name, 
                                  uint32_t newEndTime) OVERRIDE;  
    virtual TACK_RETVAL deletePin(std::string& name) OVERRIDE;

    virtual std::string getStringDump() OVERRIDE;
    
private:
    
    // Maps names to name records (but ignore TackPin.minGeneration)
    std::map<std::string, TackPin> nameRecords;
    
    // Maps key fingerprints to minGenerations
    std::map<std::string, uint8_t> keyRecords;
};

#endif
