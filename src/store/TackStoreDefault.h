
/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_STORE_DEFAULT_H__
#define __TACK_STORE_DEFAULT_H__

#include "TackStore.h"

class TackStoreDefault : public TackStore {

public:
    /* Main entry point for processing a TACK_Extension */
    TACK_RETVAL process(uint8_t* tackExt, uint32_t tackExtLen,
                        std::string name,
                        uint8_t keyHash[TACK_HASH_LENGTH],
                        uint32_t currentTime,
                        uint8_t doPinActivation,
                        TackCryptoFuncs* crypto);

    virtual TACK_RETVAL getKeyRecord(std::string& keyFingerprint, uint8_t* minGeneration);
    virtual TACK_RETVAL updateKeyRecord(std::string& keyFingerprint, uint8_t minGeneration);
    virtual TACK_RETVAL deleteKeyRecord(std::string& keyFingerprint);
    
    virtual TACK_RETVAL getPin(std::string& name, TackPinStruct* pin);
    virtual TACK_RETVAL newPin(std::string& name, TackPinStruct* pin);  
    virtual TACK_RETVAL updatePin(std::string& name, uint32_t newActivePeriodEnd);  
    virtual TACK_RETVAL deletePin(std::string& name);
    
private:
    class KeyRecord {
    public:
        KeyRecord();
        KeyRecord(uint8_t newMinGeneration);

        uint8_t minGeneration;
    };
    
    class NameRecord {
    public:
        NameRecord();
        NameRecord(std::string newKeyFingerprint,
                   uint32_t newInitialTime,
                   uint32_t newActivePeriodEnd);

        std::string keyFingerprint;
        uint32_t initialTime;
        uint32_t activePeriodEnd;
        uint8_t krTime;
    };
    
    // Maps names to name records
    std::map<std::string, NameRecord> nameRecords;
    
    // Maps key fingerprints to key records
    std::map<std::string, KeyRecord> keyRecords;
};

#endif
