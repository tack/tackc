
/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_STORE_H__
#define __TACK_STORE_H__

#include <map>
#include <string>
#include "TackCryptoFuncs.h"
#include "TackRetval.h"

/* C callbacks for use with tackExtensionProcess */
TACK_RETVAL tackTackStoreGetKeyRecord(void* krArg, char* keyFingerprintBuf, 
                                  uint8_t* minGeneration);
TACK_RETVAL tackTackStoreUpdateKeyRecord(void* krArg, char* keyFingerprintBuf, 
                                     uint8_t minGeneration);
TACK_RETVAL tackTackStoreDeleteKeyRecord(void* krArg, char* keyFingerprintBuf);


class TackStore {
public:

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
    };
    
    virtual TACK_RETVAL setPin(std::string hostName, 
                       KeyRecord keyRecord, NameRecord nameRecord) = 0;  
    virtual TACK_RETVAL getPin(std::string hostName, 
                       KeyRecord& keyRecord, NameRecord& nameRecord) = 0;
    virtual TACK_RETVAL deletePin(std::string hostName) = 0;
    
    virtual TACK_RETVAL updateKeyRecord(std::string keyFingerprint, 
                                        KeyRecord keyRecord) = 0;
    virtual TACK_RETVAL getKeyRecord(std::string keyFingerprint, 
                                     KeyRecord& keyRecord) = 0;
    virtual TACK_RETVAL deleteKeyRecord(std::string keyFingerprint) = 0;

    TACK_RETVAL pinActivation(uint8_t* tackExt,
                              std::string hostName,
                              uint32_t currentTime,
                              TackHashFunc func);
};

#endif
