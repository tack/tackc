
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
    
    TACK_RETVAL setPin(std::string hostName, 
                       KeyRecord keyRecord, NameRecord nameRecord);  
    TACK_RETVAL getPin(std::string hostName, 
                       KeyRecord& keyRecord, NameRecord& nameRecord);
    TACK_RETVAL deletePin(std::string hostName);
    
    TACK_RETVAL updateKeyRecord(std::string keyFingerprint, KeyRecord keyRecord);
    TACK_RETVAL getKeyRecord(std::string keyFingerprint, KeyRecord& keyRecord);
    TACK_RETVAL deleteKeyRecord(std::string keyFingerprint);

    TACK_RETVAL pinActivation(uint8_t* tackExt,
                              std::string hostName,
                              uint32_t currentTime,
                              TackHashFunc func);
    TACK_RETVAL processTackExtension(uint8_t* tackExt, uint32_t tackExtLen,
                                     uint8_t keyHash[TACK_HASH_LENGTH],
                                     uint32_t currentTime,
                                     TackHashFunc hashFunc, 
                                     TackVerifyFunc verifyFunc);
    TACK_RETVAL processBreakSigs(uint8_t* tackExt, TackHashFunc hashFunc, 
                                 TackVerifyFunc verifyFunc);
    
public:
    
    // Maps hostnames to name records
    std::map<std::string, NameRecord> nameRecords;
    
    // Maps key fingerprints to key records
    std::map<std::string, KeyRecord> keyRecords;
};

#endif
