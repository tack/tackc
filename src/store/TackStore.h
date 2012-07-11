
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
#include "TackStoreFuncs.h"
#include "TackRetval.h"

/* C callbacks for use with tackExtensionProcess */
TACK_RETVAL tackStoreGetKeyRecord(void* krArg, char* keyFingerprintBuf, 
                                  uint8_t* minGeneration);
TACK_RETVAL tackStoreUpdateKeyRecord(void* krArg, char* keyFingerprintBuf, 
                                     uint8_t minGeneration);
TACK_RETVAL tackStoreDeleteKeyRecord(void* krArg, char* keyFingerprintBuf);

TACK_RETVAL tackStoreGetPin(void* arg, void* argHostName, TackPinStruct* pin);
TACK_RETVAL tackStoreSetPin(void* arg, void* argHostName, TackPinStruct* pin);
TACK_RETVAL tackStoreDeletePin(void* arg, void* argHostName);


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


    TACK_RETVAL process(uint8_t* tackExt, uint32_t tackExtLen,
                        std::string hostName,
                        uint8_t keyHash[TACK_HASH_LENGTH],
                        uint32_t currentTime,
                        uint8_t doPinActivation,
                        TackCryptoFuncs* crypto);

private:
    TACK_RETVAL getStoreFuncs(TackStoreFuncs* store, std::string* hostName);
};

#endif
