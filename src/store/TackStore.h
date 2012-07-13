
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
TACK_RETVAL tackStoreGetKeyRecord(void* arg, char* keyFingerprint, 
                                  uint8_t* minGeneration);
TACK_RETVAL tackStoreUpdateKeyRecord(void* arg, char* keyFingerprint, 
                                     uint8_t minGeneration);
TACK_RETVAL tackStoreDeleteKeyRecord(void* arg, char* keyFingerprint);

TACK_RETVAL tackStoreGetPin(void* arg, void* argName, TackPinStruct* pin);
TACK_RETVAL tackStoreNewPin(void* arg, void* argName, TackPinStruct* pin);
TACK_RETVAL tackStoreUpdatePin(void* arg, void* argName, uint32_t newActivePeriodEnd);
TACK_RETVAL tackStoreDeletePin(void* arg, void* argName);


class TackStore {
public:
    /* Main entry point for client processing (in C++) */
    TACK_RETVAL process(std::string name,
                        uint8_t* tackExt, uint32_t tackExtLen,
                        uint8_t keyHash[TACK_HASH_LENGTH],
                        uint32_t currentTime,
                        uint8_t doPinActivation,
                        TackCryptoFuncs* crypto);

    /* Define the below functions in a subclass */
    virtual TACK_RETVAL getKeyRecord(std::string& keyFingerprint, 
                                     uint8_t* minGeneration) = 0;
    virtual TACK_RETVAL updateKeyRecord(std::string& keyFingerprint, 
                                        uint8_t minGeneration) = 0;
    virtual TACK_RETVAL deleteKeyRecord(std::string& keyFingerprint) = 0;
    
    virtual TACK_RETVAL getPin(std::string& name, TackPinStruct* pin) = 0;
    virtual TACK_RETVAL newPin(std::string& name, TackPinStruct* pin) = 0;  
    virtual TACK_RETVAL updatePin(std::string& name, uint32_t newActivePeriodEnd) = 0;  
    virtual TACK_RETVAL deletePin(std::string& name) = 0;

private:
    TACK_RETVAL getStoreFuncs(TackStoreFuncs* store);
};

#endif
