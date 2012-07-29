
/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_STORE_H__
#define __TACK_STORE_H__

#include <map>
#include <string>
#include "TackProcessing.h"
#include "TackCryptoFuncs.h"
#include "TackRetval.h"

class TackStore {
public:
    TackStore();

    // Accessors
    void setPinActivation(bool pinActivation);
    bool getPinActivation();

    void setCryptoFuncs(TackCryptoFuncs* crypto);
    TackCryptoFuncs* getCryptoFuncs();

    void setDirtyFlag(bool dirtyFlag);
    bool getDirtyFlag();

    // Main entry point for client processing
    TACK_RETVAL process(TackProcessingContext* ctx,
                        const std::string& name,
                        uint32_t currentTime);

    // Convenience functions
    TACK_RETVAL getPin(const std::string& name, TackNameRecord* nameRecord, 
                       uint8_t *minGeneration);
    TACK_RETVAL setPin(const std::string& name, const TackNameRecord* nameRecord, 
                       uint8_t minGeneration);

    // Define the below functions in a subclass
    virtual TACK_RETVAL getMinGeneration(const std::string& keyFingerprint, 
                                     uint8_t* minGeneration) = 0;
    virtual TACK_RETVAL setMinGeneration(const std::string& keyFingerprint, 
                                        uint8_t minGeneration) = 0;
    
    virtual TACK_RETVAL getNameRecord(const std::string& name, 
                                      TackNameRecord* nameRecord) = 0;
    virtual TACK_RETVAL setNameRecord(const std::string& name, 
                                      const TackNameRecord* nameRecord) = 0;  
    virtual TACK_RETVAL updateNameRecord(const std::string& 
                                         name, uint32_t newEndTime) = 0;  
    virtual TACK_RETVAL deleteNameRecord(const std::string& name) = 0;

    virtual TACK_RETVAL clear() = 0;

    virtual TACK_RETVAL serialize(char* list, uint32_t* listLen) = 0;

    virtual TACK_RETVAL deserialize(const char* list, uint32_t* listLen) = 0;


private:
    bool pinActivation_;
    TackCryptoFuncs* crypto_;
    bool dirtyFlag_;
};

#endif
