
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

    void setDirtyFlagEnabled(bool dirtyFlagEnabled);
    bool getDirtyFlagEnabled();

    // Main entry point for client processing
    TACK_RETVAL process(TackProcessingContext* ctx,
                        const std::string& name,
                        uint32_t currentTime);

    // Define the below functions in a subclass
    virtual TACK_RETVAL getMinGeneration(const std::string& keyFingerprint, 
                                     uint8_t* minGeneration) = 0;
    virtual TACK_RETVAL setMinGeneration(const std::string& keyFingerprint, 
                                        uint8_t minGeneration) = 0;

    virtual TACK_RETVAL getNameRecordPair(const std::string& name, 
                                          TackNameRecordPair* pair) = 0;
    virtual TACK_RETVAL setNameRecordPair(const std::string& name, 
                                          const TackNameRecordPair* pair) = 0;  

    virtual TACK_RETVAL serialize(char* list, uint32_t* listLen) = 0;
    virtual TACK_RETVAL deserialize(const char* list, uint32_t* listLen) = 0;

    virtual TACK_RETVAL clear() = 0;

    virtual uint32_t numPinned() = 0;
    virtual uint32_t numKeys() = 0;

private:
    bool pinActivation_;
    TackCryptoFuncs* crypto_;
    bool dirtyFlag_;
    bool dirtyFlagEnabled_;
};

#endif
