
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
    // Configure the store's crypto functions
    void setCryptoFuncs(TackCryptoFuncs* crypto);
    TackCryptoFuncs* getCryptoFuncs();

    // Configure an associated revocation store for storing
    // minGeneration updates (defaults to "this", can be set to NULL)
    void setRevocationStore(TackStore* revocationStore);
    bool getRevocationStore();

    void setPinActivation(bool pinActivation);
    bool getPinActivation();

    /* Main entry point for client processing */
    TACK_RETVAL process(TackProcessingContext* ctx,
                        std::string name,
                        uint32_t currentTime,
                        bool invalidateOnly=false);

    TACK_RETVAL getPin(std::string& name, TackNameRecord* nameRecord, 
                       uint8_t *minGeneration);
    TACK_RETVAL setPin(std::string& name, TackNameRecord* nameRecord, 
                       uint8_t minGeneration);

    /* Define the below functions in a subclass */
    virtual TACK_RETVAL getMinGeneration(std::string& keyFingerprint, 
                                     uint8_t* minGeneration) = 0;
    virtual TACK_RETVAL setMinGeneration(std::string& keyFingerprint, 
                                        uint8_t minGeneration) = 0;
    
    virtual TACK_RETVAL getNameRecord(std::string& name, TackNameRecord* nameRecord) = 0;
    virtual TACK_RETVAL setNameRecord(std::string& name, TackNameRecord* nameRecord) = 0;  
    virtual TACK_RETVAL updateNameRecord(std::string& name, uint32_t newEndTime) = 0;  
    virtual TACK_RETVAL deleteNameRecord(std::string& name) = 0;

private:
    bool pinActivation_;
    TackCryptoFuncs* crypto_;
    TackStore* revocationStore_;
};

#endif
