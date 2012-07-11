
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

    virtual TACK_RETVAL getKeyRecord(std::string keyFingerprint, KeyRecord& keyRecord);
    virtual TACK_RETVAL updateKeyRecord(std::string keyFingerprint, KeyRecord keyRecord);
    virtual TACK_RETVAL deleteKeyRecord(std::string keyFingerprint);

    virtual TACK_RETVAL getPin(std::string hostName, 
                               KeyRecord& keyRecord, NameRecord& nameRecord);    
    virtual TACK_RETVAL setPin(std::string hostName, 
                               KeyRecord keyRecord, NameRecord nameRecord);  
    virtual TACK_RETVAL deletePin(std::string hostName);
    
private:
    
    // Maps hostnames to name records
    std::map<std::string, NameRecord> nameRecords;
    
    // Maps key fingerprints to key records
    std::map<std::string, KeyRecord> keyRecords;
};

#endif
