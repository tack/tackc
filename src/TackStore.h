
/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_EXTENSION_H__
#define __TACK_EXTENSION_H__

#include <map>
#include <string>
#include "TackRetval.h"

class TackStore {
public:

    struct KeyRecord {
        uint8_t minGeneration;
    };
    
    struct NameRecord {
        std::string keyFingerprint;
        uint32_t initialTime;
        uint32_t activePeriodEnd;
    };
    
    TACK_RETVAL addPin(std::string& hostName, KeyRecord* keyRecord, NameRecord* nameRecord);  
    TACK_RETVAL getPin(std::string& hostName, KeyRecord* keyRecord, NameRecord* nameRecord);
    
    TACK_RETVAL getKeyRecord(std::string& keyFingerprint, KeyRecord* keyRecord);
    TACK_RETVAL deleteKeyRecord(std::string& keyFingerprint);
    
private:
    
    // Maps hostnames to name records
    std::map<std::string, NameRecord> nameRecords;
    
    // Maps key fingerprints to key records
    std::map<std::string, KeyRecord> keyRecords;
};

#endif
