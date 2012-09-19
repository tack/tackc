#include "TackStoreDefault.h"
#include "TackPinList.h"
#include "TackStoreFuncs.h"
#include <stdio.h>

// These don't do anything but Chromium wants them:
TackStoreDefault::TackStoreDefault(){}
TackStoreDefault::~TackStoreDefault(){}


TACK_RETVAL TackStoreDefault::getMinGeneration(const std::string& keyFingerprint, 
                                           uint8_t* minGeneration)
{
    std::map<std::string, uint8_t>::iterator ki = keys_.find(keyFingerprint);
    if (ki == keys_.end())
        return TACK_OK_NOT_FOUND;

    *minGeneration = ki->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setMinGeneration(const std::string& keyFingerprint, 
                                               uint8_t minGeneration)
{
    std::map<std::string, uint8_t>::iterator ki = keys_.find(keyFingerprint);
    if (ki == keys_.end())
        keys_[keyFingerprint] = minGeneration;
    else if (minGeneration > ki->second)
        ki->second = minGeneration;

    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::getPinPair(const std::string& name, 
                                            TackPinPair* pair)
{
    std::map<std::string, TackPinPair>::iterator ni = pins_.find(name);
    if (ni == pins_.end()) {
        pair->numPins = 0;
        return TACK_OK_NOT_FOUND;
    }

    *pair = ni->second;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::setPinPair(const std::string& name, 
                                            const TackPinPair* pair)
{
    if (pair->numPins == 0)
        pins_.erase(name);
    else
        pins_[name] = *pair;
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::clear()
{
    pins_.clear();
    keys_.clear();
    return TACK_OK;
}

TACK_RETVAL TackStoreDefault::addPin(const std::string& name, const TackPin* pin) 
{
    TackPinPair pair;
    TACK_RETVAL retval;

    if ((retval=getPinPair(name, &pair)) < TACK_OK)
        return retval;
    if (pair.numPins == 2)
        return TACK_ERR_BAD_PINLIST;
    else {
        memcpy(&pair.pins[pair.numPins], pin, sizeof(TackPin));
        pair.numPins++;
    }    
    return setPinPair(name, &pair);
}


/* Specify the length of the buffer - will not be overwritten, but only
   listLen-1 chars can actually be stored, due to final NULL */
TACK_RETVAL TackStoreDefault::serialize(char* list, uint32_t* listLen)
{
    std::map<std::string, TackPinPair>::iterator ni;
    uint32_t oldListLen = 0;
    uint8_t minGeneration = 0;
    TACK_RETVAL retval = TACK_OK; /* default return */

    if (*listLen < 2) /* account for the NULL */
        return TACK_ERR_UNDERSIZED_BUFFER;
    *list++ = '[';
    *listLen -= 1;

    // Iterate through all pins (map guarantees to sort alphabetically by name)
    bool firstTime = true;
    for (ni=pins_.begin(); ni != pins_.end(); ni++)  {
        TackPinPair* pair = &ni->second;
        int count = 0;
        int countInc = 1;
        int countLimit = pair->numPins;

        // If there are two pins, determine if we need to reverse the serialization
        // order to write out the pair alphabetically-sorted by fingerprint
        if (pair->numPins == 2) {
            std::string f0(pair->pins[0].fingerprint);
            std::string f1(pair->pins[1].fingerprint);
            if (f0 > f1) {
                count = 1;
                countInc = -1;
                countLimit = -1;
            }
        }

        // Iterate through each in pin the pair...
        for (; count != countLimit; count += countInc) {
            TackPin* pin = &pair->pins[count];

            retval=getMinGeneration(pin->fingerprint, &minGeneration);
            if (retval != TACK_OK)
                return retval;
            
            // Write comma prior to every entry but first
            if (firstTime)
                firstTime = false;
            else {
                if (*listLen < 2)
                    return TACK_ERR_UNDERSIZED_BUFFER;
                *list++ = ',';
                *listLen -= 1;
            }
            
            if (*listLen < 2)
                return TACK_ERR_UNDERSIZED_BUFFER;
            *list++ = '\n';
            *listLen -= 1;
            
            // Write the entry
            oldListLen = *listLen;
            if ((retval=tackPinListWriteEntry(list, listLen,
                                              ni->first.c_str(), pin,
                                              minGeneration)) != TACK_OK)
                return retval;
            
            if (retval == TACK_OK_INCOMPLETE_WRITE)
                return TACK_ERR_UNDERSIZED_BUFFER;
            
            list += (oldListLen - *listLen);
        }    
    }
    
    if (*listLen < 4)
        return TACK_ERR_UNDERSIZED_BUFFER;
    *list++ = '\n';
    *list++ = ']';
    *list++ = '\n';
    *list++ = 0;
    *listLen -= 3;

    return retval;
}

TACK_RETVAL TackStoreDefault::deserialize(const char* list, uint32_t* listLen)
{
    uint8_t state = 0;
    /* 0 = Start (before '{')
       1 = Before entry (before entry or '}')
       2 = After entry (before ',' or '}')
    */

    TACK_RETVAL retval = TACK_ERR;
    char name[256]; // 255-char length plus NULL
    char prevName[256]; // " "
    TackPin pin;
    uint8_t minGeneration = 0;
    uint32_t oldListLen = 0;

    clear();
    memset(name, 0, sizeof(name));
    memset(prevName, 0, sizeof(prevName));
    memset(&pin, 0, sizeof(TackPin));

    while (1) {

        // Check for end of string
        if ((*list == 0) || (*listLen == 0)) {
            if (state != 0)
                return TACK_ERR_BAD_PINLIST;
            break;
        }

        // Skip whitespace
        if (*list == ' ' || *list == '\n' || *list == '\t')
        {}

        else if (state == 0) { // Start
            if (*list == '[')
                state = 1;
            else {
                return TACK_ERR_BAD_PINLIST;
            }
        }

        else if (state == 1)  { // Before entry
            if (*list == ']') {
                break;
            }
            else {
                oldListLen = *listLen;
                strcpy(prevName, name);
                retval = tackPinListParseEntry(list, listLen,
                                               name, &pin, &minGeneration);

                /* Add key record */
                retval = setMinGeneration(pin.fingerprint, minGeneration);
                if (retval != TACK_OK)
                    return retval;

                /* Add pin */
                if ((retval = addPin(name, &pin)) != TACK_OK)
                    return retval;

                list += (oldListLen - *listLen);
                state = 2;
                continue;
            }
        }

        else if (state == 2) { // After entry
            if (*list == ',')
                state = 1;
            else if (*list == ']') {
                break;
            }
            else {
                return TACK_ERR_BAD_PINLIST;
            }
        }
        list++;
        *listLen -= 1;
    }
    return TACK_OK;
}

uint32_t TackStoreDefault::numPinned()
{
    return pins_.size();
}

uint32_t TackStoreDefault::numKeys()
{
    return keys_.size();
}
