/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_STORE_FUNCS_H__
#define __TACK_STORE_FUNCS_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"
#include "TackFingerprints.h"

/* Structure used to communicate with the store functions */
typedef struct {
    uint32_t initialTime;
    uint32_t endTime;
    char fingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
} TackNameRecord;

typedef struct {
    uint8_t numPins;
    TackNameRecord records[2];
} TackNameRecordPair;


/* Store functions used to communicate with the store: */

/* Returns TACK_OK_NOT_FOUND if no key record */
typedef TACK_RETVAL (*TackGetMinGenerationFunc)(const void* arg, 
                                                const char* keyFingerprint, 
                                                uint8_t* minGeneration);

/* Overwrites existing minGeneration if new value is larger, or writes a new value
   if there's no existing key record.  If new value is smaller, returns TACK_OK 
   but does nothing. */
typedef TACK_RETVAL (*TackSetMinGenerationFunc)(const void* arg, 
                                                const char* keyFingerprint, 
                                                uint8_t minGeneration);

/* Returns TACK_OK_NOT_FOUND if no name record */
typedef TACK_RETVAL (*TackGetNameRecordPairFunc)(const void* arg, 
                                                 const void* name, 
                                                 TackNameRecordPair* pair);

/* Returns TACK_OK_NOT_FOUND if no name record */
typedef TACK_RETVAL (*TackSetNameRecordPairFunc)(const void* arg, 
                                                 const void* name, 
                                                 const TackNameRecordPair* pair);

/* The store functions, plus a state "arg", are packaged into this struct
   for convenient parameter passing */
typedef struct {
    TackGetMinGenerationFunc getMinGeneration;
    TackSetMinGenerationFunc setMinGeneration; /* Generations and pin activation */
    TackGetNameRecordPairFunc getNameRecordPair;
    TackSetNameRecordPairFunc setNameRecordPair;
} TackStoreFuncs;

#ifdef __cplusplus
}
#endif
#endif
