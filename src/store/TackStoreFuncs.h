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
    char fingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint32_t initialTime;
    uint32_t endTime;
} TackNameRecord;

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
typedef TACK_RETVAL (*TackGetNameRecordFunc)(const void* arg, 
                                             const void* name, 
                                             TackNameRecord* nameRecord);

/* If there's an existing name record, overwrite it.  If there's no existing
   one, create a new one. */
typedef TACK_RETVAL (*TackSetNameRecordFunc)(const void* arg, 
                                             const void* name, 
                                             const TackNameRecord* nameRecord);

/* Returns TACK_OK_NOT_FOUND if no name record */
typedef TACK_RETVAL (*TackUpdateNameRecordFunc)(const void* arg, 
                                                const void* name, 
                                                uint32_t newEndTime);

/* Returns TACK_OK_NOT_FOUND if no name record */
typedef TACK_RETVAL (*TackDeleteNameRecordFunc)(const void* arg, 
                                                const void* name);

/* The store functions, plus a state "arg", are packaged into this struct
   for convenient parameter passing */
typedef struct {
    TackGetMinGenerationFunc getMinGeneration;
    TackSetMinGenerationFunc setMinGeneration; /* Revocation or pin activation */
    TackGetNameRecordFunc getNameRecord;
    TackSetNameRecordFunc setNameRecord; /* Pin activation */
    TackUpdateNameRecordFunc updateNameRecord; /* Pin activation */
    TackDeleteNameRecordFunc deleteNameRecord; /* Pin activation or invalidation */
} TackStoreFuncs;

/* Helper functions */

TACK_RETVAL tackStoreGetPin(const TackStoreFuncs* store, const void* arg, const void* name, 
                            TackNameRecord* nameRecord, uint8_t *minGeneration);

TACK_RETVAL tackStoreSetPin(const TackStoreFuncs* store, const void* arg, const void* name, 
                            const TackNameRecord* nameRecord, uint8_t minGeneration);

#ifdef __cplusplus
}
#endif
#endif
