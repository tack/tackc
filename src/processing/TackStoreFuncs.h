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

/* Store functions used to communicate with the store */
typedef TACK_RETVAL (*TackGetMinGenerationFunc)(void* arg, char* keyFingerprint, 
                                                uint8_t* minGeneration);
typedef TACK_RETVAL (*TackSetMinGenerationFunc)(void* arg, char* keyFingerprint, 
                                                uint8_t minGeneration);
typedef TACK_RETVAL (*TackGetNameRecordFunc)(void* arg, void* name, 
                                             TackNameRecord* nameRecord);
typedef TACK_RETVAL (*TackSetNameRecordFunc)(void* arg, void* name, 
                                             TackNameRecord* nameRecord);
typedef TACK_RETVAL (*TackUpdateNameRecordFunc)(void* arg, void* name, 
                                                uint32_t newEndTime);
typedef TACK_RETVAL (*TackDeleteNameRecordFunc)(void* arg, void* name);

/* The store functions, plus a state "arg", are packaged into this struct
   for convenient parameter passing */
typedef struct {
    void* arg;
    TackGetMinGenerationFunc getMinGeneration;
    TackSetMinGenerationFunc setMinGeneration; /* Revocation or pin activation */
    TackGetNameRecordFunc getNameRecord;
    TackSetNameRecordFunc setNameRecord; /* Only needed for pin activation */
    TackUpdateNameRecordFunc updateNameRecord; /* Only needed for pin activation */
    TackDeleteNameRecordFunc deleteNameRecord; /* Only needed for pin activation */
} TackStoreFuncs;


#ifdef __cplusplus
}
#endif
#endif