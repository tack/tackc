/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_KEYRECORD_FUNCS_H__
#define __TACK_KEYRECORD_FUNCS_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"
#include "TackFingerprints.h"

/* The following callbacks are used by tackExtensionProcess() to implement
   client processing */

/* Used to lookup a key's minGeneration (and existence) */
typedef TACK_RETVAL (*TackGetKeyRecordFunc)(void* arg, char* keyFingerprint, 
                                            uint8_t* minGeneration);

/* Used to update a key's minGeneration */
typedef TACK_RETVAL (*TackUpdateKeyRecordFunc)(void* arg, char* keyFingerprint, 
                                               uint8_t minGeneration);

/* Used to delete a key as a result of break signature */
typedef TACK_RETVAL (*TackDeleteKeyRecordFunc)(void* arg, char* keyFingerprint);

/* Used to fetch the relevant pin (if any) */
typedef struct {
    char keyFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t minGeneration;
    uint32_t initialTime;
    uint32_t activePeriodEnd;
} TackPinStruct;

typedef TACK_RETVAL (*TackGetPinFunc)(void* arg, void* argHostName, 
                                      TackPinStruct* pin);

/* Used to set the relevant pin's activePeriodEnd, or create a new pin */
/* Only used by pin activation */
typedef TACK_RETVAL (*TackSetPinFunc)(void* arg, void* argHostName, 
                                      TackPinStruct* pin);

/* Used to delete a relevant but inactive pin */
/* Only used by pin activation */
typedef TACK_RETVAL (*TackDeletePinFunc)(void* arg, void* argHostName);


/* Package all the callbacks, for convenient parameter passing */
typedef struct {
    void* arg;
    void* argHostName;
    TackGetKeyRecordFunc getKeyRecord;
    TackUpdateKeyRecordFunc updateKeyRecord;
    TackDeleteKeyRecordFunc deleteKeyRecord;
    TackGetPinFunc getPin;
    TackSetPinFunc setPin; /* Only needed for pin activation */
    TackDeletePinFunc deletePin; /* Only needed for pin activation */
} TackStoreFuncs;


#ifdef __cplusplus
}
#endif
#endif
