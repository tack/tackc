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

/* Used to fetch the relevant pin (if any) */
typedef struct {
    char keyFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t minGeneration;
    uint32_t initialTime;
    uint32_t endTime;
} TackPinStruct;

/* The following callbacks are used by tackExtensionProcess() to implement
   client processing */

/* Lookup a key's minGeneration (and existence) 
   Returns TACK_OK, TACK_OK_NOT_FOUND, or some error
*/
typedef TACK_RETVAL (*TackGetKeyRecordFunc)(void* arg, char* keyFingerprint, 
                                            uint8_t* minGeneration);

/* Update a key's minGeneration 
   If the key record does not exist, return TACK_OK_NOT_FOUND
*/
typedef TACK_RETVAL (*TackUpdateKeyRecordFunc)(void* arg, char* keyFingerprint, 
                                               uint8_t minGeneration);

/* Delete a key as a result of break signature 
   If the key record does not exist, return TACK_OK_NOT_FOUND
*/
typedef TACK_RETVAL (*TackDeleteKeyRecordFunc)(void* arg, char* keyFingerprint);

/* Get the relevant pin 
   If the name record does not exist, return TACK_OK_NOT_FOUND
   If the name record has no key record, return TACK_ERR_MISSING_KEY_RECORD
   (which indicates a corrupted store)
*/
typedef TACK_RETVAL (*TackGetPinFunc)(void* arg, void* name, 
                                      TackPinStruct* pin);

typedef TACK_RETVAL (*TackNewPinFunc)(void* arg, void* name, 
                                       TackPinStruct* pin);

typedef TACK_RETVAL (*TackUpdatePinFunc)(void* arg, void* name, 
                                         uint32_t newEndTime);


/* Delete a relevant but inactive pin
   If the name record does not exist, return TACK_OK_NOT_FOUND
   Only used by pin activation 
   May or MAY NOT delete a key record that has become unreferenced
*/
typedef TACK_RETVAL (*TackDeletePinFunc)(void* arg, void* name);


/* Package all the callbacks, for convenient parameter passing */
typedef struct {
    void* arg;
    TackGetKeyRecordFunc getKeyRecord;
    TackUpdateKeyRecordFunc updateKeyRecord;
    TackDeleteKeyRecordFunc deleteKeyRecord;
    TackGetPinFunc getPin;
    TackNewPinFunc newPin; /* Only needed for pin activation */
    TackUpdatePinFunc updatePin; /* Only needed for pin activation */
    TackDeletePinFunc deletePin; /* Only needed for pin activation */
} TackStoreFuncs;


#ifdef __cplusplus
}
#endif
#endif
