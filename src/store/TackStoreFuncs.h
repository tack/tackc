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


/* Used to fetch the relevant pin (if any) */
typedef struct {
    char keyFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t minGeneration;
    uint32_t initialTime;
    uint32_t activePeriodEnd;
} TackPinStruct;

/* Get the relevant pin 
   If the name record does not exist, return TACK_OK_NOT_FOUND
   If the name record has no key record, return TACK_ERR_MISSING_KEY_RECORD
   (which indicates a corrupted store)
*/
typedef TACK_RETVAL (*TackGetPinFunc)(void* arg, void* argHostName, 
                                      TackPinStruct* pin);

/* Creates a new name record, or overwrites any existing one
   Reuses an existing key record, or creates a new one
   Only used by pin activation */
typedef TACK_RETVAL (*TackSetPinFunc)(void* arg, void* argHostName, 
                                      TackPinStruct* pin);

/* Delete a relevant but inactive pin
   If the name record does not exist, return TACK_OK_NOT_FOUND
   Only used by pin activation 
   May or MAY NOT delete a key record that has become unreferenced
*/
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
