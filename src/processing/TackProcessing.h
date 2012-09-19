/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_PROCESSING_H__
#define __TACK_PROCESSING_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "TackRetval.h"
#include "TackCryptoFuncs.h"
#include "TackStoreFuncs.h"
#include "TackFingerprints.h"


/* This struct stores processing state between tackProcessWellFormed() and 
   tackProcessStore(), and between tackProcessStore() calls */
typedef struct {
    uint8_t* tackExt;
    uint8_t numTacks;
    uint8_t* tacks[2];
    char fingerprints[2][TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
} TackProcessingContext;


/* Call once for each connection to check well-formedness and 
   initialize the context */
TACK_RETVAL tackProcessWellFormed(TackProcessingContext* ctx,
                                  uint8_t* tackExt, uint32_t tackExtLen,
                                  uint8_t keyHash[TACK_HASH_LENGTH],
                                  uint32_t currentTime,
                                  TackCryptoFuncs* crypto);

/* Call once for each store, after the above well-formed check.
   Relies on tackProcessStoreHelper() to do client-processing logic,
   but handles interaction with the store. 

   Returns TACK_OK_ACCEPTED, TACK_OK_REJECTED, TACK_OK_UNPINNED, or error
*/
TACK_RETVAL tackProcessStore(void* storeArg, TackStoreFuncs* store, 
                             TackProcessingContext* ctx,  uint8_t pinActivation,
                             const void* name, uint32_t currentTime, 
                             TackCryptoFuncs* crypto);

#ifdef __cplusplus
}
#endif
#endif
