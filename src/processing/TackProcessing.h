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
    uint8_t* tack;
    char tackFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t breakSigFlags;
} TackProcessingContext;


/* Call once for each connection to check well-formedness and 
   initialize the context */
TACK_RETVAL tackProcessWellFormed(TackProcessingContext* ctx,
                                  uint8_t* tackExt, uint32_t tackExtLen,
                                  uint8_t keyHash[TACK_HASH_LENGTH],
                                  uint32_t currentTime,
                                  TackCryptoFuncs* crypto);

/* Call once for each store, after the above well-formed check */
TACK_RETVAL tackProcessStore(TackProcessingContext* ctx,
                             const void* name,
                             uint32_t currentTime,
                             uint8_t pinActivation,
                             uint8_t invalidateOnly,
                             TackStoreFuncs* store, 
                             void* storeArg, 
                             TackCryptoFuncs* crypto);

/* Helper function used by tackProcessStore() 
   Performs the core client processing logic, but uses in/out variables
   instead of accessing the store. */
TACK_RETVAL tackProcessStoreHelper(TackProcessingContext* ctx,
                                   uint32_t currentTime,   
                                   TackNameRecord* nameRecord,
                                   uint8_t* minGeneration,
                                   TACK_RETVAL* activationRetval,
                                   TackNameRecord* nameRecordOut,
                                   uint8_t* minGenerationOut,
                                   uint8_t invalidateOnly,
                                   TackCryptoFuncs* crypto);


#ifdef __cplusplus
}
#endif
#endif
