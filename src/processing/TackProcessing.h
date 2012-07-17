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
#include "TackFingerprints.h"

typedef struct {
    uint8_t* tackExt;
    uint8_t* tack;
    char tackFingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t breakSigFlags;
} TackProcessingContext;

typedef struct {
    char fingerprint[TACK_KEY_FINGERPRINT_TEXT_LENGTH+1];
    uint8_t minGeneration;    
    uint32_t initialTime;
    uint32_t endTime;
} TackPin;

/* Call once for each connection to check well-formedness and 
   initialize the context */
TACK_RETVAL tackProcessWellFormed(uint8_t* tackExt, uint32_t tackExtLen,
                                  uint8_t keyHash[TACK_HASH_LENGTH],
                                  uint32_t currentTime,
                                  TackProcessingContext* ctx,
                                  TackCryptoFuncs* crypto);

/* After calling tackProcessWellFormed, call the below once for each store 
   (Or use the C++ TackStore classes which wrap this) */
TACK_RETVAL tackProcessStore(TackProcessingContext* ctx,
                             uint32_t currentTime,   
                             /* Input data from store (pin/minGeneration): */
                             TackPin* pin,
                             uint8_t minGeneration,
                             /* Output data for store (pin/minGeneration): */
                             TACK_RETVAL* activationRetval, /* OK/DELETE/UPDATE/NEW */
                             TackPin* pinOut,
                             uint8_t* minGenerationOut,
                             TackCryptoFuncs* crypto);

#ifdef __cplusplus
}
#endif
#endif
