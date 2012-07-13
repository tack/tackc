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

/* Main entry point for client processing */
TACK_RETVAL tackProcess(uint8_t* tackExt, uint32_t tackExtLen,
                        uint8_t keyHash[TACK_HASH_LENGTH],
                        uint32_t currentTime,
                        uint8_t doPinActivation,
                        TackStoreFuncs* store,
                        TackCryptoFuncs* crypto);

#ifdef __cplusplus
}
#endif
#endif
