/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_EXTENSION_H__
#define __TACK_EXTENSION_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "TackRetval.h"
#include "TackCryptoFuncs.h"
#include "Tack.h"
#include "TackBreakSig.h"

#define TACK_BREAKSIGS_MAXCOUNT 8

typedef struct {
    uint8_t tackCount; /* 0 or 1 */
    Tack tack;
    
    uint8_t breakSigsCount; /* 0...8 */
    TackBreakSig breakSigs[TACK_BREAKSIGS_MAXCOUNT];
    
    uint8_t activationFlag;
} TackExtension;

TACK_RETVAL tackExtensionInit(TackExtension* tackExt, uint8_t* data, uint32_t len);
TACK_RETVAL tackExtensionVerifySignatures(TackExtension* tackExt, VerifyFunc func);

#ifdef __cplusplus
}
#endif
#endif
