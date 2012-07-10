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
#include "TackKeyRecordFuncs.h"
#include "Tack.h"
#include "TackBreakSig.h"

#define TACK_BREAKSIGS_MAXCOUNT 8

uint8_t* tackExtensionGetTack(uint8_t* tackExt);
uint8_t  tackExtensionGetNumBreakSigs(uint8_t* tackExt);
uint8_t* tackExtensionGetBreakSig(uint8_t* tackExt, uint8_t index);
uint8_t  tackExtensionGetActivationFlag(uint8_t* tackExt);

TACK_RETVAL tackExtensionSyntaxCheck(uint8_t* tackExt, uint32_t tackExtLen);

TACK_RETVAL tackExtensionProcess(uint8_t* tackExt, uint32_t tackExtLen,
                                 uint8_t keyHash[TACK_HASH_LENGTH],
                                 uint32_t currentTime,
                                 void* krArg,
                                 TackGetKeyRecordFunc getKrFunc,
                                 TackUpdateKeyRecordFunc updateKrFunc,
                                 TackDeleteKeyRecordFunc deleteKrFunc,
                                 TackHashFunc hashFunc, 
                                 TackVerifyFunc verifyFunc);

#ifdef __cplusplus
}
#endif
#endif
