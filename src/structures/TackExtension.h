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

#define TACK_TACK_MAXCOUNT 2

uint8_t  tackExtensionGetNumTacks(uint8_t* tackExt);
uint8_t* tackExtensionGetTack(uint8_t* tackExt, uint8_t index);
uint8_t  tackExtensionGetActivationFlags(uint8_t* tackExt);
uint8_t  tackExtensionGetActivationFlag(uint8_t* tackExt, uint8_t index);

TACK_RETVAL tackExtensionSyntaxCheck(uint8_t* tackExt, uint32_t tackExtLen);

/* Mostly internal helper function, but may be useful in working with tackExts */
uint8_t* tackExtensionPostTacks(uint8_t* tackExt);

#ifdef __cplusplus
}
#endif
#endif
