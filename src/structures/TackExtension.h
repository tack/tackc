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

uint8_t  tackExtGetNumTacks(uint8_t* tackExt);
uint8_t* tackExtGetTack(uint8_t* tackExt, uint8_t index);
uint8_t  tackExtGetActivationFlags(uint8_t* tackExt);
uint8_t  tackExtGetActivationFlag(uint8_t* tackExt, uint8_t index);

TACK_RETVAL tackExtSyntaxCheck(uint8_t* tackExt, uint32_t tackExtLen);

/* Mostly internal helper function, but may be useful in working with tackExts */
uint8_t* tackExtPostTacks(uint8_t* tackExt);

#ifdef __cplusplus
}
#endif
#endif
