/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_UTIL_H__
#define __TACK_UTIL_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"

uint16_t ptou16(uint8_t* p);
uint32_t ptou32(uint8_t* p);

TACK_RETVAL tackBase64Decode(uint8_t* in, uint32_t inLen,
                             uint8_t* out, uint32_t* outLen);

TACK_RETVAL tackDePem(char* label, uint8_t* in, uint32_t inLen, 
                      uint8_t* out, uint32_t* outLen);

#ifdef __cplusplus
}
#endif
#endif
