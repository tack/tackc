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

uint16_t ptou16(uint8_t* p);
uint32_t ptou32(uint8_t* p);

#ifdef __cplusplus
}
#endif
#endif
