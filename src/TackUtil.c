/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include "TackUtil.h"

uint16_t ptou16(uint8_t* p)
{
    return ((uint16_t)*(p+0) << 8) |
        (uint16_t)*(p+1); 
}

uint32_t ptou32(uint8_t* p)
{
    return ((uint32_t)*(p+0) << 24) |
        ((uint32_t)*(p+1) << 16) |
        ((uint32_t)*(p+2) << 8) |
        (uint32_t)*(p+3); 
}
