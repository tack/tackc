/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_PIN_LIST_H__
#define __TACK_PIN_LIST_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"
#include "TackStoreFuncs.h"


TACK_RETVAL tackPinListWriteEntry(char* list, uint32_t* listLen, 
                                  const char* name, TackPin* pin, 
                                  uint8_t minGeneration);

TACK_RETVAL tackPinListParseEntry(const char* list, uint32_t* listLen, 
                                  char* name, TackPin* pin, 
                                  uint8_t* minGeneration);

#ifdef __cplusplus
}
#endif
#endif
