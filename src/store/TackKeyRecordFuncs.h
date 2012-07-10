/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_KEYRECORD_FUNCS_H__
#define __TACK_KEYRECORD_FUNCS_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"


typedef TACK_RETVAL (*TackGetKeyRecordFunc)(void* krArg, char* keyFingerprint, 
                                            uint8_t* minGeneration);

typedef TACK_RETVAL (*TackUpdateKeyRecordFunc)(void* krArg, char* keyFingerprint, 
                                               uint8_t minGeneration);

typedef TACK_RETVAL (*TackDeleteKeyRecordFunc)(void* krArg, char* keyFingerprint);


#ifdef __cplusplus
}
#endif
#endif
