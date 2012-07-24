/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_TEST_H__
#define __TACK_TEST_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "TackRetval.h"
#include "TackCryptoFuncs.h"

TACK_RETVAL tackTestProcessWellFormed(TackCryptoFuncs* crypto);
TACK_RETVAL tackTestProcessStore(TackCryptoFuncs* crypto);

#ifdef __cplusplus
TACK_RETVAL tackTestStore(TackCryptoFuncs* crypto);
#endif

#ifdef __cplusplus
}
#endif
#endif
