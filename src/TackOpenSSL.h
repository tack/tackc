/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_OPENSSL_H__
#define __TACK_OPENSSL_H__

#include <stdint.h>
#include "TackRetval.h"
#include "TackCryptoFuncs.h"

TACK_RETVAL tackOpenSSLVerifyFunc(uint8_t publicKey[TACK_PUBKEY_LENGTH], 
						uint8_t signature[TACK_SIG_LENGTH],
						uint8_t* data, uint32_t dataLen);


#endif