/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_CRYPTO_FUNCS_H__
#define __TACK_CRYPTO_FUNCS_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "TackRetval.h"

#define TACK_HASH_LENGTH 32
#define TACK_SIG_LENGTH 64
#define TACK_PUBKEY_LENGTH 64


typedef TACK_RETVAL (*TackVerifyFunc)(uint8_t publicKey[TACK_PUBKEY_LENGTH], 
                                      uint8_t signature[TACK_SIG_LENGTH],
                                      uint8_t* data, uint32_t dataLen);

typedef TACK_RETVAL (*TackHashFunc)(uint8_t* input, uint32_t inputLen, 
                                    uint8_t output[TACK_HASH_LENGTH]);

#ifdef __cplusplus
}
#endif
#endif
