#ifndef __TACK_CHROMIUM_H__
#define __TACK_CHROMIUM_H__

#include <stdint.h>
#include "TackRetval.h"
#include "TackCryptoFuncs.h"
#ifdef __cplusplus
extern "C" {
#endif

TACK_RETVAL tackChromiumVerifyFunc(uint8_t publicKey[TACK_PUBKEY_LENGTH], 
                              uint8_t signature[TACK_SIG_LENGTH],
                              uint8_t* data, uint32_t dataLen);

TACK_RETVAL tackChromiumHashFunc(uint8_t* input, uint32_t inputLen, 
                                uint8_t output[TACK_HASH_LENGTH]);

/* Global crypto funcs structure for convenient parameter passing */
extern TackCryptoFuncs tackChromiumStruct;
extern TackCryptoFuncs* tackChromium;

#ifdef __cplusplus
}
#endif
#endif
