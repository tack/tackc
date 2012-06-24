#ifndef __TACK_NSS_H__
#define __TACK_NSS_H__

#include <stdint.h>
#include "TackRetval.h"
#include "TackCryptoFuncs.h"
#ifdef __cplusplus
extern "C" {
#endif

TACK_RETVAL tackNssVerifyFunc(uint8_t publicKey[TACK_PUBKEY_LENGTH], 
                              uint8_t signature[TACK_SIG_LENGTH],
                              uint8_t* data, uint32_t dataLen);

#ifdef __cplusplus
}
#endif
#endif
