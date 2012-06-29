/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_RETVAL_H__
#define __TACK_RETVAL_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef int32_t TACK_RETVAL;

const char* tackRetvalString(TACK_RETVAL error);


#define TACK_OK                                 0x00000000
#define TACK_OK_SIGNATURE_GOOD                  0x00000001

#define TACK_ERR                                -0x00000001
#define TACK_ERR_BAD_GENERATION                 -0x00000002
#define TACK_ERR_BAD_ACTIVATION_FLAG            -0x00000003
#define TACK_ERR_BAD_PUBKEY                     -0x00000004

#define TACK_ERR_BAD_TACK_LENGTH                -0x00001001
#define TACK_ERR_BAD_BREAKSIGS_LENGTH           -0x00001002
#define TACK_ERR_BAD_TACKEXT_LENGTH             -0x00001003

#define TACK_ERR_SIGNATURE_BAD                  -0x00002001

#define TACK_ERR_CRYPTO_FUNC                    -0x00003001

#define TACK_ERR_ASSERTION                      -0x00004001

#define TACK_ERR_NOT_FOUND                      -0x00005001

#ifdef __cplusplus
}
#endif
#endif
