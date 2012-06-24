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

char* tackRetvalString(TACK_RETVAL error);


#define TACK_OK                                 0x00000000
#define TACK_OK_SIGNATURE_GOOD                  0x00000001

#define TACK_ERR                                0x80000000
#define TACK_ERR_BAD_GENERATION                 0x80000001
#define TACK_ERR_BAD_ACTIVATION_FLAG            0x80000002
#define TACK_ERR_BAD_PUBKEY                     0x80000003

#define TACK_ERR_BAD_TACK_LENGTH                0x80001001
#define TACK_ERR_BAD_BREAKSIG_LENGTH            0x80001002
#define TACK_ERR_BAD_BREAKSIGS_LENGTH           0x80001003
#define TACK_ERR_BAD_TACKEXT_LENGTH             0x80001004

#define TACK_ERR_SIGNATURE_BAD                  0x80002001

#define TACK_ERR_CRYPTO_FUNC                    0x80003001


#ifdef __cplusplus
}
#endif
#endif
