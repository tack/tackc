/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include "TackOpenSSL.h"

TACK_RETVAL tackOpenSSLVerifyFunc(uint8_t publicKey[TACK_PUBKEY_LENGTH], 
						uint8_t signature[TACK_SIG_LENGTH],
						uint8_t* data, uint32_t dataLen)
{
	uint8_t pubKeyBuf[TACK_PUBKEY_LENGTH + 1];
	uint8_t hashBuf[TACK_HASH_LENGTH];
	EC_KEY* ec_key = 0;
	EC_GROUP* ec_group = 0;
	EC_POINT* ec_point = 0;
	ECDSA_SIG* ecdsa_sig = 0;
	SHA256_CTX sha256_ctx;	
	TACK_RETVAL retval = TACK_ERR_CRYPTO_FUNC;
	int ret = 0;

	/* Prepare the public key to be passed into OpenSSL */
	pubKeyBuf[0] = 0x04;
	memcpy(pubKeyBuf+1, publicKey, TACK_PUBKEY_LENGTH);

	/* Create EC_KEY from raw bytes */
	if ((ec_key = EC_KEY_new_by_curve_name(OBJ_txt2nid("prime256v1"))) == 0)
		goto end;
	if ((ec_group = EC_GROUP_new_by_curve_name(OBJ_txt2nid("prime256v1"))) == 0)
		goto end;
	if ((ec_point = EC_POINT_new(ec_group)) == 0)
		goto end;		
	if (EC_POINT_oct2point(ec_group, ec_point, pubKeyBuf, 65, 0) == 0)
		goto end;
	if (EC_KEY_set_public_key(ec_key, ec_point) == 0)
		goto end;

	/* Create ECDSA_SIG from raw bytes */
	if ((ecdsa_sig = ECDSA_SIG_new()) == 0)
		goto end;		
	if (BN_bin2bn(signature, TACK_SIG_LENGTH/2, ecdsa_sig->r) == 0)
		goto end;
	if (BN_bin2bn(signature + TACK_SIG_LENGTH/2, TACK_SIG_LENGTH/2, ecdsa_sig->s) == 0)
		goto end;
		
	/* Hash the input data */
	SHA256_Init(&sha256_ctx);  
	SHA256_Update(&sha256_ctx, data, dataLen);   
	SHA256_Final(hashBuf, &sha256_ctx);	

	/* Verify the signature */
	ret = ECDSA_do_verify(hashBuf, TACK_HASH_LENGTH, ecdsa_sig, ec_key);
	if (ret == 1)
		retval = TACK_OK_SIGNATURE_GOOD;
	else if (ret == 0)
		retval = TACK_ERR_SIGNATURE_BAD;
	else if (ret == -1)
		retval = TACK_ERR_CRYPTO_FUNC;

end:
	if (ec_key)
		EC_KEY_free(ec_key);
	if (ec_group)
		EC_GROUP_free(ec_group);
	if (ec_point)
		EC_POINT_free(ec_point);
	if (ecdsa_sig)
		ECDSA_SIG_free(ecdsa_sig);

	return(retval);
}
