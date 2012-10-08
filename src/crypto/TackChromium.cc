#include "TackChromium.h"
#include "crypto/signature_verifier.h"
#include "crypto/sha2.h"

TackCryptoFuncs tackChromiumStruct = {
    tackChromiumVerifyFunc,
    tackChromiumHashFunc
};
TackCryptoFuncs* tackChromium = &tackChromiumStruct;

static const uint8_t ECDSA_SHA256_AlgorithmID[] = {0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 
                                                   0x3d, 0x04, 0x03, 0x02, 0x05, 0x00};

static const uint8_t SPKI_P256[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                                    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                                    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                                    0x42, 0x00, 0x04};

TACK_RETVAL tackChromiumVerifyFunc(uint8_t publicKeyBytes[TACK_PUBKEY_LENGTH],
                              uint8_t signature[TACK_SIG_LENGTH],
                              uint8_t *data,
                              uint32_t dataLength)
{
	/* Convert signature to an ASN.1 SEQUENCE of INTEGERS */
	int rLen=TACK_SIG_LENGTH/2, sLen=TACK_SIG_LENGTH/2;
	for (int count=0; count < TACK_SIG_LENGTH / 2; count++) {
		if (signature[count] == 0) {
			rLen = (TACK_SIG_LENGTH/2) - 1 - count;
			break;
		}
	}
	for (int count=0; count < TACK_SIG_LENGTH / 2; count++) {
		if (signature[(TACK_SIG_LENGTH/2) + count] == 0) {
			sLen = (TACK_SIG_LENGTH/2) - 1 - count;
			break;
		}
	}
	uint8_t sigBytes[TACK_SIG_LENGTH + 6];	
	sigBytes[0] = 0x30; /* SEQUENCE tag */
	sigBytes[1] = 4 + rLen + sLen; /* length (4 = 2 sets of type/length) */
	sigBytes[2] = 0x02; /* INTEGER tag */ 
	sigBytes[3] = rLen; /* length */ 
	memcpy(sigBytes+4, signature + (TACK_SIG_LENGTH/2) - rLen, rLen);
	sigBytes[4+rLen] = 0x02; /* INTEGER tag */
	sigBytes[5+rLen] = sLen; /* length */
	memcpy(sigBytes+6+rLen, signature + TACK_SIG_LENGTH - sLen , sLen);
	int sigBytesLen = 6 + rLen + sLen;

	/* Prepend some ASN.1 gunk to the public key */
	int spkiBytesLen = TACK_PUBKEY_LENGTH + sizeof(SPKI_P256);	
	uint8_t spkiBytes[spkiBytesLen];
	memcpy(spkiBytes, SPKI_P256, sizeof(SPKI_P256));
	memcpy(spkiBytes + sizeof(SPKI_P256), publicKeyBytes, TACK_PUBKEY_LENGTH);
	
	crypto::SignatureVerifier verifier;
	if (!verifier.VerifyInit(ECDSA_SHA256_AlgorithmID, sizeof(ECDSA_SHA256_AlgorithmID),
		sigBytes, sigBytesLen,
		spkiBytes, spkiBytesLen))
		return TACK_ERR_CRYPTO_FUNC;

	verifier.VerifyUpdate(data, dataLength);
	
	if (verifier.VerifyFinal())
		return TACK_OK;
	else
		return TACK_ERR_BAD_SIGNATURE;
}

TACK_RETVAL tackChromiumHashFunc(uint8_t* input, uint32_t inputLen, 
                            uint8_t output[TACK_HASH_LENGTH])
{
	std::string str((char*)input, inputLen);
	crypto::SHA256HashString(str, output, TACK_HASH_LENGTH);	
	return TACK_OK;
}

