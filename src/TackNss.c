#include <prtypes.h>

#include <sechash.h>
#include <keyhi.h>
#include <pk11pub.h>

#include "TackNss.h"

static const uint8_t SPKI_P256[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                                    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                                    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                                    0x42, 0x00, 0x04};

static SECKEYPublicKey* getPublicKeyFromBytes(uint8_t *publicKeyBytes) {
  uint8_t spkiBytes[TACK_PUBKEY_LENGTH + sizeof(SPKI_P256)];
  memcpy(spkiBytes, SPKI_P256, sizeof(SPKI_P256));
  memcpy(spkiBytes + sizeof(SPKI_P256), publicKeyBytes, TACK_PUBKEY_LENGTH);

  SECItem spkiItem;
  spkiItem.data = spkiBytes;
  spkiItem.len  = sizeof(spkiBytes);

  CERTSubjectPublicKeyInfo *spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&spkiItem);
  SECKEYPublicKey *publicKey     = SECKEY_ExtractPublicKey(spki);

  SECKEY_DestroySubjectPublicKeyInfo(spki);

  return publicKey;  
}

TACK_RETVAL tackNssVerifyFunc(uint8_t publicKeyBytes[TACK_PUBKEY_LENGTH],
                              uint8_t signature[TACK_SIG_LENGTH],
                              uint8_t *data,
                              uint32_t dataLength)
{
  SECItem signatureItem;
  SECItem hashItem;
  uint8_t hashBuffer[TACK_HASH_LENGTH];

  SECKEYPublicKey *publicKey = getPublicKeyFromBytes(publicKeyBytes);
  PK11_HashBuf(SEC_OID_SHA256, hashBuffer, data, dataLength);

  signatureItem.data = signature;
  signatureItem.len  = TACK_SIG_LENGTH;

  hashItem.data      = hashBuffer;
  hashItem.len       = sizeof(hashBuffer);

  uint32_t result = PK11_Verify(publicKey, &signatureItem, &hashItem, NULL);  

  SECKEY_DestroyPublicKey(publicKey);
  
  if (result == SECSuccess) return TACK_OK_SIGNATURE_GOOD;
  else                      return TACK_ERR_SIGNATURE_BAD;
}

TACK_RETVAL tackNssHashFunc(uint8_t* input, uint32_t inputLen, 
                                	uint8_t output[TACK_HASH_LENGTH])
{
	/* Stubbed to return all-zeros hash */
	memset(output, 0, TACK_HASH_LENGTH);
	return TACK_OK;
}

