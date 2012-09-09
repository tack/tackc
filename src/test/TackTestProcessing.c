/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "TackProcessing.h"
#include "TackExtension.h"
#include "Tack.h"
#include "TackUtil.h"
#include "TackPinList.h"
#include "TackTest.h"


char ET1pem[] = "\
-----BEGIN TACK EXTENSION-----\
AKYmSlxQLWzgRMLJQWi6Ol+OkJmhrhDnZ1wqarwuhJLmQV09qt3UGUYvBogGKQLI\
/ziQ2AVWhKph6KurwrANInQHAAAByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYfMMSPSsvUElDb/G6akJ48jLLAtAHwP3Pf9fyTs/yMi0ojZMTLXbTVb\
l0wdyKnsLnOv3yR8qOXD9QYbbLzop0LNAA==\
-----END TACK EXTENSION-----";

/*
key fingerprint = gv6qp.hmd4y.tsjxo.wcakm.sotjm
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = 0
 */

char ET1mpem[] = "\
-----BEGIN TACK EXTENSION-----\
AKYmSlxQLWzgRMLJQWi6Ol+OkJmhrhDnZ1wqarwuhJLmQV09qt3UGUYvBogGKQLI\
/ziQ2AVWhKph6KurwrANInQHAQEByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYde9WR8Tncu7pMoOHDOtysqJ8FuuNAT8dEcLcquRxu0o41r5MygnsxH\
ZiO3FlW0Qjw8y9ABo7wViNpx5rOevIZWAA==\
-----END TACK EXTENSION-----\
";
/*
key fingerprint = gv6qp.hmd4y.tsjxo.wcakm.sotjm
min_generation  = 1
generation      = 1
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
*/

char ET2pem[] = "\
-----BEGIN TACK EXTENSION-----\
AKa9pBxgjx6GyZorFfwRrfEjYdh/B6iLoE+kzTSX11U/HQRM1FOQYVw0ZptDfcyX\
W9oQjhDZQSYm9CNDSoFqKDqcZP4ByR7zMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYflR5CmjDponB6KRhGro008Duvb2iTxoZW52nlIHujlVrxUY/KwWOtw\
WBlKfHkrbbIAqWFapNsM23585P5ms8z6AA==\
-----END TACK EXTENSION-----\
";
/*
key fingerprint = w6v4n.wofh4.cqtjq.adcxi.teugp
min_generation  = 100
generation      = 254
expiration      = 2026-12-17T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = 0
*/


char ET2mpem[] = "\
-----BEGIN TACK EXTENSION-----\
AKa9pBxgjx6GyZorFfwRrfEjYdh/B6iLoE+kzTSX11U/HQRM1FOQYVw0ZptDfcyX\
W9oQjhDZQSYm9CNDSoFqKDqc/v8ByR7zMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYeQ9pdb13GiJmNZ05pylEaCG2rHlPSVKSqUqnLY6FNdq2fXC7yl6qIF\
c0KY1SYP0IS/QsWXlA//IvjpIIlfZyOXAA==\
-----END TACK EXTENSION-----\
";
/*
key fingerprint = w6v4n.wofh4.cqtjq.adcxi.teugp
min_generation  = 254
generation      = 255
expiration      = 2026-12-17T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = 0
*/

char ET1T2pem[] = "\
-----BEGIN TACK EXTENSION-----\
AUwmSlxQLWzgRMLJQWi6Ol+OkJmhrhDnZ1wqarwuhJLmQV09qt3UGUYvBogGKQLI\
/ziQ2AVWhKph6KurwrANInQHAAAByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYfMMSPSsvUElDb/G6akJ48jLLAtAHwP3Pf9fyTs/yMi0ojZMTLXbTVb\
l0wdyKnsLnOv3yR8qOXD9QYbbLzop0LNvaQcYI8ehsmaKxX8Ea3xI2HYfweoi6BP\
pM00l9dVPx0ETNRTkGFcNGabQ33Ml1vaEI4Q2UEmJvQjQ0qBaig6nGT+Acke8zK2\
S2ZyeiBj5AZvO5WMsKruV2pezv2VM5m7iHRzHZWH5UeQpow6aJweikYRq6NNPA7r\
29ok8aGVudp5SB7o5Va8VGPysFjrcFgZSnx5K22yAKlhWqTbDNt+fOT+ZrPM+gA=\
-----END TACK EXTENSION-----\
";
/*
key fingerprint = gv6qp.hmd4y.tsjxo.wcakm.sotjm
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
key fingerprint = w6v4n.wofh4.cqtjq.adcxi.teugp
min_generation  = 100
generation      = 254
expiration      = 2026-12-17T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = 0
*/

char ET2mT1mpem[] = "\
-----BEGIN TACK EXTENSION-----\
AUy9pBxgjx6GyZorFfwRrfEjYdh/B6iLoE+kzTSX11U/HQRM1FOQYVw0ZptDfcyX\
W9oQjhDZQSYm9CNDSoFqKDqc/v8ByR7zMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYeQ9pdb13GiJmNZ05pylEaCG2rHlPSVKSqUqnLY6FNdq2fXC7yl6qIF\
c0KY1SYP0IS/QsWXlA//IvjpIIlfZyOXJkpcUC1s4ETCyUFoujpfjpCZoa4Q52dc\
Kmq8LoSS5kFdPard1BlGLwaIBikCyP84kNgFVoSqYeirq8KwDSJ0BwEBAckZUzK2\
S2ZyeiBj5AZvO5WMsKruV2pezv2VM5m7iHRzHZWHXvVkfE53Lu6TKDhwzrcrKifB\
brjQE/HRHC3KrkcbtKONa+TMoJ7MR2YjtxZVtEI8PMvQAaO8FYjaceaznryGVgA=\
-----END TACK EXTENSION-----\
";
/*
key fingerprint = w6v4n.wofh4.cqtjq.adcxi.teugp
min_generation  = 254
generation      = 255
expiration      = 2026-12-17T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
key fingerprint = gv6qp.hmd4y.tsjxo.wcakm.sotjm
min_generation  = 1
generation      = 1
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = 01
*/


char ET1T1mpem[] = "\
-----BEGIN TACK EXTENSION-----\
AUwmSlxQLWzgRMLJQWi6Ol+OkJmhrhDnZ1wqarwuhJLmQV09qt3UGUYvBogGKQLI\
/ziQ2AVWhKph6KurwrANInQHAAAByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYfMMSPSsvUElDb/G6akJ48jLLAtAHwP3Pf9fyTs/yMi0ojZMTLXbTVb\
l0wdyKnsLnOv3yR8qOXD9QYbbLzop0LNJkpcUC1s4ETCyUFoujpfjpCZoa4Q52dc\
Kmq8LoSS5kFdPard1BlGLwaIBikCyP84kNgFVoSqYeirq8KwDSJ0BwEBAckZUzK2\
S2ZyeiBj5AZvO5WMsKruV2pezv2VM5m7iHRzHZWHXvVkfE53Lu6TKDhwzrcrKifB\
brjQE/HRHC3KrkcbtKONa+TMoJ7MR2YjtxZVtEI8PMvQAaO8FYjaceaznryGVgA=\
-----END TACK EXTENSION-----\
";
/*
key fingerprint = gv6qp.hmd4y.tsjxo.wcakm.sotjm
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
key fingerprint = gv6qp.hmd4y.tsjxo.wcakm.sotjm
min_generation  = 1
generation      = 1
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = 0
*/


uint8_t tackExtET1[2048];
uint32_t tackExtET1Len;

uint8_t tackExtET1m[2048];
uint32_t tackExtET1mLen;

uint8_t tackExtET2[2048];
uint32_t tackExtET2Len;

uint8_t tackExtET2m[2048];
uint32_t tackExtET2mLen;

uint8_t tackExtET1T2[2048];
uint32_t tackExtET1T2Len;

uint8_t tackExtET2mT1m[2048];
uint32_t tackExtET2mT1mLen;

uint8_t tackExtET1T1m[2048];
uint32_t tackExtET1T1mLen;

#include <stdio.h>

TACK_RETVAL tackTestProcessInit()
{
    TACK_RETVAL retval;

    char label[] ="TACK EXTENSION";

    retval=tackDePem(label, (uint8_t*)ET1pem, strlen(ET1pem), tackExtET1, &tackExtET1Len);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, (uint8_t*)ET1mpem, strlen(ET1mpem), tackExtET1m, &tackExtET1mLen);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, (uint8_t*)ET2pem, strlen(ET2pem), tackExtET2, &tackExtET2Len);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, (uint8_t*)ET2mpem, strlen(ET2mpem), tackExtET2m, &tackExtET2mLen);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, (uint8_t*)ET1T2pem, strlen(ET1T2pem), tackExtET1T2, &tackExtET1T2Len);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, (uint8_t*)ET2mT1mpem, strlen(ET2mT1mpem), tackExtET2mT1m, &tackExtET2mT1mLen);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, (uint8_t*)ET1T1mpem, strlen(ET1T1mpem), tackExtET1T1m, &tackExtET1T1mLen);
    if (retval != TACK_OK)
        return retval;

    return retval;
}

#define TCHECK(x) \
    assert(x == TACK_OK)

#define TCHECK_VAL(x,y) \
    assert(x == y)


TACK_RETVAL tackTestProcessWellFormed(TackCryptoFuncs* crypto) {
    
    TackProcessingContext ctx;
    uint8_t* keyHash;
    uint8_t* tack;
    uint32_t count=0;
    uint32_t expirationTime;

    TCHECK(tackTestProcessInit());

    tack = tackExtensionGetTack(tackExtET1, 0);
    keyHash = tackTackGetTargetHash(tack);

    /* Test with NULL input */
    TCHECK(tackProcessWellFormed(&ctx, NULL, 169, keyHash, 123, crypto));
    assert(ctx.tackExt == NULL);
    assert(ctx.tack[0] == NULL);
    assert(ctx.tack[1] == NULL);
    assert(strlen(ctx.tackFingerprint[0]) == 0);
    assert(strlen(ctx.tackFingerprint[1]) == 0);

    /* Test normal behavior (ET1, ET1T2) */
    TCHECK(tackProcessWellFormed(&ctx, 
               tackExtET1, tackExtET1Len, keyHash, 123, crypto));
    assert(ctx.tackExt == tackExtET1);
    assert(ctx.tack[0] == tackExtensionGetTack(tackExtET1, 0));
    assert(ctx.tack[1] == NULL);

    TCHECK(tackProcessWellFormed(&ctx, 
               tackExtET1T2, tackExtET1T2Len, keyHash, 123, crypto));
    assert(ctx.tackExt == tackExtET1T2);
    assert(ctx.tack[0] == tackExtensionGetTack(tackExtET1T2, 0));
    assert(ctx.tack[1] == tackExtensionGetTack(tackExtET1T2, 1));

    /* Test tack ext lengths (ET1, ET1T2) */
    /* Test that errors are returned for a range of bad lengths */
    for (count=0; count < tackExtET1Len+100; count++) {
        if (count == tackExtET1Len) continue;
        TCHECK_VAL(tackProcessWellFormed(&ctx, tackExtET1, count, keyHash, 123, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    for (count=tackExtET1T2Len-100; count < tackExtET1T2Len+100; count++) {
        if (count == tackExtET1T2Len) continue;
        TCHECK_VAL(tackProcessWellFormed(&ctx, tackExtET1T2, count, keyHash, 123, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    /* Test bad tacklength */
    *tackExtET1 += 1;
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 123, crypto),
               TACK_ERR_BAD_TACKS_LENGTH);
    *tackExtET1 -= 1;
    
    /* Test setting other activation flag bits */
    tackExtET1[tackExtET1Len-1]=3; /* 0->3 */
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 123, crypto),
               TACK_OK);
    tackExtET1[tackExtET1Len-1]=4; /* ->4 */
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 123, crypto),
               TACK_ERR_BAD_ACTIVATION_FLAGS);
    tackExtET1[tackExtET1Len-1]=255; /* ->255 */
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 123, crypto),
               TACK_ERR_BAD_ACTIVATION_FLAGS);
    tackExtET1[tackExtET1Len-1] = 0;

    /* Test bad generation (mingeneration > generation) */
    tackExtET1[66]++;
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 123, crypto),
               TACK_ERR_BAD_GENERATION);
    tackExtET1[66]--;

    /* Test good/bad expiration */
    tack = tackExtensionGetTack(tackExtET1, 0);
    expirationTime = tackTackGetExpiration(tack);

    TCHECK(tackProcessWellFormed(&ctx, 
               tackExtET1, tackExtET1Len, keyHash, expirationTime-1, crypto));
    
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, expirationTime, crypto),
               TACK_ERR_EXPIRED_EXPIRATION);
    
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, expirationTime+1, crypto),
               TACK_ERR_EXPIRED_EXPIRATION);
    
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 0xFFFFFFFF, crypto),
               TACK_ERR_EXPIRED_EXPIRATION);

    /* Test bad targetHash */
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash+1, 123, crypto),
               TACK_ERR_MISMATCHED_TARGET_HASH);

    /* Test bad signature */
    tackExtET1[160]++;
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 123, crypto),
        TACK_ERR_BAD_SIGNATURE);
    tackExtET1[160]--;

    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1T1m, tackExtET1T1mLen, keyHash, 123, crypto),
               TACK_ERR_EQUAL_TACK_KEYS);

    return TACK_OK;
}

#ifdef __cplusplus

#include "TackStoreDefault.h"

static void setActivationFlag(uint8_t* tackExt, uint8_t activationFlag)
{
    *tackExtensionPostTacks(tackExt) = activationFlag;
}

TACK_RETVAL tackTestStore(TackCryptoFuncs* crypto)
{
    TackProcessingContext ctxET1, ctxET1m, ctxET2, ctxET2m, ctxET1T2, ctxET2mT1m;

    uint8_t* keyHash;
    uint8_t* tack;
    uint32_t currentTime = 1000;
    TackStoreDefault store;

    TCHECK(tackTestProcessInit());

    tack = tackExtensionGetTack(tackExtET1, 0);
    keyHash = tackTackGetTargetHash(tack);

    /* Prepare contexts*/
    TCHECK(tackProcessWellFormed(&ctxET1, 
               tackExtET1, tackExtET1Len, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxET1m, 
               tackExtET1m, tackExtET1mLen, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxET2, 
               tackExtET2, tackExtET2Len, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxET2m, 
               tackExtET2m, tackExtET2mLen, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxET1T2, 
               tackExtET1T2, tackExtET1T2Len, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxET2mT1m, 
               tackExtET2mT1m, tackExtET2mT1mLen, keyHash, currentTime, crypto));


    store.setCryptoFuncs(crypto);
    store.setPinActivation(true);
    store.setDirtyFlagEnabled(true);

    /* Test dirty flag does not get set by inactive tack */
    store.setDirtyFlag(false);
    setActivationFlag(tackExtET1, 0);

    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime), TACK_OK_UNPINNED);
    assert(store.getDirtyFlag() == false);

    setActivationFlag(tackExtET1, 1);

    /* Test dirty flag does get set by active tacks */
    store.setDirtyFlag(false);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime), TACK_OK_UNPINNED);
    assert(store.getDirtyFlag() == true);

    /* Test pin activation logic on a sequence of times */
    store.setDirtyFlag(false);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+10), TACK_OK_UNPINNED);
    assert(store.getDirtyFlag() == true);

    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+18), TACK_OK_ACCEPTED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+100), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+199), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+396), TACK_OK_ACCEPTED);

    /* Test that activation time is not extended if off for the store */
    store.setPinActivation(false);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+1000), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+1001), TACK_OK_UNPINNED);
    store.setPinActivation(true);

    /* Test pin activation logic for a second pin */
    setActivationFlag(tackExtET2, 1);
    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime+10), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime+10), TACK_OK_ACCEPTED);

    /* Test that the first pin rejects the second tack, with/without pin-activ. store */
    store.setDirtyFlag(false);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime), TACK_OK_REJECTED);
    assert(store.getDirtyFlag() == false);

    store.setPinActivation(false);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime), TACK_OK_REJECTED);
    store.setPinActivation(true);

    /* Test that the second tack can supercede the first pin */
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime+1000), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime+2000), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+2001), TACK_OK_REJECTED);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime+2001), TACK_OK_ACCEPTED);
    store.setPinActivation(false);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime+2001), TACK_OK_ACCEPTED);
    store.setPinActivation(true);

    /* Test that the second pin is still working */
    store.setPinActivation(false);
    store.setDirtyFlag(false);
    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime+11), TACK_OK_ACCEPTED);
    assert(store.getDirtyFlag() == false);

    /* TODO test some contradicting pins */

    /* TODO test some pairs of pins */

    /* Prepare for mingen testing */
    store.clear();
    store.setPinActivation(true);
    uint8_t minGen;

    /* Simple mingen test, updating 2 keys */
    TCHECK_VAL(store.process(&ctxET1, "a.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "b.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1m, "c.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2m, "d.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "X.com", currentTime), TACK_ERR_REVOKED_GENERATION);
    TCHECK_VAL(store.process(&ctxET2, "X.com", currentTime), TACK_OK_UNPINNED);

    store.getMinGeneration("gv6qp.hmd4y.tsjxo.wcakm.sotjm", &minGen);
    assert(minGen == 1);
    store.getMinGeneration("w6v4n.wofh4.cqtjq.adcxi.teugp", &minGen);
    assert(minGen == 254);

    /* Another mingen test, checking that pin-act store is not required, and
     doing 2 updates in a single extension */
    store.clear();
    TCHECK_VAL(store.process(&ctxET1, "a.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "b.com", currentTime), TACK_OK_UNPINNED);
    store.setPinActivation(false);
    TCHECK_VAL(store.process(&ctxET2mT1m, "c.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "a.com", currentTime), TACK_ERR_REVOKED_GENERATION);
    TCHECK_VAL(store.process(&ctxET2, "b.com", currentTime), TACK_OK_UNPINNED);

    store.getMinGeneration("gv6qp.hmd4y.tsjxo.wcakm.sotjm", &minGen);
    assert(minGen == 1);
    store.getMinGeneration("w6v4n.wofh4.cqtjq.adcxi.teugp", &minGen);
    assert(minGen == 254);

    /* Check serialization */
    store.clear();
    store.setPinActivation(true);
    setActivationFlag(tackExtET1, 1);
    setActivationFlag(tackExtET2, 1);
    setActivationFlag(tackExtET1T2, 3);
    setActivationFlag(tackExtET2mT1m, 3);

    TCHECK_VAL(store.process(&ctxET1, "c.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "b.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2mT1m, "a.com", currentTime), TACK_OK_UNPINNED);


    // Check that serialize -> deserialize -> serialize yields same string
    TACK_RETVAL retval;
    char outTest[1024];
    uint32_t outLen = 1024;
    if ((retval = store.serialize(outTest, &outLen)) != TACK_OK)
        return retval;
    //printf("%s", outTest);

    TackStoreDefault store2;
    if ((retval = store2.deserialize(outTest, &outLen)) != TACK_OK)
        return retval;

    char outTest2[1024];
    uint32_t outLen2 = 1024;
    outLen2 = 1024;
    if ((retval = store2.serialize(outTest2, &outLen2)) != TACK_OK)
        return retval;

    //printf("%s", outTest2);
    assert(strcmp(outTest, outTest2) == 0);

    // Check that the largest minGen was deserialized
    store.getMinGeneration("w6v4n.wofh4.cqtjq.adcxi.teugp", &minGen);
    assert(minGen == 254);

    return TACK_OK;
}

#endif

