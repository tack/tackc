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


char Epem[] = "\
-----BEGIN TACK EXTENSION-----\
AAAAAAE=\
-----END TACK EXTENSION-----";
/*
activation_flag = enabled
 */

char ET1pem[] = "\
-----BEGIN TACK EXTENSION-----\
AKbRPZvVlyhVTrl58hQ+n8JbkxNYOS21nmcu/FA5QwFHmw/WXbAtI7TzTt3DVqaG\
KC9DLdEjj5BNi6TMDiqP2osnAAAByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYfVaCzrqEiJRCibqMlGZupEEupuqM8BErj0yH6e2RrH7Xz0Di7x8UFt\
13MY5KC7nPtFa9bw1FU5gmjTPF3n4ySPAAAB\
-----END TACK EXTENSION-----";
/*
key fingerprint = 2jgim.5jn33.3gc6r.he4gi.3mope
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = first_active
 */

char EB1pem[] = "\
-----BEGIN TACK EXTENSION-----\
AAAAgNE9m9WXKFVOuXnyFD6fwluTE1g5LbWeZy78UDlDAUebD9ZdsC0jtPNO3cNW\
poYoL0Mt0SOPkE2LpMwOKo/aiyda/tMjsxDveK8d4bL1gz7VG0c+VzbqoO95Lvw1\
hxVua2qVuZVbna4XqrsKFiHm2SV0OSynXp+z0ufSNDE0GIYRAQ==\
-----END TACK EXTENSION-----";
/*
Breaks key fingerprint  = 2jgim.5jn33.3gc6r.he4gi.3mope
activation_flags = first_active
 */

char EB1T2pem[] = "\
-----BEGIN TACK EXTENSION-----\
AKYP/OQDx82nI/uQ5UeNf3p7cQtbEHtuP/yG6MMFzeaBoLhoYfD+7q05srz+Gujq\
bPYN4ImuAUIlXTMAtfNVqq9aAAAByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYcmRIue/F9nBusdnGNg+eudJUJDMuUYPLnC9oEzbWrKbecXiH/5WyX7\
PxJfpzodEtSnxRFQyp6t/tSeRbvef8K4AIDRPZvVlyhVTrl58hQ+n8JbkxNYOS21\
nmcu/FA5QwFHmw/WXbAtI7TzTt3DVqaGKC9DLdEjj5BNi6TMDiqP2osnWv7TI7MQ\
73ivHeGy9YM+1RtHPlc26qDveS78NYcVbmtqlbmVW52uF6q7ChYh5tkldDksp16f\
s9Ln0jQxNBiGEQE=\
-----END TACK EXTENSION-----";
/*
key fingerprint = ha2gz.wki3m.jwvrz.mazmj.h6c2a
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
Breaks key fingerprint  = 2jgim.5jn33.3gc6r.he4gi.3mope
activation_flags = first_active
 */

char EBmaxT2pem[] = "\
-----BEGIN TACK EXTENSION-----\
AKYP/OQDx82nI/uQ5UeNf3p7cQtbEHtuP/yG6MMFzeaBoLhoYfD+7q05srz+Gujq\
bPYN4ImuAUIlXTMAtfNVqq9aAAAByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYcmRIue/F9nBusdnGNg+eudJUJDMuUYPLnC9oEzbWrKbecXiH/5WyX7\
PxJfpzodEtSnxRFQyp6t/tSeRbvef8K4BADRPZvVlyhVTrl58hQ+n8JbkxNYOS21\
nmcu/FA5QwFHmw/WXbAtI7TzTt3DVqaGKC9DLdEjj5BNi6TMDiqP2osnWv7TI7MQ\
73ivHeGy9YM+1RtHPlc26qDveS78NYcVbmtqlbmVW52uF6q7ChYh5tkldDksp16f\
s9Ln0jQxNBiGEbQyq4ralFoFhBW403SE8xajczDTrl6C1XdDVEtEZfMG+guPLIFZ\
jTYDBdYlWb+cYadgzV0YmDxK8EdId/uJCBRRvfHTqGBG16nFi91rG6EMajO6SdpN\
KkGRkW7TpjNH54fLI6YWSYcFMuMQHlC8NNAcR71ibvceU+hf+PMJe7DKbAsVLjzf\
Ip5jB9TKooRxbAzOPYI2zYWUJDBEkpMABpMXDjMB5NGBbqdMYKxVe9Yck47/oBWK\
gE0291rx6c9NNCki6Qa0az1TVB6CzPAgU3NcwKSDW9x5obyCFhEmgwYS6R1+Y+8z\
UA2RnINr7+8gsnIps38keWMkTWbCG5s1r63RPZvVlyhVTrl58hQ+n8JbkxNYOS21\
nmcu/FA5QwFHmw/WXbAtI7TzTt3DVqaGKC9DLdEjj5BNi6TMDiqP2osnWv7TI7MQ\
73ivHeGy9YM+1RtHPlc26qDveS78NYcVbmtqlbmVW52uF6q7ChYh5tkldDksp16f\
s9Ln0jQxNBiGEbQyq4ralFoFhBW403SE8xajczDTrl6C1XdDVEtEZfMG+guPLIFZ\
jTYDBdYlWb+cYadgzV0YmDxK8EdId/uJCBRRvfHTqGBG16nFi91rG6EMajO6SdpN\
KkGRkW7TpjNH54fLI6YWSYcFMuMQHlC8NNAcR71ibvceU+hf+PMJe7DKbAsVLjzf\
Ip5jB9TKooRxbAzOPYI2zYWUJDBEkpMABpMXDjMB5NGBbqdMYKxVe9Yck47/oBWK\
gE0291rx6c9NNCki6Qa0az1TVB6CzPAgU3NcwKSDW9x5obyCFhEmgwYS6R1+Y+8z\
UA2RnINr7+8gsnIps38keWMkTWbCG5s1r63RPZvVlyhVTrl58hQ+n8JbkxNYOS21\
nmcu/FA5QwFHmw/WXbAtI7TzTt3DVqaGKC9DLdEjj5BNi6TMDiqP2osnWv7TI7MQ\
73ivHeGy9YM+1RtHPlc26qDveS78NYcVbmtqlbmVW52uF6q7ChYh5tkldDksp16f\
s9Ln0jQxNBiGEbQyq4ralFoFhBW403SE8xajczDTrl6C1XdDVEtEZfMG+guPLIFZ\
jTYDBdYlWb+cYadgzV0YmDxK8EdId/uJCBRRvfHTqGBG16nFi91rG6EMajO6SdpN\
KkGRkW7TpjNH54fLI6YWSYcFMuMQHlC8NNAcR71ibvceU+hf+PMJe7DKAQ==\
-----END TACK EXTENSION-----";
/*
key fingerprint = ha2gz.wki3m.jwvrz.mazmj.h6c2a
min_generation  = 0
generation      = 0
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
Breaks key fingerprint  = 2jgim.5jn33.3gc6r.he4gi.3mope
Breaks key fingerprint  = kmpvg.b723d.6aggr.da3tg.gsfur
Breaks key fingerprint  = i3ix6.7g6fs.zbzvm.emvs8.jdn3o
Breaks key fingerprint  = 2jgim.5jn33.3gc6r.he4gi.3mope
Breaks key fingerprint  = kmpvg.b723d.6aggr.da3tg.gsfur
Breaks key fingerprint  = i3ix6.7g6fs.zbzvm.emvs8.jdn3o
Breaks key fingerprint  = 2jgim.5jn33.3gc6r.he4gi.3mope
Breaks key fingerprint  = kmpvg.b723d.6aggr.da3tg.gsfur
activation_flags = first_active
*/

char ET1Mpem[] = "\
-----BEGIN TACK EXTENSION-----\
AKbRPZvVlyhVTrl58hQ+n8JbkxNYOS21nmcu/FA5QwFHmw/WXbAtI7TzTt3DVqaG\
KC9DLdEjj5BNi6TMDiqP2osn/v8ByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYffhjg/WkdSX7fvRdP4xNl1XDwY1L98zvuLPMGE5FDWSgAdaf5247xs\
jReyKKZNySSpuoGOdol7AUlYyNhVvq2KAAAB\
-----END TACK EXTENSION-----";
/*
key fingerprint = 2jgim.5jn33.3gc6r.he4gi.3mope
min_generation  = 254
generation      = 255
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = first_active
*/

char ET2pem[] = "\
-----BEGIN TACK EXTENSION-----\
AKYP/OQDx82nI/uQ5UeNf3p7cQtbEHtuP/yG6MMFzeaBoLhoYfD+7q05srz+Gujq\
bPYN4ImuAUIlXTMAtfNVqq9aAQEByRlTMrZLZnJ6IGPkBm87lYywqu5Xal7O/ZUz\
mbuIdHMdlYfR21FTnmACJ4zyZi2JLW9GbflwLRhQesPbHXD5CcLqCXb/ad5o+o3q\
A6XEJzHNKkrq/iIL+U3bA7AENOlelY8hAAAB\
-----END TACK EXTENSION-----";
/*
key fingerprint = ha2gz.wki3m.jwvrz.mazmj.h6c2a
min_generation  = 1
generation      = 1
expiration      = 2026-12-16T01:55Z
target_hash     = 32b64b66727a2063e4066f3b958cb0aa
                  ee576a5ecefd953399bb8874731d9587
activation_flags = first_active
*/

uint8_t tackExtE[2048];
uint32_t tackExtELen;

uint8_t tackExtET1[2048];
uint32_t tackExtET1Len;

uint8_t tackExtEB1[2048];
uint32_t tackExtEB1Len;

uint8_t tackExtEB1T2[2048];
uint32_t tackExtEB1T2Len;

uint8_t tackExtEBmaxT2[2048]; /* like EB1, but w/more extraneous break sigs*/
uint32_t tackExtEBmaxT2Len;

uint8_t tackExtET1M[2048]; /* like ET1, but w/mingen=254,gen=255*/
uint32_t tackExtET1MLen;

uint8_t tackExtET2[2048];
uint32_t tackExtET2Len;


TACK_RETVAL tackTestProcessInit()
{
    TACK_RETVAL retval;

    char label[] ="TACK EXTENSION";
    retval=tackDePem(label, 
                     (uint8_t*)Epem, strlen(Epem), tackExtE, &tackExtELen);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, 
                     (uint8_t*)ET1pem, strlen(ET1pem), tackExtET1, &tackExtET1Len);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, 
                     (uint8_t*)EB1pem, strlen(EB1pem), tackExtEB1, &tackExtEB1Len);
    if (retval != TACK_OK)
        return retval;

    retval=tackDePem(label, 
                     (uint8_t*)EB1T2pem, strlen(EB1T2pem), tackExtEB1T2, &tackExtEB1T2Len);

    retval=tackDePem(label, 
                     (uint8_t*)EBmaxT2pem, strlen(EBmaxT2pem), 
                     tackExtEBmaxT2, &tackExtEBmaxT2Len);

    retval=tackDePem(label, 
                     (uint8_t*)ET1Mpem, strlen(ET1Mpem), 
                     tackExtET1M, &tackExtET1MLen);

    retval=tackDePem(label, 
                     (uint8_t*)ET2pem, strlen(ET2pem), 
                     tackExtET2, &tackExtET2Len);

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
    TCHECK(tackProcessWellFormed(&ctx, NULL, 170, keyHash, 123, crypto));
    assert(ctx.tackExt == NULL);
    assert(ctx.tack[0] == NULL);
    assert(strlen(ctx.tackFingerprint[0]) == 0);
    assert(ctx.breakSigFlags == 0);

    /* Test normal behavior */
    TCHECK(tackProcessWellFormed(&ctx, 
               tackExtET1, tackExtET1Len, keyHash, 123, crypto));
    assert(ctx.tackExt == tackExtET1);
    assert(ctx.tack[0] == tackExtensionGetTack(tackExtET1, 0));
    assert(ctx.breakSigFlags == 0);

    /* Test tack ext lengths (copied code for E, ET1, EB1, EB1T2 */
    /* Test that errors are returned for a range of bad lengths */
    TCHECK(tackProcessWellFormed(&ctx, tackExtE, tackExtELen, keyHash, 123, crypto));
    for (count=0; count < tackExtELen+10; count++) {
        if (count == tackExtELen) continue;
        TCHECK_VAL(tackProcessWellFormed(&ctx, tackExtE, count, keyHash, 123, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    TCHECK(tackProcessWellFormed(&ctx, tackExtET1, tackExtET1Len, keyHash, 123, crypto));
    for (count=0; count < tackExtET1Len+10; count++) {
        if (count == tackExtET1Len) continue;
        TCHECK_VAL(tackProcessWellFormed(&ctx, tackExtET1, count, keyHash, 123, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    TCHECK(tackProcessWellFormed(&ctx, tackExtEB1, tackExtEB1Len, keyHash, 123, 
                                 crypto));
    for (count=0; count < tackExtEB1Len+10; count++) {
        if (count == tackExtEB1Len) continue;
        TCHECK_VAL(tackProcessWellFormed(&ctx, tackExtEB1, count, keyHash, 123, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    TCHECK(tackProcessWellFormed(&ctx, tackExtEB1T2, tackExtEB1T2Len, keyHash, 123, 
                                 crypto));
    for (count=0; count < tackExtEB1T2Len+10; count++) {
        if (count == tackExtEB1T2Len) continue;
        TCHECK_VAL(tackProcessWellFormed(&ctx, tackExtEB1T2, count, keyHash, 123, crypto),
                   TACK_ERR_BAD_TACKEXT_LENGTH);
    }

    /* Test bad tacklength */
    *tackExtET1 += 1;
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 123, crypto),
               TACK_ERR_BAD_TACK_LENGTH);
    *tackExtET1 -= 1;
    
    /* Test bad breaksigs length */
    /* Modify the low-order byte of the 2-byte length to be non-multiple of 128 */
    tackExtEB1T2[3+TACK_LENGTH]++;
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtEB1T2, tackExtEB1T2Len, keyHash, 123, crypto),
               TACK_ERR_BAD_BREAKSIGS_LENGTH);
    tackExtEB1T2[3+TACK_LENGTH]--;
    /* Modify the high-order byte of the 2-byte length to be 4 (=9 break sigs)  */
    tackExtEB1T2[2+TACK_LENGTH]=4;
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtEB1T2, tackExtEB1T2Len, keyHash, 123, crypto),
               TACK_ERR_BAD_BREAKSIGS_LENGTH);
    tackExtEB1T2[2+TACK_LENGTH]=0;

    /* Test bad activation flag */
    tackExtET1[tackExtET1Len-1]+=3; /* 1->4 */
    TCHECK_VAL(tackProcessWellFormed(&ctx, 
                   tackExtET1, tackExtET1Len, keyHash, 123, crypto),
               TACK_ERR_BAD_ACTIVATION_FLAG);
    tackExtET1[tackExtET1Len-1]-=3;

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

    return TACK_OK;
}

#ifdef __cplusplus

#include "TackStoreDefault.h"

TACK_RETVAL tackTestStore(TackCryptoFuncs* crypto)
{
    TackProcessingContext ctxET1, ctxEB1, ctxEB1T2, ctxEBmaxT2, ctxET1M, ctxET2;

    uint8_t* keyHash;
    uint8_t* tack;
    uint32_t currentTime = 1000;
    TackStoreDefault store;

    TCHECK(tackTestProcessInit());

    tack = tackExtensionGetTack(tackExtET1, 0);
    keyHash = tackTackGetTargetHash(tack);

    /* Prepare context for ET1, EB1, EB1T2, EBmaxT2, ET1M */
    TCHECK(tackProcessWellFormed(&ctxET1, 
               tackExtET1, tackExtET1Len, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxEB1, 
               tackExtEB1, tackExtEB1Len, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxEB1T2, 
               tackExtEB1T2, tackExtEB1T2Len, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxEBmaxT2, 
               tackExtEBmaxT2, tackExtEBmaxT2Len, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxET1M, 
               tackExtET1M, tackExtET1MLen, keyHash, currentTime, crypto));

    TCHECK(tackProcessWellFormed(&ctxET2, 
               tackExtET2, tackExtET2Len, keyHash, currentTime, crypto));
    
    store.setCryptoFuncs(crypto);
    store.setPinActivation(true);
    store.setDirtyFlagEnabled(true);

    store.setDirtyFlag(false);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime), TACK_OK_UNPINNED);
    assert(store.getDirtyFlag() == true);

    store.setDirtyFlag(false);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+10), TACK_OK_UNPINNED);
    assert(store.getDirtyFlag() == true);

    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+18), TACK_OK_ACCEPTED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+100), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+199), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+396), TACK_OK_ACCEPTED);
    store.setPinActivation(false);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+1000), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x.com", currentTime+1001), TACK_OK_UNPINNED);
    store.setPinActivation(true);

    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime+10), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime+10), TACK_OK_ACCEPTED);

    store.setDirtyFlag(false);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime), TACK_OK_REJECTED);
    assert(store.getDirtyFlag() == false);

    store.setPinActivation(false);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime), TACK_OK_REJECTED);
    store.setPinActivation(true);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime+1000), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime+2000), TACK_OK_UNPINNED);
    store.setPinActivation(false);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime+2001), TACK_OK_ACCEPTED);
    store.setPinActivation(true);
    TCHECK_VAL(store.process(&ctxET2, "x.com", currentTime+2001), TACK_OK_ACCEPTED);

    store.setPinActivation(false);
    store.setDirtyFlag(false);
    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime+11), TACK_OK_ACCEPTED);
    assert(store.getDirtyFlag() == false);
    store.setPinActivation(true);

    /* Ensure there is a pin for key 0 in the store, for following minGen test */
    TCHECK_VAL(store.process(&ctxET1, "third.com", currentTime), TACK_OK_UNPINNED);

    /* Try setting a larger minGen (254) with a name that comes before the other
       names, to ensure that only the largest minGen is processed */
    TCHECK_VAL(store.process(&ctxET1M, "a.com", currentTime), TACK_OK_UNPINNED);
    uint8_t minGen;
    store.getMinGeneration("2jgim.5jn33.3gc6r.he4gi.3mope", &minGen);
    assert(minGen == 254);

    store.setMinGeneration("2jgim.5jn33.3gc6r.he4gi.3mope", 253);
    store.getMinGeneration("2jgim.5jn33.3gc6r.he4gi.3mope", &minGen);
    assert(minGen == 254);

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

    // Check that the largest minGen was deserialized
    store2.getMinGeneration("rnx3y.35xdl.hssy4.bop3v.zifgu", &minGen);
    assert(minGen == 254);

    assert(strcmp(outTest, outTest2) == 0);

    // OK new round of tests for break sigs and generations
    store.clear();
    TCHECK_VAL(store.process(&ctxET1, "x1.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x2.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x3.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET2, "y.com", currentTime), TACK_OK_UNPINNED);
    assert(store.numPinned() == 4 && store.numKeys() == 2);

    // Try break sig EB1
    TCHECK_VAL(store.process(&ctxEB1, "x1.com", currentTime), TACK_OK_UNPINNED);
    assert(store.numPinned() == 1 && store.numKeys() == 1);

    // Try break sig EB1T2 *and* revocation, as it has a lower min_generation
    // than the ET2
    TCHECK_VAL(store.process(&ctxET1, "x1.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(retval = store.process(&ctxEB1T2, "x1.com", currentTime), 
               TACK_ERR_REVOKED_GENERATION);
    assert(store.numPinned() == 1 && store.numKeys() == 1);

    // Reset, try another break signature case, with a min_generation update (ET2)
    store.clear();
    TCHECK_VAL(store.process(&ctxET1, "x1.com", currentTime), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxET1, "x1.com", currentTime+10), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxEBmaxT2, "x1.com", currentTime+11), TACK_OK_UNPINNED);
    assert(store.numPinned() == 1 && store.numKeys() == 1);

    TCHECK_VAL(store.process(&ctxEBmaxT2, "x1.com", currentTime+100), TACK_OK_UNPINNED);
    TCHECK_VAL(store.process(&ctxEBmaxT2, "x1.com", currentTime+101), TACK_OK_ACCEPTED);
    TCHECK_VAL(store.process(&ctxET2, "x1.com", currentTime+101), TACK_OK_ACCEPTED);
    TCHECK_VAL(store.process(&ctxEBmaxT2, "x1.com", currentTime+101), 
               TACK_ERR_REVOKED_GENERATION);

    
    return TACK_OK;
}

#endif

