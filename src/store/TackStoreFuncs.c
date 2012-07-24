/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include "TackStoreFuncs.h"

TACK_RETVAL tackStoreGetPin(const TackStoreFuncs* store, const void* arg, const void* name, 
                             TackNameRecord* nameRecord, uint8_t *minGeneration)
{
    TACK_RETVAL retval = TACK_ERR;
    if ((retval = store->getNameRecord(arg, name, nameRecord)) != TACK_OK)
        return retval;

    if ((retval = store->getMinGeneration(arg, nameRecord->fingerprint, 
                                          minGeneration)) != TACK_OK)
        return retval;
    return TACK_OK;
}

TACK_RETVAL tackStoreSetPin(const TackStoreFuncs* store, const void* arg, const void* name, 
                            const TackNameRecord* nameRecord, uint8_t minGeneration)
{
    TACK_RETVAL retval = TACK_ERR;
    /* Set key record first to leave things in consistent state if interrupted */
    if ((retval = store->setMinGeneration(arg, nameRecord->fingerprint, 
                                          minGeneration)) != TACK_OK)
        return retval;
    if ((retval = store->setNameRecord(arg, name, nameRecord)) != TACK_OK)
        return retval;
    return TACK_OK;
}
