/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackStoreFuncs.h"

TACK_RETVAL appendPin(TackPinPair* pair, uint32_t initialTime, uint32_t endTime, 
                      char* fingerprint)
{
    if (pair->numPins > 1)
        return TACK_ERR_ASSERTION;
    pair->pins[pair->numPins].initialTime = initialTime;
    pair->pins[pair->numPins].endTime = endTime;
    strcpy(pair->pins[pair->numPins].fingerprint, fingerprint);
    pair->numPins++;
    return TACK_OK;
}
