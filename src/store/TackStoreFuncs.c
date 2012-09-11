/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#include <string.h>
#include "TackStoreFuncs.h"

void tackPairDeleteRecords(TackNameRecordPair* pair, uint8_t deleteMask)
{
    if (deleteMask == 3)
        pair->numPins = 0;

    else if (deleteMask == 2) {
        if (pair->numPins == 2)
            pair->numPins = 1;
    }

    else if (deleteMask == 1) {
        if (pair->numPins == 1) {
            pair->numPins = 0;
        }
        else if (pair->numPins == 2) {
            memcpy(pair->records, pair->records+1, sizeof(TackNameRecord));        
            pair->numPins = 1;
        }
    }
}
