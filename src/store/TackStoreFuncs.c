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
        pair->numRecords = 0;
    else if (deleteMask == 2)
        pair->numRecords = 1;
    else if (deleteMask == 1) {
        memcpy(pair->records, pair->records+1, sizeof(TackNameRecord));
        pair->numRecords = 1;
    }
}
