/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */

#ifndef __TACK_EXTENSION_H__
#define __TACK_EXTENSION_H__

#include "TackRetval.h"
#include "TackCryptoFuncs.h"
#include "Tack.h"
#include "TackBreakSig.h"

#define TACK_BREAK_SIGS_MAXCOUNT 8

typedef struct {
	uint8_t tackCount; /* 0 or 1 */
	Tack tack;
	
	uint8_t breakSigsCount; /* 0...8 */
	TackBreakSig breakSigs[TACK_BREAK_SIGS_MAXCOUNT];

	uint8_t activationFlag;
} TackExtension;

TACK_RETVAL tackExtensionInit(TackExtension* tackExt, uint8_t* data);
TACK_RETVAL tackExtensionVerifySignatures(TackExtension* tackExt, VerifyFunc func);

#endif