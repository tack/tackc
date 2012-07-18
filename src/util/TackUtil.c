/* Authors: 
 *   Trevor Perrin
 *
 * See the LICENSE file for legal information regarding use of this file.
 */


#include <string.h>
#include <stdio.h>
#include "TackUtil.h"

uint16_t ptou16(uint8_t* p)
{
    return ((uint16_t)*(p+0) << 8) |
        (uint16_t)*(p+1); 
}

uint32_t ptou32(uint8_t* p)
{
    return ((uint32_t)*(p+0) << 24) |
        ((uint32_t)*(p+1) << 16) |
        ((uint32_t)*(p+2) << 8) |
        (uint32_t)*(p+3); 
}

/* 97 is equal sign (padding), 98 is CR/LF to skip over, 99 is invalid */
static const uint8_t base64Digits[] = { 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 98, 99, 99, 98, 99, 99, /* CR and LF */
99, 99, 99, 99, 99, 99, 99, 99,
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 62, 99, 99, 99, 63, /* + and / */
52, 53, 54, 55, 56, 57, 58, 59, /* 0...7 */
60, 61, 99, 99, 99, 97, 99, 99, /* 8..9 and = */
99,  0,  1,  2,  3,  4,  5,  6, /* A.. */
 7,  8,  9, 10, 11, 12, 13, 14, 
15, 16, 17, 18, 19, 20, 21, 22, 
23, 24, 25, 99, 99, 99, 99, 99, /* ..Z */ 
99, 26, 27, 28, 29, 30, 31, 32, /* a... */
33, 34, 35, 36, 37, 38, 39, 40, 
41, 42, 43, 44, 45, 46, 47, 48, 
49, 50, 51, 99, 99, 99, 99, 99, /* ...z */
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99, 
99, 99, 99, 99, 99, 99, 99, 99};

TACK_RETVAL tackBase64Decode(uint8_t* in, uint32_t inLen,
                             uint8_t* out, uint32_t* outLen) {
    uint8_t a, b, c, d;
    uint32_t count;
    uint8_t* outStart = out;
 
    for (count=0; count*4 < inLen; count++) {
        if (base64Digits[*in] == 99) {return TACK_ERR_BAD_BASE64;}
        while (base64Digits[*in] == 98) in++; /* CR or LF */
        a = base64Digits[*in++];

        if (base64Digits[*in] == 99) {return TACK_ERR_BAD_BASE64;}
        while (base64Digits[*in] == 98) in++; /* CR or LF */
        b = base64Digits[*in++];

        if (base64Digits[*in] == 99) {return TACK_ERR_BAD_BASE64;}
        while (base64Digits[*in] == 98) in++; /* CR or LF */
        c = base64Digits[*in++];

        if (base64Digits[*in] == 99) {return TACK_ERR_BAD_BASE64;}
        while (base64Digits[*in] == 98) in++; /* CR or LF */
        d = base64Digits[*in++];

        *(out++) = (a << 2) | ((b & 0x30) >> 4);
        if (c == 97) /* padding '=' */
            break;

        *(out++) = ((b & 0x0f) << 4) | ((c & 0x3c) >> 2);
        if (d == 97) /* padding '=' */
            break;

        *(out++) = ((c & 0x03) << 6) | d;
    }
    *outLen = out - outStart;
    return TACK_OK;
}

TACK_RETVAL tackDePem(char* label, uint8_t* in, uint32_t inLen, 
                      uint8_t* out, uint32_t* outLen) {
    uint32_t count = 0;
    char startLabel[256];
    uint32_t startLen = 0;
    char endLabel[256];
    uint32_t endLen = 0;
    int32_t startIndex=0;

    if (strlen(label) > 100)
        return TACK_ERR;

    sprintf(startLabel, "-----BEGIN %s-----", label);
    sprintf(endLabel, "-----END %s-----", label);
    startLen = strlen(startLabel);
    endLen = strlen(endLabel);

    for (count=0; count < inLen - startLen; count++) {
        if (memcmp((in + count), startLabel, startLen) == 0)
            break;
    }
    if (count == inLen - startLen) {
        return TACK_ERR_BAD_PEM;
    }
    startIndex = count + startLen;
    
    for (count=0; count < inLen - (endLen + startIndex) + 1; count++) {
        if (memcmp((in + startIndex + count), endLabel, endLen) == 0)
            break;
    }
    if (count == inLen - (endLen + startIndex) + 1) {
        return TACK_ERR_BAD_PEM;
    }

    return tackBase64Decode(in + startIndex, count, out, outLen);
}
