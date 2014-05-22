#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

#include "baseX.h"

/*
 * base64 code is modified from original source code from: 
 * https://github.com/tomcumming/base64.git
 *
 * Copyright (c) 2014 Tom Cumming
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * ( of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

uint8_t charTable[64] = 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t 
b64_encodedLength(size_t length)
{
	return (length + 2) / 3 * 4;
}

size_t 
b64_decodedLength(size_t length)
{
	return length * 3 / 4;
}

void 
b64_encode(uint8_t *src, size_t len, uint8_t *dst)
{
	while(len >= 3) {
		// 1st b64 char
		*dst = charTable[(src[0] & 0xfc) >> 2]; 
		dst++;

		// 2nd
		*dst = (src[0] & 0x03) << 4;
		*dst |= (src[1] & 0xf0) >> 4;
		*dst = charTable[*dst];
		dst++;

		//3rd
		*dst = (src[1] & 0x0f) << 2;
		*dst |= (src[2] & 0xc0) >> 6;
		*dst = charTable[*dst];
		dst++;

		//4th
		*dst = charTable[src[2] & 0x3f];
		dst++;

		src += 3;
		len -= 3;
	}

	if(len == 2) {
		// 1st b64 char
		*dst = charTable[(src[0] & 0xfc) >> 2]; 
		dst++;

		// 2nd
		*dst = (src[0] & 0x03) << 4;
		*dst |= (src[1] & 0xf0) >> 4;
		*dst = charTable[*dst];
		dst++;

		// padding
		*dst = '=';
	} else if(len == 1) {
		// 1st b64 char
		*dst = charTable[(src[0] & 0xfc) >> 2];
		dst++;

		// 2nd
		*dst = charTable[(src[0] & 0x03) << 4];
		dst++;

		// padding
		*dst = '=';
		dst++;

		*dst = '=';
	}
}

uint8_t 
lookupB64(uint8_t c)
{
	switch(c) {
		default:
		case 'A': return 0;
		case 'B': return 1;
		case 'C': return 2;
		case 'D': return 3;
		case 'E': return 4;
		case 'F': return 5;
		case 'G': return 6;
		case 'H': return 7;
		case 'I': return 8;
		case 'J': return 9;
		case 'K': return 10;
		case 'L': return 11;
		case 'M': return 12;
		case 'N': return 13;
		case 'O': return 14;
		case 'P': return 15;
		case 'Q': return 16;
		case 'R': return 17;
		case 'S': return 18;
		case 'T': return 19;
		case 'U': return 20;
		case 'V': return 21;
		case 'W': return 22;
		case 'X': return 23;
		case 'Y': return 24;
		case 'Z': return 25;
		case 'a': return 26;
		case 'b': return 27;
		case 'c': return 28;
		case 'd': return 29;
		case 'e': return 30;
		case 'f': return 31;
		case 'g': return 32;
		case 'h': return 33;
		case 'i': return 34;
		case 'j': return 35;
		case 'k': return 36;
		case 'l': return 37;
		case 'm': return 38;
		case 'n': return 39;
		case 'o': return 40;
		case 'p': return 41;
		case 'q': return 42;
		case 'r': return 43;
		case 's': return 44;
		case 't': return 45;
		case 'u': return 46;
		case 'v': return 47;
		case 'w': return 48;
		case 'x': return 49;
		case 'y': return 50;
		case 'z': return 51;
		case '0': return 52;
		case '1': return 53;
		case '2': return 54;
		case '3': return 55;
		case '4': return 56;
		case '5': return 57;
		case '6': return 58;
		case '7': return 59;
		case '8': return 60;
		case '9': return 61;
		case '+': return 62;
		case '/': return 63;
	}
}

void 
decode2(uint8_t *src, uint8_t *dst)
{
	*dst = lookupB64(src[0]) << 2;
	*dst |= (lookupB64(src[1]) & 0x30) >> 4;
}

void 
decode3(uint8_t *src, uint8_t *dst)
{
	decode2(src, dst);
	dst++;

	*dst = (lookupB64(src[1]) & 0x0f) << 4;
	*dst |= (lookupB64(src[2]) & 0x3c) >> 2;
}

void 
decode4(uint8_t *src, uint8_t *dst)
{
	decode3(src, dst);
	dst += 2;

	*dst = (lookupB64(src[2]) & 0x03) << 6;
	*dst |= lookupB64(src[3]);
}

size_t 
b64_decode(uint8_t *src, size_t len, uint8_t *dst)
{
	size_t dstLength = 0;

	while(len >= 5) {
		decode4(src, dst);
		dst += 3;
		src += 4;
		len -= 4;
		dstLength += 3;
	}
	
	if(len == 4) {
		if(src[3] != '=') {
			decode4(src, dst);
			dstLength += 3;
		} else if(src[2] != '=') {
			decode3(src, dst);
			dstLength += 2;
		} else {
			decode2(src, dst);
			dstLength += 1;
		}
	}

	// The following code handles non standard code that doesnt use the '='
	// termination symbol 

	else if(len == 3) {
		decode3(src, dst);
		dstLength += 2;
	} else if(len == 2) {
		decode2(src, dst);
		dstLength += 1;
	} else {
		// encoding error!
	}

	return dstLength;
}


/*
 * base58 code is modified from original source code from: 
 * https://github.com/netrikare/NBase58.git
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * ( of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

static const char *ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static unsigned char INDEXES[128] = { -1 };

unsigned char *
getIndexes(void)
{
	int i;

	for (i = 0; i < 58; i++)
		INDEXES[(int)ALPHABET[i]] = i;

	return INDEXES;
}

unsigned char 
divmod58(unsigned char *in, int inLen, int i)
{
	int rem = 0;
	for(;i<inLen; i++) {
		rem = rem * 256 + in[i];
		in[i] = rem / 58;
		rem = rem % 58;
	}
	return rem & 0xFF;
}

unsigned char 
divmod256(unsigned char *in, int inLen, int i)
{
	int rem = 0;
	for(;i<inLen; i++) {
		rem = rem * 58 + in[i];
		in[i] = rem / 256;
		rem = rem % 256;
	}
	return rem & 0xFF;
}

unsigned char *
b58_encode(unsigned char *in, int inLen, int *outLen)
{
	if(inLen == 0)
		return NULL;

	unsigned char *inCopy = malloc(inLen);
	memcpy(inCopy, in, inLen);

	//count leading zeros
	int z = -1;
	while(z < inLen && inCopy[++z] == 0x00)
		;

	int j = inLen * 2;
	int inLen_x2 = j;
	unsigned char *temp = malloc(inLen_x2);

	//skip leading zeros and encode from startAt
	int startAt = z;
	while(startAt < inLen){
		unsigned char mod = divmod58(inCopy, inLen, startAt);
		if(inCopy[startAt] == 0)
			++startAt;

		temp[--j] = ALPHABET[mod];
	}

	free(inCopy);

	while(j<inLen_x2 && temp[j] == '1')		
		j++;

	while(--z >= 0)
		temp[--j] = '1';


	*outLen = inLen_x2 - j;

	int len = inLen_x2 - j;

	unsigned char *out = malloc(len + 1);
	out[len] = 0;
	memcpy(out, temp + j, len);
	free(temp);

	return out;
}

unsigned char *
b58_decode(unsigned char *input, int inLen, int *outLen)
{
	if(inLen == 0)
		return NULL;

	unsigned char *input58 = malloc(inLen);
	unsigned char *indexes = getIndexes();

	int i=0;
	for(; i<inLen; i++){
		input58[i] = indexes[input[i]];
	}

	//count leading zeros
	int z = -1;
	while(z<inLen && input58[++z] == 0x00)
		;

	unsigned char *temp = malloc(inLen);
	int j = inLen;

	int startAt = z;
	while(startAt < inLen){
		char mod = divmod256(input58, inLen, startAt);
		if(input58[startAt] == 0)
			++startAt;

		temp[--j] = mod;
	}

	free(input58);

	while(j<inLen && temp[j] == 0)		
		j++;

	*outLen = inLen - j + z;
	int len = inLen - j + z;
	unsigned char *out = malloc(len + 1);
	out[len] = 0;
	memcpy(out, temp + j - z, len);
	free(temp);

	return out;
}
