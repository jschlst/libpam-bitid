#ifndef BASEX_H
#define BASEX_H

#include <stdint.h>
#include <stddef.h>

/*
 * Returns the required size of the destination buffer when encoding
 */
size_t b64_encodedLength(size_t length);

/*
 * Returns the upper limit for decoded buffer length
 */
size_t b64_decodedLength(size_t length);

/*
 * src: The source buffer to encode
 * len: The length (in bytes) of the source
 * dst: The destination buffer, must be at least b64_encodedLength(len) in size
 */
void b64_encode(uint8_t *src, size_t len, uint8_t *dst);

/*
 * src: The source buffer to decode
 * len: The length (in bytes) of the source
 * dst: The destination buffer, must be at least b64_decodedLength(len) in size
 *
 * returns: Number of bytes written to dst
 */
size_t b64_decode(uint8_t *src, size_t len, uint8_t *dst);

unsigned char * b58_encode(unsigned char *in, int inLen, int *outLen);
unsigned char * b58_decode(unsigned char *in, int inLen, int *outLen);
#endif /* BASEX_H_ */
