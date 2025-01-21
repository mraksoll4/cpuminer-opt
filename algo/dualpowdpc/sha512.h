#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

#define SHA512_OUTPUT_SIZE 64

/**
 * SHA‑512 context: stores the current 512-bit state,
 * a 128-byte buffer, and a counter of all added bytes.
 */
typedef struct {
    uint64_t s[8];
    unsigned char buf[128];
    uint64_t bytes;
} sha512_ctx;

/* Initialize the context. */
void sha512_init(sha512_ctx* ctx);

/* Update the context (add the next portion of data). */
void sha512_update(sha512_ctx* ctx, const unsigned char* data, size_t len);

/* Finalize the computation and obtain the final 64-byte hash. */
void sha512_finalize(sha512_ctx* ctx, unsigned char hash[SHA512_OUTPUT_SIZE]);

/* Reset the context to its initial state (as after sha512_init). */
void sha512_reset(sha512_ctx* ctx);

/**
 * A simplified "one-shot" function that:
 *  1) Initializes the context
 *  2) Adds all data (input, length input_len)
 *  3) Finalizes and stores the result (64 bytes) in output
 */
void sha512_hash(const char* input, char* output, uint32_t input_len);

#endif // SHA512_H
