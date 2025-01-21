/*-
 *
 * Copyright 2025 DPOWCORE project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "miner.h"
#include "algo/yespower/yespower.h"         // yespower_tls(...) SSE2/ref
#include "argon2d/argon2d/argon2.h"         // argon2id_hash_raw
#include "sha512.h"                         // Your SHA-512 (C implementation)
#include "algo-gate-api.h"                  // algo_gate_t, submit_solution, ...
#include "simd-utils.h"
#include "dualpowdpc-gate.h"

yespower_params_t yespower_params;

extern __thread sha256_context sha256_prehash_ctx;

#if defined(__SSE2__) || defined(__aarch64__)

int yespower_hash_dpc(const char *input, char *output, int thrid)
{
   return yespower_tls(input, 80, &yespower_params,
           (yespower_binary_t*)output, thrid);
}

#else

int yespower_hash_ref_dpc(const char *input, char *output, int thrid)
{
   return yespower_tls_ref(input, 80, &yespower_params,
           (yespower_binary_t*)output, thrid);
}

#endif

/* 
 * Global (or thread-local) variable:
 *   extern __thread sha256_context sha256_prehash_ctx; 
 * Declared in miner.h or yespower.h.
 * We simply use it. 
 */

/* ------------------------------------------------------------------
 * Function: argon2idDPC_hash
 *   - 1) Double SHA-512 => salt_sha512 (64 bytes)
 *   - 2) Argon2id(t=2, m=4096, p=2) => 32 bytes
 *   - 3) Argon2id(t=2, m=32768, p=2) => 32 bytes
 *   - Final result (32 bytes) is stored in output.
 * ------------------------------------------------------------------ */
// Align buffers for all calculations
void argon2idDPC_hash(const char *input, char *output)
{
    unsigned char _ALIGN(64) salt_sha512[64];
    unsigned char _ALIGN(64) hash[32];
    
    // Step 1: Double SHA-512
    sha512_ctx sha_ctx;
    sha512_init(&sha_ctx);
    sha512_update(&sha_ctx, (const unsigned char *)input, 80);
    sha512_finalize(&sha_ctx, salt_sha512);
    sha512_reset(&sha_ctx);
    sha512_update(&sha_ctx, salt_sha512, 64);
    sha512_finalize(&sha_ctx, salt_sha512);

    // Step 2: First Argon2id (t=2, m=4096, p=2)
    argon2_context context1 = {0};
    context1.out = hash;
    context1.outlen = 32;
    context1.pwd = (uint8_t *)input;
    context1.pwdlen = 80;
    context1.salt = salt_sha512;
    context1.saltlen = 64;
    context1.secret = NULL;
    context1.secretlen = 0;
    context1.ad = NULL;
    context1.adlen = 0;
    context1.flags = ARGON2_DEFAULT_FLAGS;
    context1.m_cost = 4096;
    context1.lanes = 2;
    context1.threads = 2;
    context1.t_cost = 2;
    context1.allocate_cbk = NULL;
    context1.free_cbk = NULL;
    context1.version = 0x13;

    int rc = argon2id_ctx_dpc(&context1);
    if (rc != ARGON2_OK) {
        applog(LOG_ERR, "argon2idDPC_hash: first Argon2id rc=%d\n", rc);
        return;
    }

    // Step 3: Second Argon2id (t=2, m=32768, p=2)
    argon2_context context2 = {0};
    context2.out = (uint8_t *)output;
    context2.outlen = 32;
    context2.pwd = (uint8_t *)input;
    context2.pwdlen = 80;
    context2.salt = hash;
    context2.saltlen = 32;
    context2.secret = NULL;
    context2.secretlen = 0;
    context2.ad = NULL;
    context2.adlen = 0;
    context2.flags = ARGON2_DEFAULT_FLAGS;
    context2.m_cost = 32768;
    context2.lanes = 2;
    context2.threads = 2;
    context2.t_cost = 2;
    context2.allocate_cbk = NULL;
    context2.free_cbk = NULL;
    context2.version = 0x13;

    rc = argon2id_ctx_dpc(&context2);
    if (rc != ARGON2_OK) {
        applog(LOG_ERR, "argon2idDPC_hash: second Argon2id rc=%d\n", rc);
        return;
    }
}

bool register_argon2idDPC_algo(algo_gate_t* gate)
{
    gate->scanhash = (void*)&scanhash_dualpowdpc;
    gate->hash = (void*)&argon2idDPC_hash;
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
    opt_target_factor = 65536.0;
    return true;
}

/* ------------------------------------------------------------------
 * scanhash_dualpowdpc
 *   - Similar structure to scanhash_yespower:
 *     1) be32enc(endiandata[0..19]), 
 *     2) sha256_ctx_init(&sha256_prehash_ctx), sha256_update(...,64)
 *     3) In a loop: algo_gate.hash(...) => yespower => if < target => argon2 => if < target => submit
 * ------------------------------------------------------------------ */
int scanhash_dualpowdpc(struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
    uint32_t _ALIGN(64) vhash[8];
    unsigned char _ALIGN(64) argon2hash[32];
    uint32_t _ALIGN(64) endiandata[20];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce;
    uint32_t n = first_nonce;
    const int thr_id = mythr->id;
    uint64_t argon_count = 0;

    /* 1) Fill 19 words => endiandata[0..18], +nonce => endiandata[19] */
    for (int k = 0; k < 19; k++) {
        be32enc(&endiandata[k], pdata[k]);
    }
    endiandata[19] = n;

    /* 2) Part of scanhash_yespower: "partial sha256" */
    sha256_ctx_init(&sha256_prehash_ctx);
    sha256_update(&sha256_prehash_ctx, endiandata, 64);

    do {
        if (algo_gate.hash((char*)endiandata, (char*)vhash, thr_id)) {
            if unlikely(valid_hash(vhash, ptarget) && !opt_benchmark) {
                argon_count++;
                argon2idDPC_hash((const char*)endiandata, (char*)argon2hash);
                
                if (valid_hash((uint32_t*)argon2hash, ptarget)) {
                    be32enc(pdata + 19, n);

                    //char yeshex[65], arghex[65];
                    //bin2hex(yeshex, (unsigned char*)vhash, 32);
                    //bin2hex(arghex, (unsigned char*)argon2hash, 32);
                    //applog(LOG_INFO, 
                    //    "DUALPOWDPC thr=%d: FOUND nonce=0x%08x\n"
                    //    "  Yespower-hash:    %s\n"
                    //    "  Argon2idDPC-hash: %s",
                    //   thr_id, n, yeshex, arghex);

                    submit_solution(work, argon2hash, mythr);
                }
            }
        }
        endiandata[19] = ++n;
    } while (n < last_nonce && !work_restart[thr_id].restart);

    *hashes_done = argon_count;

    pdata[19] = n;
    return 0;
}

/* ------------------------------------------------------------------
 * Register dualpowdpc
 *  - yespower_params: version=1.0, N=2048, r=8, pers="One POW?..."
 *  - gate->scanhash = scanhash_dualpowdpc
 *  - gate->hash = yespower_hash (SSE2/ref)
 * ------------------------------------------------------------------ */
bool register_dualpowdpc_algo(algo_gate_t *gate)
{
    // Configure yespower
    yespower_params.version = YESPOWER_1_0;
    yespower_params.N       = 2048;
    yespower_params.r       = 8;
    yespower_params.pers    = "One POW? Why not two? 17/04/2024";
    yespower_params.perslen = 32;

    gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
    gate->scanhash      = (void*)&scanhash_dualpowdpc;

#if defined(__SSE2__) || defined(__aarch64__)
    gate->hash          = (void*)&yespower_hash_dpc;     // SSE2 variant
#else
    gate->hash          = (void*)&yespower_hash_ref_dpc; // ref
#endif

    opt_target_factor   = 65536.0;

    applog(LOG_INFO, "DUALPOWDPC: yespowerDPC + argon2idDPC algo registered.\n");
    return true;
}
