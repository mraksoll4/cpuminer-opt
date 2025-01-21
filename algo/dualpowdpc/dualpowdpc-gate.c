#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "miner.h"
#include "algo/yespower/yespower.h"
#include "argon2d/argon2d/argon2.h"
#include "sha512.h"
#include "algo-gate-api.h"
#include "simd-utils.h"
#include "dualpowdpc-gate.h"

// Thread-local context for argon2id
typedef struct {
    argon2_context context1;
    argon2_context context2;
    uint8_t memory1[4096 * 1024];  // 4MB for first pass
    uint8_t memory2[32768 * 1024]; // 32MB for second pass
} argon2id_thread_ctx;

__thread argon2id_thread_ctx* argon_ctx = NULL;
yespower_params_t yespower_params;

extern __thread sha256_context sha256_prehash_ctx;

// Initialize thread-local argon2id context
bool init_argon2id_thread_ctx(int thr_id) {
    if (!argon_ctx) {
        argon_ctx = (argon2id_thread_ctx*)malloc(sizeof(argon2id_thread_ctx));
        if (!argon_ctx) return false;

        // Initialize first context (4096 MB)
        memset(&argon_ctx->context1, 0, sizeof(argon2_context));
        argon_ctx->context1.t_cost = 2;
        argon_ctx->context1.m_cost = 4096;
        argon_ctx->context1.lanes = 2;
        argon_ctx->context1.threads = 2;
        argon_ctx->context1.flags = ARGON2_DEFAULT_FLAGS;
        argon_ctx->context1.version = 0x13;

        // Initialize second context (32768 MB)
        memset(&argon_ctx->context2, 0, sizeof(argon2_context));
        argon_ctx->context2.t_cost = 2;
        argon_ctx->context2.m_cost = 32768;
        argon_ctx->context2.lanes = 2;
        argon_ctx->context2.threads = 2;
        argon_ctx->context2.flags = ARGON2_DEFAULT_FLAGS;
        argon_ctx->context2.version = 0x13;

    }
    return true;
}

void free_argon2id_thread_ctx() {
    if (argon_ctx) {
        free(argon_ctx);
        argon_ctx = NULL;
    }
}

// Internal yespower function
static int yespower_hash_internal(const char *input, char *output, int thrid)
{
#if defined(__SSE2__) || defined(__aarch64__)
    return yespower_tls(input, 80, &yespower_params, 
            (yespower_binary_t*)output, thrid);
#else
    return yespower_tls_ref(input, 80, &yespower_params,
            (yespower_binary_t*)output, thrid);
#endif
}

// Internal argon2id function
static void argon2id_hash_internal(const char *input, char *output, int thr_id)
{
    unsigned char _ALIGN(64) salt_sha512[64];
    unsigned char _ALIGN(64) hash[32];
    
    // Double SHA-512
    sha512_ctx sha_ctx;
    sha512_init(&sha_ctx);
    sha512_update(&sha_ctx, (const unsigned char *)input, 80);
    sha512_finalize(&sha_ctx, salt_sha512);
    sha512_reset(&sha_ctx);
    sha512_update(&sha_ctx, salt_sha512, 64);
    sha512_finalize(&sha_ctx, salt_sha512);

    // Use thread-local context
    if (!argon_ctx) {
        if (!init_argon2id_thread_ctx(thr_id)) return;
    }

    // First Argon2id pass
    argon_ctx->context1.out = hash;
    argon_ctx->context1.outlen = 32;
    argon_ctx->context1.pwd = (uint8_t *)input;
    argon_ctx->context1.pwdlen = 80;
    argon_ctx->context1.salt = salt_sha512;
    argon_ctx->context1.saltlen = 64;
    
    int rc = argon2id_ctx_dpc(&argon_ctx->context1);
    if (rc != ARGON2_OK) {
        applog(LOG_ERR, "argon2idDPC_hash: first Argon2id rc=%d\n", rc);
        return;
    }

    // Second Argon2id pass
    argon_ctx->context2.out = (uint8_t *)output;
    argon_ctx->context2.outlen = 32;
    argon_ctx->context2.pwd = (uint8_t *)input;
    argon_ctx->context2.pwdlen = 80;
    argon_ctx->context2.salt = hash;
    argon_ctx->context2.saltlen = 32;

    rc = argon2id_ctx_dpc(&argon_ctx->context2);
    if (rc != ARGON2_OK) {
        applog(LOG_ERR, "argon2idDPC_hash: second Argon2id rc=%d\n", rc);
        return;
    }
}

// Main scanhash function for dualpowdpc
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

    // Initialize thread context if needed
    if (!init_argon2id_thread_ctx(thr_id)) {
        return -1;
    }

    for (int k = 0; k < 19; k++) {
        be32enc(&endiandata[k], pdata[k]);
    }
    endiandata[19] = n;

    sha256_ctx_init(&sha256_prehash_ctx);
    sha256_update(&sha256_prehash_ctx, endiandata, 64);

    do {
        // First yespower
        if (yespower_hash_internal((char*)endiandata, (char*)vhash, thr_id)) {
            if unlikely(valid_hash(vhash, ptarget) && !opt_benchmark) {
                argon_count++;
                // Then argon2id
                argon2id_hash_internal((char*)endiandata, (char*)argon2hash, thr_id);
                
                if (valid_hash((uint32_t*)argon2hash, ptarget)) {
                    be32enc(pdata + 19, n);

                    //char yeshex[65], arghex[65];
                    //bin2hex(yeshex, (unsigned char*)vhash, 32);
                    //bin2hex(arghex, (unsigned char*)argon2hash, 32);
                    //applog(LOG_INFO, 
                    //    "DUALPOWDPC thr=%d: FOUND nonce=0x%08x\n"
                    //    "  Yespower-hash:    %s\n"
                    //    "  Argon2idDPC-hash: %s",
                    //    thr_id, n, yeshex, arghex);

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


bool register_dualpowdpc_algo(algo_gate_t *gate)
{

    yespower_params.version = YESPOWER_1_0;
    yespower_params.N = 2048;
    yespower_params.r = 8;
    yespower_params.pers = "One POW? Why not two? 17/04/2024";
    yespower_params.perslen = 32;


    gate->scanhash = (void*)&scanhash_dualpowdpc;
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT | SHA256_OPT;
    gate->get_work_data_size = (void*)&std_get_work_data_size;
    gate->work_cmp_size = 76;

    opt_target_factor = 65536.0;

    applog(LOG_INFO, "DUALPOWDPC: Dual PoW (yespower + argon2id) algo registered.\n");
    return true;
}