/*-
 * Example: dualpowdpc-gate.c
 *
 *  Алгоритм DUALPOWDPC ("dpowcoin"):
 *   - Yespower (N=2048, r=8, pers="One POW? Why not two? 17/04/2024")
 *   - Argon2idDPC: "двойной SHA-512" + "2× Argon2id" (4MB, затем 32MB)
 *   - Одновременно оба POW должны удовлетворять target.
 *
 * Copyright 2018 Cryply team
 * All rights reserved.
 *
 * ... (условия лицензии, как в вашем исходном файле) ...
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "miner.h"
#include "algo/yespower/yespower.h"         // yespower_tls(...) SSE2/ref
#include "argon2d/argon2d/argon2.h"    // argon2id_hash_raw
#include "sha512.h"           // ваш SHA-512 (C-реализация)
#include "algo-gate-api.h"    // algo_gate_t, submit_solution, ...
#include "simd-utils.h"

yespower_params_t yespower_params;

extern __thread sha256_context sha256_prehash_ctx;



#if defined(__SSE2__) || defined(__aarch64__)

int yespower_hash_dpc( const char *input, char *output, int thrid )
{
   return yespower_tls( input, 80, &yespower_params,
           (yespower_binary_t*)output, thrid );
}

#else

int yespower_hash_ref_dpc( const char *input, char *output, int thrid )
{
   return yespower_tls_ref( input, 80, &yespower_params,
           (yespower_binary_t*)output, thrid );
}

#endif

/* 
 * Глобальная (или thread-local) переменная:
 *   extern __thread sha256_context sha256_prehash_ctx; 
 * Объявлена в miner.h или yespower.h.
 * Мы просто используем её. 
 */


/* ------------------------------------------------------------------
 * Функция: argon2idDPC_hash
 *   - 1) Двойной SHA-512 => salt_sha512 (64 байта)
 *   - 2) Argon2id( t=2, m=4096, p=2 ) => 32 байта
 *   - 3) Argon2id( t=2, m=32768, p=2 ) => 32 байта
 *   - Итог (32 байта) кладёт в output.
 * ------------------------------------------------------------------ */
// Применяем выравнивание для всех буферов, которые участвуют в вычислениях
void argon2idDPC_hash(const char *input, char *output, uint32_t input_len)
{
    unsigned char _ALIGN(64) salt_sha512[64];  // Исправлена синтаксическая ошибка
    unsigned char _ALIGN(64) hash[32];         // Исправлено выравнивание
    
    // Step 1: Double SHA-512
    sha512_ctx sha_ctx;
    sha512_init(&sha_ctx);
    sha512_update(&sha_ctx, (const unsigned char *)input, input_len);
    sha512_finalize(&sha_ctx, salt_sha512);
    sha512_reset(&sha_ctx);
    sha512_update(&sha_ctx, salt_sha512, 64);
    sha512_finalize(&sha_ctx, salt_sha512);

    // Step 2: First Argon2id (t=2, m=4096, p=2)
    argon2_context context1 = {0};
    context1.out = hash;
    context1.outlen = 32;
    context1.pwd = (uint8_t *)input;
    context1.pwdlen = input_len;
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
    context1.version = 0x13;  // Используем конкретное значение версии

    int rc = argon2id_ctx_dpc(&context1);  // Используем специализированную функцию
    if (rc != ARGON2_OK) {
        applog(LOG_ERR, "argon2idDPC_hash: first Argon2id rc=%d\n", rc);
        return;
    }

    // Step 3: Second Argon2id (t=2, m=32768, p=2)
    argon2_context context2 = {0};
    context2.out = (uint8_t *)output;
    context2.outlen = 32;
    context2.pwd = (uint8_t *)input;  // Используем исходный input
    context2.pwdlen = input_len;      // Используем исходную длину
    context2.salt = hash;            // Используем результат первого хеширования как соль
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

    rc = argon2id_ctx_dpc(&context2);  // Используем специализированную функцию
    if (rc != ARGON2_OK) {
        applog(LOG_ERR, "argon2idDPC_hash: second Argon2id rc=%d\n", rc);
        return;
    }
}


/* ------------------------------------------------------------------
 * scanhash_dualpowdpc
 *   - Повторяем структуру scanhash_yespower:
 *     1) be32enc(endiandata[0..19]), 
 *     2) sha256_ctx_init(&sha256_prehash_ctx), sha256_update(...,64)
 *     3) в цикле: algo_gate.hash(...) => yespower => if < target => argon2 => if < target => submit
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
    uint64_t argon_count = 0;  // Счётчик только для Argon2 вычислений

    /* 1) Заполняем 19 слов => endiandata[0..18], +nonce => endiandata[19] */
    for (int k = 0; k < 19; k++) {
        be32enc(&endiandata[k], pdata[k]);
    }
    endiandata[19] = n;

    /* 2) Часть scanhash_yespower: "partial sha256" */
    sha256_ctx_init(&sha256_prehash_ctx);
    sha256_update(&sha256_prehash_ctx, endiandata, 64);

    do {
        if (algo_gate.hash((char*)endiandata, (char*)vhash, thr_id)) {
            if unlikely(valid_hash(vhash, ptarget) && !opt_benchmark) {
                // Увеличиваем счётчик только когда делаем Argon2 вычисление
                argon_count++;
                
                argon2idDPC_hash((const char*)endiandata, (char*)argon2hash, 80);
                
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

    // Возвращаем только количество Argon2 вычислений
    *hashes_done = argon_count;

    pdata[19] = n;
    return 0;
}

/* ------------------------------------------------------------------
 * Регистрация dualpowdpc
 *  - yespower_params: version=1.0, N=2048, r=8, pers="One POW?..."
 *  - gate->scanhash = scanhash_dualpowdpc
 *  - gate->hash = yespower_hash (SSE2/ref)
 * ------------------------------------------------------------------ */
bool register_dualpowdpc_algo(algo_gate_t *gate)
{
    // Настраиваем yespower
    yespower_params.version = YESPOWER_1_0;
    yespower_params.N       = 2048; // как у вас
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

    applog(LOG_INFO, "DUALPOWDPC: yespower + argon2idDPC algo registered.\n");
    return true;
}