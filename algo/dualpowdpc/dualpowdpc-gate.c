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

#include "yespower.h"         // yespower_tls(...) SSE2/ref
#include "argon2.h"           // argon2id_hash_raw
#include "sha512.h"           // ваш SHA-512 (C-реализация)
#include "sha256.h"           // sha256_ctx_init, sha256_update, etc
#include "algo-gate-api.h"    // algo_gate_t, submit_solution, ...


// yespower конфигурация
yespower_params_t yespower_params;

// Thread-local контекст SHA-256, как в scanhash_yespower:
__thread sha256_context sha256_prehash_ctx;

/* SSE2 / REF вариант yespower_hash, 
   зависящий от __SSE2__ или __aarch64__ */
#if defined(__SSE2__) || defined(__aarch64__)
int yespower_hash(const char *input, char *output, int thrid)
{
    // 80 байт -> yespower(N=..., r=..., pers=...) -> 32 байта
    return yespower_tls(input, 80, &yespower_params,
                        (yespower_binary_t*)output, thrid);
}
#else
int yespower_hash_ref(const char *input, char *output, int thrid)
{
    return yespower_tls_ref(input, 80, &yespower_params,
                            (yespower_binary_t*)output, thrid);
}
#endif

/* ------------------------------------------------------------------
 * Реализация argon2idDPC_hash:
 *  - Двойной SHA-512 => 64 байт
 *  - 1-й раунд Argon2id(t=2,m=4096,p=2) => 32 байта
 *  - 2-й раунд Argon2id(t=2,m=32768,p=2) => 32 байта
 *  - Результат (32 байта) возвращаем
 * ------------------------------------------------------------------*/
static void argon2idDPC_hash(const char *input, char *output, uint32_t input_len)
{
    // (1) Двойной SHA-512
    unsigned char salt_sha512[64];
    {
        sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, (const unsigned char*)input, input_len);
        sha512_finalize(&ctx, salt_sha512);

        sha512_reset(&ctx);
        sha512_update(&ctx, salt_sha512, 64);
        sha512_finalize(&ctx, salt_sha512);
    }

    // (2) Argon2id 2 раунда
    unsigned char hash[32];
    unsigned char hash2[32];

    // Первый (t=2, m=4096, p=2)
    {
        int rc = argon2id_hash_raw(
            2,       // t_cost=2
            4096,    // m_cost=4096 KiB = ~4MB
            2,       // параллелизм=2
            input, input_len,       // пароль
            salt_sha512, 64,        // соль
            hash, 32
        );
        if (rc != ARGON2_OK) {
            applog(LOG_ERR, "argon2idDPC_hash: first Argon2id rc=%d\n", rc);
            // exit(1) или return
        }
    }

    // Второй (t=2, m=32768, p=2)
    {
        int rc = argon2id_hash_raw(
            2, 
            32768,   // 32MB
            2,
            input, input_len,
            hash, 32,
            hash2, 32
        );
        if (rc != ARGON2_OK) {
            applog(LOG_ERR, "argon2idDPC_hash: second Argon2id rc=%d\n", rc);
        }
    }

    // Результат -> output
    memcpy(output, hash2, 32);
}

/* ------------------------------------------------------------------
 * scanhash_dualpowdpc:
 *   - Копируем 80 байт заголовка (endiandata),
 *   - Инициализируем sha256_prehash_ctx, update(..., 64), 
 *     (как scanhash_yespower, без sha256_final)
 *   - Перебираем nonce от first_nonce до max_nonce:
 *       yespower_hash => если < target => argon2idDPC => если < target => submit
 * ------------------------------------------------------------------*/
int scanhash_dualpowdpc(struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
    // Выделяем буферы
    uint32_t _ALIGN(64) vhash[8];        // yespower => 32 байта
    unsigned char argon2hash[32];       // Argon2idDPC => 32 байт
    uint32_t _ALIGN(64) endiandata[20]; // 80 байт

    uint32_t *pdata   = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce  = max_nonce;
    uint32_t n = first_nonce;
    const int thr_id = mythr->id;

    // 1) Заполняем endiandata[0..18], +nonce
    for (int k = 0; k < 19; k++) {
        be32enc(&endiandata[k], pdata[k]);
    }
    endiandata[19] = n;

    // 2) Частичный SHA-256 (64 байта), как scanhash_yespower
    sha256_ctx_init(&sha256_prehash_ctx);
    sha256_update(&sha256_prehash_ctx, endiandata, 64);

    // 3) Цикл по nonce
    do {
        // (a) yespower (через gate->hash)
        if (algo_gate.hash((char*)endiandata, (char*)vhash, thr_id)) {
            // Проверяем < target
            if (unlikely(valid_hash(vhash, ptarget) && !opt_benchmark)) {
                // (b) Если yespower < target, проверяем Argon2idDPC
                argon2idDPC_hash((const char*)endiandata, (char*)argon2hash, 80);

                if (valid_hash((uint32_t*)argon2hash, ptarget)) {
                    // Оба POW пройдены
                    be32enc(pdata + 19, n);
                    submit_solution(work, argon2hash, mythr);
                }
            }
        }
        // Следующий nonce
        endiandata[19] = ++n;
    } while (n < last_nonce && !work_restart[thr_id].restart);

    // Итого перебрали n - first_nonce nonce
    *hashes_done = n - first_nonce;
    pdata[19] = n;
    return 0;
}

/* ------------------------------------------------------------------
 * Регистрация dualpowdpc ("dpowcoin"):
 *   - Настраивает yespower_params (N=2048, r=8, pers=...).
 *   - gate->scanhash = scanhash_dualpowdpc
 *   - gate->hash = yespower_hash (SSE2/ref)
 * ------------------------------------------------------------------*/
bool register_dualpowdpc_algo(algo_gate_t* gate)
{
    // Настройка yespower
    yespower_params.version = YESPOWER_1_0;
    yespower_params.N       = 2048;
    yespower_params.r       = 8;
    yespower_params.pers    = "One POW? Why not two? 17/04/2024";
    yespower_params.perslen = 32;

    gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
    gate->scanhash      = (void*)&scanhash_dualpowdpc;
#if defined(__SSE2__) || defined(__aarch64__)
    gate->hash          = (void*)&yespower_hash;
#else
    gate->hash          = (void*)&yespower_hash_ref;
#endif

    // Можно изменить opt_target_factor, если нужно
    opt_target_factor   = 65536.0;

    applog(LOG_INFO, "DUALPOWDPC: yespower + argon2idDPC algo registered.\n");
    return true;
}
