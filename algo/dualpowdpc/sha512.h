#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

#define SHA512_OUTPUT_SIZE 64

/**
 * Контекст SHA‑512: хранит текущее 512-битное состояние, 
 * 128‑байтный буфер, и счётчик всех добавленных байт.
 */
typedef struct {
    uint64_t s[8];          /* внутреннее 512‑битное состояние (8 × 64 бит) */
    unsigned char buf[128]; /* буфер для "неполного" блока */
    uint64_t bytes;         /* общее число обработанных байт */
} sha512_ctx;

/* Инициализировать контекст. */
void sha512_init(sha512_ctx* ctx);

/* Обновить контекст (добавить очередную порцию данных). */
void sha512_update(sha512_ctx* ctx, const unsigned char* data, size_t len);

/* Завершить вычисление и получить окончательный 64‑байтовый хеш. */
void sha512_finalize(sha512_ctx* ctx, unsigned char hash[SHA512_OUTPUT_SIZE]);

/* Сброс контекста к начальному состоянию (как после sha512_init). */
void sha512_reset(sha512_ctx* ctx);

/**
 * Упрощённая «одновыстрельная» функция, которая:
 *  1) инициализирует контекст
 *  2) добавляет все данные (input, длина input_len)
 *  3) финализирует и кладёт результат (64 байта) в output
 */
void sha512_hash(const char* input, char* output, uint32_t input_len);

#endif // SHA512_H
