#include "sha512.h"
#include <string.h>  // для memcpy, memset
#include <stdio.h>   // (необязательно, только если понадобится fprintf)

/* 
 * Макросы SHA-512 (циклич. сдвиги, Ch, Maj, большие и малые сигмы).
 * Без суффиксов ULL; 64-битные литералы в hex виде интерпретируются 
 * компилятором как 64-бит unsigned long long автоматически.
 */
#define ROTR64(x,n) ( ((x) >> (n)) | ((x) << (64-(n))) )

static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (~x & z);
}
static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}
static inline uint64_t Sigma0(uint64_t x)
{
    return ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39);
}
static inline uint64_t Sigma1(uint64_t x)
{
    return ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41);
}
static inline uint64_t sigma0(uint64_t x)
{
    return ROTR64(x, 1) ^ ROTR64(x, 8) ^ (x >> 7);
}
static inline uint64_t sigma1(uint64_t x)
{
    return ROTR64(x,19) ^ ROTR64(x,61) ^ (x >> 6);
}

/* Таблица констант K0..K79 (FIPS 180‑4). */
static const uint64_t K[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/* Начальные значения (IV) SHA-512 (FIPS 180‑4). */
static const uint64_t SHA512_IV[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

/* Чтение 64-бит из массива (big-endian). */
static inline uint64_t read_be64(const unsigned char *p)
{
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) |
           ((uint64_t)p[7]      );
}

/* Запись 64-бит в массив (big-endian). */
static inline void write_be64(unsigned char *p, uint64_t x)
{
    p[0] = (unsigned char)(x >> 56);
    p[1] = (unsigned char)(x >> 48);
    p[2] = (unsigned char)(x >> 40);
    p[3] = (unsigned char)(x >> 32);
    p[4] = (unsigned char)(x >> 24);
    p[5] = (unsigned char)(x >> 16);
    p[6] = (unsigned char)(x >>  8);
    p[7] = (unsigned char)(x      );
}

/* Вспомогательная функция: обрабатывает один 128-байтовый блок из buf. */
static void sha512_transform(uint64_t state[8], const unsigned char block[128])
{
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    int t;

    /* Распаковываем первые 16 слов W. */
    for (t = 0; t < 16; t++) {
        W[t] = read_be64(block + t*8);
    }
    /* Вычисляем W[16..79]. */
    for (t = 16; t < 80; t++) {
        W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
    }

    /* Инициализируем рабочие переменные */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    /* 80 раундов */
    for (t = 0; t < 80; t++) {
        uint64_t T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t];
        uint64_t T2 = Sigma0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /* Прибавляем к состоянию */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/* Инициализация контекста */
void sha512_init(sha512_ctx* ctx)
{
    /* Копируем IV в ctx->s */
    memcpy(ctx->s, SHA512_IV, sizeof(ctx->s));
    ctx->bytes = 0;
    memset(ctx->buf, 0, 128);
}

/* Добавление данных в контекст (инкрементально). */
void sha512_update(sha512_ctx* ctx, const unsigned char* data, size_t len)
{
    size_t have = (size_t)(ctx->bytes % 128); // сколько байт уже в буфере
    ctx->bytes += len;

    /* Если буфер частично заполнен и вместе с новыми данными >=128, 
       сначала дозаполним buf и обработаем его */
    size_t need = 128 - have;
    if (have && len >= need) {
        memcpy(ctx->buf + have, data, need);
        sha512_transform(ctx->s, ctx->buf);
        data += need;
        len  -= need;
        have = 0;
    }
    /* Обрабатываем полные 128-байтовые блоки напрямую из data */
    while (len >= 128) {
        sha512_transform(ctx->s, data);
        data += 128;
        len  -= 128;
    }
    /* Остаток <128 копируем в буфер */
    if (len > 0) {
        memcpy(ctx->buf + have, data, len);
    }
}

/* Завершение вычисления: добавляем padding, длину, извлекаем финальный хеш. */
void sha512_finalize(sha512_ctx* ctx, unsigned char hash[SHA512_OUTPUT_SIZE])
{
    /*
     * По спецификации SHA-512:
     *  - Добавим 0x80, затем 0..(до 111) нулей, чтобы (длина % 128) стала 112
     *  - затем 16 байт (128 бит) с описанием длины (в битах, big-endian)
     */
    static const unsigned char pad[128] = { 0x80 }; // первый байт 0x80, остальные 0
    unsigned char sizedesc[16];

    /* Кол-во бит за все время */
    uint64_t bits_lo = (ctx->bytes << 3);
    uint64_t bits_hi = 0; // для 64-бит счётчика байт, верхние 64=0

    /* Формируем 16 байт длины: сначала 8 байт bits_hi=0, потом bits_lo big-endian */
    memset(sizedesc, 0, 8);
    sizedesc[8]  = (unsigned char)(bits_lo >> 56);
    sizedesc[9]  = (unsigned char)(bits_lo >> 48);
    sizedesc[10] = (unsigned char)(bits_lo >> 40);
    sizedesc[11] = (unsigned char)(bits_lo >> 32);
    sizedesc[12] = (unsigned char)(bits_lo >> 24);
    sizedesc[13] = (unsigned char)(bits_lo >> 16);
    sizedesc[14] = (unsigned char)(bits_lo >>  8);
    sizedesc[15] = (unsigned char)(bits_lo      );

    /* Сколько байт нужно добавить (pad) до блока 112 (mod 128). 
       Формула, аналогичная BitcoinCore:
         1 + ((239 - (ctx->bytes % 128)) % 128)
       Тут 1 — это байт 0x80, 16 — под длину, итого 17..(17+111)
    */
    size_t pad_len = 1 + ((239 - (ctx->bytes % 128)) % 128);

    sha512_update(ctx, pad, pad_len);         // добавляем 0x80 + (pad_len-1) нулей
    sha512_update(ctx, sizedesc, 16);         // добавляем 16 байт длины

    /* Теперь ctx->s содержит итоговый хеш, скопируем в hash (big-endian) */
    for (int i = 0; i < 8; i++) {
        write_be64(hash + i*8, ctx->s[i]);
    }
}

/* Сброс контекста к начальному состоянию (как после init). */
void sha512_reset(sha512_ctx* ctx)
{
    sha512_init(ctx);
}

/* Упрощённая обёртка: "сразу всё за один вызов" */
void sha512_hash(const char* input, char* output, uint32_t input_len)
{
    sha512_ctx ctx;
    unsigned char temp[SHA512_OUTPUT_SIZE];

    sha512_init(&ctx);
    sha512_update(&ctx, (const unsigned char*)input, input_len);
    sha512_finalize(&ctx, temp);

    /* 64 байта результата копируем в output */
    memcpy(output, temp, SHA512_OUTPUT_SIZE);
}
