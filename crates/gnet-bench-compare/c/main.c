// Cross-language reference timings: libsodium running the same per-op
// categories as the Rust perf_gate, printed in the same ns/op format
// for side-by-side comparison with the gnet and Go-stdlib numbers.
//
// Each category uses best-of-10 sampling — same protocol as the Rust
// gate's `measure_best` and the Go bench's `measureBest`. A noisy CPU
// (powersave governor, GH Actions VM, contended host) affects all
// three runtimes proportionally; the ratio is what's meaningful.
//
// libsodium notes:
//   - X25519:    crypto_scalarmult_curve25519
//   - AEAD:      crypto_aead_chacha20poly1305_ietf_encrypt / _decrypt
//   - hex:       sodium_bin2hex / sodium_hex2bin
//   - BLAKE2b:   crypto_generichash (libsodium's variant; BLAKE2s isn't
//                in libsodium; ML-KEM-768 isn't either — skip with 0.0)
//
// Build:
//   make           # uses pkg-config (libsodium installed via brew/apt)
//
// Run:
//   ./bench

#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ITERS_X25519    1000
#define ITERS_AEAD      1000
#define ITERS_HEX       200000
#define ITERS_BLAKE     50000
#define BEST_OF         10

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// measure: average ns/op over `iters` iterations after a warm-up pass.
typedef void (*fn_t)(void *ctx);
static double measure(int iters, fn_t f, void *ctx) {
    int warm = iters / 4 + 1;
    for (int i = 0; i < warm; i++) f(ctx);
    uint64_t t0 = now_ns();
    for (int i = 0; i < iters; i++) f(ctx);
    uint64_t t1 = now_ns();
    return (double)(t1 - t0) / (double)iters;
}

static double measure_best(int iters, fn_t f, void *ctx) {
    double best = -1.0;
    for (int i = 0; i < BEST_OF; i++) {
        double sample = measure(iters, f, ctx);
        if (best < 0 || sample < best) best = sample;
    }
    return best;
}

// ===== X25519 =====
typedef struct {
    unsigned char sk[crypto_scalarmult_curve25519_SCALARBYTES];
    unsigned char pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char ss[crypto_scalarmult_curve25519_BYTES];
} x25519_ctx_t;

static void x25519_op(void *vctx) {
    x25519_ctx_t *c = (x25519_ctx_t *)vctx;
    crypto_scalarmult_curve25519(c->ss, c->sk, c->pk);
}

static double bench_x25519(void) {
    x25519_ctx_t c;
    randombytes_buf(c.sk, sizeof c.sk);
    crypto_scalarmult_curve25519_base(c.pk, c.sk);
    return measure_best(ITERS_X25519, x25519_op, &c);
}

// ===== AEAD ChaCha20-Poly1305 (IETF) seal =====
typedef struct {
    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    unsigned char aad[16];
    unsigned char pt[1400];
    unsigned char ct[1400 + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long ct_len;
} aead_ctx_t;

static void aead_seal_op(void *vctx) {
    aead_ctx_t *c = (aead_ctx_t *)vctx;
    crypto_aead_chacha20poly1305_ietf_encrypt(c->ct, &c->ct_len,
                                              c->pt, sizeof c->pt,
                                              c->aad, sizeof c->aad,
                                              NULL, c->nonce, c->key);
}

static void aead_open_op(void *vctx) {
    aead_ctx_t *c = (aead_ctx_t *)vctx;
    unsigned char pt_out[1400];
    unsigned long long pt_len;
    crypto_aead_chacha20poly1305_ietf_decrypt(pt_out, &pt_len,
                                              NULL,
                                              c->ct, c->ct_len,
                                              c->aad, sizeof c->aad,
                                              c->nonce, c->key);
}

static double bench_aead_seal(void) {
    aead_ctx_t c;
    randombytes_buf(c.key, sizeof c.key);
    memset(c.nonce, 0, sizeof c.nonce);
    memset(c.aad, 0, sizeof c.aad);
    memset(c.pt, 0xAB, sizeof c.pt);
    return measure_best(ITERS_AEAD, aead_seal_op, &c);
}

static double bench_aead_open(void) {
    aead_ctx_t c;
    randombytes_buf(c.key, sizeof c.key);
    memset(c.nonce, 0, sizeof c.nonce);
    memset(c.aad, 0, sizeof c.aad);
    memset(c.pt, 0xAB, sizeof c.pt);
    // pre-seal so we have a valid ciphertext for the open bench
    crypto_aead_chacha20poly1305_ietf_encrypt(c.ct, &c.ct_len,
                                              c.pt, sizeof c.pt,
                                              c.aad, sizeof c.aad,
                                              NULL, c.nonce, c.key);
    return measure_best(ITERS_AEAD, aead_open_op, &c);
}

// ===== Hex =====
typedef struct {
    unsigned char bin[32];
    char hex[65];
} hex_ctx_t;

static void hex_encode_op(void *vctx) {
    hex_ctx_t *c = (hex_ctx_t *)vctx;
    sodium_bin2hex(c->hex, sizeof c->hex, c->bin, sizeof c->bin);
}

static void hex_decode_op(void *vctx) {
    hex_ctx_t *c = (hex_ctx_t *)vctx;
    unsigned char out[32];
    size_t out_len;
    sodium_hex2bin(out, sizeof out, c->hex, 64, NULL, &out_len, NULL);
}

static double bench_hex_encode(void) {
    hex_ctx_t c;
    randombytes_buf(c.bin, sizeof c.bin);
    return measure_best(ITERS_HEX, hex_encode_op, &c);
}

static double bench_hex_decode(void) {
    hex_ctx_t c;
    randombytes_buf(c.bin, sizeof c.bin);
    sodium_bin2hex(c.hex, sizeof c.hex, c.bin, sizeof c.bin);
    return measure_best(ITERS_HEX, hex_decode_op, &c);
}

// ===== BLAKE2b (libsodium's variant; BLAKE2s is gnet's; compare =====
typedef struct {
    unsigned char input[64];
    unsigned char out[32];
} blake_ctx_t;

static void blake_op(void *vctx) {
    blake_ctx_t *c = (blake_ctx_t *)vctx;
    crypto_generichash(c->out, sizeof c->out, c->input, sizeof c->input, NULL, 0);
}

static double bench_blake(void) {
    blake_ctx_t c;
    randombytes_buf(c.input, sizeof c.input);
    return measure_best(ITERS_BLAKE, blake_op, &c);
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    printf("libsodium — cross-language reference timings\n");
    printf("Same per-op categories as the Rust perf_gate, best-of-10 samples.\n");
    printf("(ML-KEM-768 and BLAKE2s are not in libsodium; skipped here —\n");
    printf(" the Go bench covers ML-KEM-768; gnet has BLAKE2s natively.)\n\n");
    printf("  %-32s  %12s\n", "category", "libsodium ns/op");
    printf("  ----------------------------------------------\n");
    printf("  %-32s  %12.1f\n", "X25519 ECDH", bench_x25519());
    printf("  %-32s  %12.1f\n", "AEAD seal 1400B", bench_aead_seal());
    printf("  %-32s  %12.1f\n", "AEAD open 1400B", bench_aead_open());
    printf("  %-32s  %12.1f\n", "Hex encode 32B", bench_hex_encode());
    printf("  %-32s  %12.1f\n", "Hex decode 32B", bench_hex_decode());
    printf("  %-32s  %12.1f\n", "BLAKE2b-256 64B", bench_blake());

    return 0;
}
