//
// Created by Rick on 2026/9/13.
//
#ifndef BN_H
#define BN_H

#include <stdint.h>
#include <stddef.h>

/* 64*4 = 256 字节 = 2048 bit，足以容纳 1024 bit / 2048 bit 的 RSA 模数 */
#define BN_LIMBS 64

typedef struct
{
    uint32_t d[BN_LIMBS];
} bn;

/* 十六进制字符串 -> bn，成功返回 1 */
int bn_from_hex(bn* a, const char* hex);

/* out(2*BN_LIMBS limbs) = a * b */
void bn_mul(uint32_t* out, const bn* a, const bn* b);

/* r = x mod n，x 为 xn 个 limb 的大数 */
void bn_mod(const bn* n, const uint32_t* x, int xn, bn* r);

/* r = m^e mod n */
void bn_modexp(bn* r, const bn* m, const bn* e, const bn* n);

/* bn -> 小写十六进制，不补前导零（0 输出 "0"） */
void bn_to_hex(const bn* a, char* out, size_t outsz);

#endif /* BN_H */
