//
// Created by Rick on 2026/9/13.
//
#include "bn.h"
#include <string.h>
#include <stdio.h>

static void bn_zero(bn* a) { memset(a, 0, sizeof *a); }

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int bn_from_hex(bn* a, const char* hex)
{
    bn_zero(a);
    size_t n = strlen(hex);
    /* 一个 limb 4 字节 = 8 个十六进制字符，最多 8*BN_LIMBS = 512 个字符
     * (BN_LIMBS=64 → 容量 2048 bit；真机模数 256 字符 = 1024 bit，只占低一半 limb) */
    if (n == 0 || n > 8 * BN_LIMBS) return 0;
    size_t nbytes = (n + 1) / 2;
    for (size_t j = 0; j < nbytes; j++)
    {
        /* j: 从最低字节起 */
        int lv = hexval((unsigned char)hex[n - 1 - 2 * j]);
        int hv = (n >= 2 * j + 2) ? hexval((unsigned char)hex[n - 2 - 2 * j]) : 0;
        if (lv < 0 || hv < 0) return 0;
        a->d[j / 4] |= (uint32_t)((hv << 4) | lv) << ((j % 4) * 8);
    }
    return 1;
}

static int bn_cmp(const bn* a, const bn* b)
{
    for (int i = BN_LIMBS - 1; i >= 0; i--)
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    return 0;
}

/* a -= b（要求 a >= b） */
static void bn_sub(bn* a, const bn* b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < BN_LIMBS; i++)
    {
        uint64_t t = (uint64_t)a->d[i] - b->d[i] - borrow;
        a->d[i] = (uint32_t)t;
        borrow = (t >> 32) & 1;
    }
}

void bn_mod(const bn* n, const uint32_t* x, int xn, bn* r)
{
    bn_zero(r);
    int top = xn - 1;
    while (top >= 0 && x[top] == 0) top--;
    if (top < 0) return;
    for (int i = top; i >= 0; i--)
    {
        for (int b = 31; b >= 0; b--)
        {
            uint32_t carry = 0;
            for (int k = 0; k < BN_LIMBS; k++)
            {
                /* r = r*2 + bit */
                uint32_t nc = r->d[k] >> 31;
                r->d[k] = (r->d[k] << 1) | carry;
                carry = nc;
            }
            r->d[0] |= (x[i] >> b) & 1;
            /* carry=1 表示 r 已溢出 BN_LIMBS*32 位（模数接近本类型上限时会遇到），
             * 此时 r >= n 必然成立；减一次即可，因为 r < 2n */
            if (carry || bn_cmp(r, n) >= 0) bn_sub(r, n);
        }
    }
}

void bn_mul(uint32_t* out, const bn* a, const bn* b)
{
    memset(out, 0, 2 * BN_LIMBS * 4);
    for (int i = 0; i < BN_LIMBS; i++)
    {
        uint64_t carry = 0;
        for (int j = 0; j < BN_LIMBS; j++)
        {
            uint64_t t = (uint64_t)a->d[i] * b->d[j] + out[i + j] + carry;
            out[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        for (int k = i + BN_LIMBS; carry && k < 2 * BN_LIMBS; k++)
        {
            uint64_t t = (uint64_t)out[k] + carry;
            out[k] = (uint32_t)t;
            carry = t >> 32;
        }
    }
}

void bn_modexp(bn* r, const bn* m, const bn* e, const bn* n)
{
    bn base;
    bn_mod(n, m->d, BN_LIMBS, &base);
    bn_zero(r);
    r->d[0] = 1;
    uint32_t prod[2 * BN_LIMBS];
    int top = BN_LIMBS - 1;
    while (top >= 0 && e->d[top] == 0) top--;
    for (int i = top; i >= 0; i--)
    {
        for (int b = 31; b >= 0; b--)
        {
            bn_mul(prod, r, r);
            bn_mod(n, prod, 2 * BN_LIMBS, r); /* r = r^2 */
            if ((e->d[i] >> b) & 1)
            {
                bn_mul(prod, r, &base);
                bn_mod(n, prod, 2 * BN_LIMBS, r);
            }
        }
    }
}

void bn_to_hex(const bn* a, char* out, size_t outsz)
{
    int top = BN_LIMBS - 1;
    while (top > 0 && a->d[top] == 0) top--;
    if (a->d[top] == 0)
    {
        /* 整个数为 0 */
        if (outsz < 2) return;
        out[0] = '0';
        out[1] = 0;
        return;
    }
    size_t pos = (size_t)snprintf(out, outsz, "%x", a->d[top]);
    for (int i = top - 1; i >= 0 && pos < outsz; i--)
        pos += (size_t)snprintf(out + pos, outsz - pos, "%08x", a->d[i]);
}
