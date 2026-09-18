//
// Created by Rick on 2026/9/13.
//
#include "rsa.h"
#include "bn.h"
#include "config.h"
#include <stdio.h>
#include <string.h>

/*
 * 锐捷 eportal 的 ohdave 风格 RSA：
 *   1. 明文 = "密码>mac"，整体反转后逐字节取 ASCII 值；
 *   2. 尾部补 0 使总长度为 chunk(126) 的整数倍（即数值最高位补零，不改变大小）；
 *   3. 从数组尾部开始每 126 字节取一块，按大端组成大数 m，计算 c = m^e mod n；
 *   4. 所有块的十六进制小写结果依次拼接，最后整体左侧补 '0' 到 4 的倍数
 *      （与原 shell 脚本的 awk 步骤完全一致）。
 */
int ruijie_rsa_encrypt(const char* pwd, const char* mac,
                       const char* e_hex, const char* n_hex,
                       char* out, size_t outsz)
{
    char plain[512];
    int len = snprintf(plain, sizeof plain, "%s>%s", pwd, mac);
    if (len <= 0 || (size_t)len >= sizeof plain) return 0;

    bn e, n;
    if (!bn_from_hex(&e, e_hex) || !bn_from_hex(&n, n_hex)) return 0;

#if RSA_PAD_PER_BLOCK
    /* 每块补足到模数的十六进制宽度 */
    size_t width = strlen(n_hex) + (strlen(n_hex) & 1);
#endif

    size_t used = 0;
    out[0] = 0;
    for (int off = 0; off < len; off += RSA_CHUNK)
    {
        int cnt = len - off;
        if (cnt > RSA_CHUNK) cnt = RSA_CHUNK;
        /* 第 off 块 = 明文末尾起第 off..off+cnt-1 字节（off=0 即最后一块） */
        char be[RSA_CHUNK];
        for (int i = 0; i < cnt; i++)
            be[cnt - 1 - i] = plain[len - 1 - off - i];

        bn m;
        memset(&m, 0, sizeof m);
        for (int i = 0; i < cnt; i++)
        {
            /* 大端：be[0] 为最高字节 */
            int bi = cnt - 1 - i;
            m.d[bi / 4] |= (uint32_t)(unsigned char)
            be[i] << ((bi % 4) * 8);
        }

        bn r;
        bn_modexp(&r, &m, &e, &n);

        char hex[BN_LIMBS * 8 + 8];
        bn_to_hex(&r, hex, sizeof hex);
        size_t hl = strlen(hex);
#if RSA_PAD_PER_BLOCK
        size_t blkpad = hl < width ? width - hl : 0;
#else
        size_t blkpad = 0;
#endif
        if (used + blkpad + hl + 1 >= outsz) return 0;
        if (blkpad)
        {
            memset(out + used, '0', blkpad);
            used += blkpad;
        }
        memcpy(out + used, hex, hl + 1);
        used += hl;
    }

#if !RSA_PAD_PER_BLOCK
    /* 整体左侧补 '0'，长度补到 4 的倍数（对应原脚本里的 awk 补零） */
    size_t pad = (4 - used % 4) % 4;
    if (pad)
    {
        if (used + pad + 1 > outsz) return 0;
        memmove(out + pad, out, used + 1);
        memset(out, '0', pad);
    }
#endif
    return 1;
}
