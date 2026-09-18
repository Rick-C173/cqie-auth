//
// Created by Rick on 2026/9/13.
//
#ifndef RSA_H
#define RSA_H

#include <stddef.h>

/*
 * ohdave 风格 RSA 加密：明文 = pwd>mac，反转后按 126 字节小端分块，
 * 每块做 m^e mod n，结果十六进制（小写、左补0至4的倍数）以空格连接。
 * 成功返回 1。
 */
int ruijie_rsa_encrypt(const char* pwd, const char* mac,
                       const char* e_hex, const char* n_hex,
                       char* out, size_t outsz);

#endif /* RSA_H */

