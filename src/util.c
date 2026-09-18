//
// Created by Rick on 2026/9/13.
//
#include "util.h"
#include "compat.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* urlencode(const char* s)
{
    static const char hx[] = "0123456789ABCDEF";
    size_t n = 0;
    for (const char* p = s; *p; p++)
        n += (isalnum((unsigned char)*p) || strchr("._~-", *p)) ? 1 : 3;
    char* o = malloc(n + 1);
    if (!o) return NULL;
    char* w = o;
    for (const char* p = s; *p; p++)
    {
        unsigned char ch = (unsigned char)*p;
        if (isalnum(ch) || strchr("._~-", ch))
        {
            *w++ = (char)ch;
        }
        else
        {
            *w++ = '%';
            *w++ = hx[ch >> 4];
            *w++ = hx[ch & 15];
        }
    }
    *w = 0;
    return o;
}

int extract_field(const char* page, const char* field, char* out, size_t outsz)
{
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", field);
    const char* p = strstr(page, pat);
    if (!p) return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p) return 0;
    while (*++p == ' ');
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) out[i++] = *p++;
    out[i] = 0;
    return i > 0;
}

int extract_service(const char* page, const char* name, char* out, size_t outsz)
{
    const char* p = page;
    while ((p = strstr(p, "<option")) != NULL)
    {
        const char* gt = strchr(p, '>');
        const char* end = gt ? strstr(gt, "</option>") : NULL;
        if (gt && end)
        {
            size_t tl = (size_t)(end - (gt + 1));
            if (tl < 256)
            {
                char text[256];
                memcpy(text, gt + 1, tl);
                text[tl] = 0;
                if (strstr(text, name))
                {
                    const char* v = strstr(p, "value=\"");
                    if (v && v < gt)
                    {
                        v += 7;
                        size_t i = 0;
                        while (*v && *v != '"' && i + 1 < outsz) out[i++] = *v++;
                        out[i] = 0;
                        return 1;
                    }
                }
            }
        }
        p += 7;
    }
    return 0;
}

char* fetch_redirect_url(const char* page)
{
    const char* p = strstr(page, "location.href='");
    if (!p) return NULL;
    p += 15;
    const char* q = strchr(p, '\'');
    if (!q || q == p) return NULL;
    char* r = malloc((size_t)(q - p) + 1);
    if (!r) return NULL;
    memcpy(r, p, (size_t)(q - p));
    r[q - p] = 0;
    return r;
}

int extract_mac(const char* qs, char* out, size_t outsz)
{
    return extract_qs_param(qs, "mac", out, outsz);
}

int extract_qs_param(const char* qs, const char* name, char* out, size_t outsz)
{
    size_t nl = strlen(name);
    const char* m = NULL;
    const char* p = qs;
    /* 与 extract_mac 原行为一致：取最后一次出现；
     * 参数名必须完整（前面是 & 或串首，后面紧跟 =），避免 wlanmac 之类误匹配 */
    while ((p = strstr(p, name)) != NULL)
    {
        if ((p == qs || p[-1] == '&') && p[nl] == '=') m = p;
        p += nl;
    }
    if (!m) return 0;
    const char* v = m + nl + 1;
    size_t i = 0;
    while (*v && *v != '&' && i + 1 < outsz) out[i++] = *v++;
    out[i] = 0;
    return i > 0;
}

size_t hex_encode(const char* in, char* out, size_t outsz)
{
    static const char HEX[] = "0123456789abcdef";
    size_t n = strlen(in);
    if (n * 2 + 1 > outsz) return 0;
    for (size_t i = 0; i < n; i++)
    {
        unsigned char c = (unsigned char)in[i];
        out[i * 2] = HEX[c >> 4];
        out[i * 2 + 1] = HEX[c & 15];
    }
    out[n * 2] = 0;
    return n * 2;
}

size_t hex_decode(const char* s, char* out, size_t outsz)
{
    int hi = -1;
    size_t n = 0;
    for (const char* p = s; *p; p++)
    {
        unsigned char c = (unsigned char)*p;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue; /* xxd 跳过空白 */
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else break; /* 其它字符终止 */
        if (hi < 0)
        {
            hi = v;
        }
        else
        {
            if (n + 1 >= outsz) break;
            out[n++] = (char)((hi << 4) | v);
            hi = -1;
        }
    }
    if (n < outsz) out[n] = 0; /* 便于当字符串打印 */
    return n;
}

void hex_print_decode(const char* s)
{
    /* 实际输入是 userIndex（hex，约 54 字符 -> 27 字节），2048 已足够。
     * 原来是 8192 的 static（.bss），白白占着镜像。 */
    static char buf[2048];
    size_t n = hex_decode(s, buf, sizeof buf - 1);
    if (n) fwrite(buf, 1, n, stdout);
    putchar('\n');
}

int file_read_trim(const char* path, char* out, size_t outsz)
{
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    size_t n = fread(out, 1, outsz - 1, f);
    fclose(f);
    out[n] = 0;
    char* s = out;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char* e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = 0;
    if (s != out) memmove(out, s, strlen(s) + 1);
    return 1;
}

void msleep(int ms)
{
    if (ms <= 0) return;
    compat_msleep(ms);
}
