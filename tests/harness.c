//
// tests/harness.c - 供自检脚本调用的最小 CLI 包装
//
//   harness rsa <e_hex> <n_hex> <pwd> <mac>
//   harness urlencode <string>
//   harness field <field> <page_file>
//   harness service <name> <page_file>
//   harness redirect <page_file>
//   harness mac <query_string>
//   harness hexdec <hex_string>
//
#include "bn.h"
#include "rsa.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char* slurp(const char* path)
{
    static char buf[65536];
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = 0;
    fclose(f);
    return buf;
}

int main(int argc, char** argv)
{
    if (argc < 2) return 2;
    const char* cmd = argv[1];

    if (!strcmp(cmd, "rsa"))
    {
        if (argc < 6) return 2;
        static char out[1 << 16];
        if (!ruijie_rsa_encrypt(argv[4], argv[5], argv[2], argv[3], out, sizeof out))
        {
            puts("ENCRYPT_FAILED");
            return 1;
        }
        puts(out);
        return 0;
    }
    if (argc < 3) return 2;

    if (!strcmp(cmd, "urlencode"))
    {
        char* e = urlencode(argv[2]);
        puts(e ? e : "(null)");
        free(e);
        return 0;
    }
    if (!strcmp(cmd, "field"))
    {
        if (argc < 4) return 2;
        char out[512] = "";
        char* page = slurp(argv[3]);
        if (page && extract_field(page, argv[2], out, sizeof out)) puts(out);
        return 0;
    }
    if (!strcmp(cmd, "service"))
    {
        if (argc < 4) return 2;
        char out[512] = "";
        char* page = slurp(argv[3]);
        if (page && extract_service(page, argv[2], out, sizeof out)) puts(out);
        return 0;
    }
    if (!strcmp(cmd, "redirect"))
    {
        char* page = slurp(argv[2]);
        if (page)
        {
            char* r = fetch_redirect_url(page);
            if (r)
            {
                puts(r);
                free(r);
            }
        }
        return 0;
    }
    if (!strcmp(cmd, "mac"))
    {
        char out[128] = "";
        if (extract_mac(argv[2], out, sizeof out)) puts(out);
        return 0;
    }
    if (!strcmp(cmd, "hexdec"))
    {
        hex_print_decode(argv[2]);
        return 0;
    }
    return 2;
}
