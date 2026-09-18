//
// state.c - 状态文件读写
//
// 为什么不再把状态丢在当前目录：cron/路由器上 CWD 可能是 /（只读），
// 而且 userIndex 相当于会话令牌，不该留在随手可读的地方。
//
#define _POSIX_C_SOURCE 200809L   /* mkdir / rename / chmod */
#include "state.h"
#include "config.h"
#include "compat.h" /* Windows 下经此拿到 windows.h（MoveFileExA） */
#include "log.h"
#include "util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char g_dir[512];

/* 逐级 mkdir -p，权限 0700。Windows 下 / 与 \ 都认，切开后统一按 '/' 还原 */
static int mkdir_p(const char* path)
{
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char* p = tmp + 1; *p; p++)
    {
        if (*p != '/' && *p != '\\') continue;
        *p = 0;
        if (compat_mkdir(tmp) != 0)
        {
            struct stat st;
            if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode)) return 0;
        }
        *p = '/';
    }
    if (compat_mkdir(tmp) != 0)
    {
        struct stat st;
        if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode)) return 0;
    }
    return 1;
}

const char* state_init(const char* cli_dir)
{
    const char* dir = cli_dir;
    if (!dir || !dir[0]) dir = getenv("CQIE_STATE_DIR");
    if (!dir || !dir[0]) dir = STATE_DIR;

    if (mkdir_p(dir))
    {
        snprintf(g_dir, sizeof g_dir, "%s", dir);
    }
    else
    {
        LOG_WARN("状态目录 %s 不可用，回退到当前目录", dir);
        snprintf(g_dir, sizeof g_dir, ".");
    }
    LOG_DEBUG("状态目录: %s", g_dir);
    return g_dir;
}

const char* state_dir(void)
{
    if (!g_dir[0]) state_init(NULL);
    return g_dir;
}

int state_path(char* buf, size_t n, const char* name)
{
    int r = snprintf(buf, n, "%s/%s", state_dir(), name);
    return r > 0 && (size_t)r < n;
}

int state_write(const char* name, const char* content)
{
    char path[600], tmp[640];
    if (!state_path(path, sizeof path, name)) return 0;
    snprintf(tmp, sizeof tmp, "%s.tmp", path);

    FILE* f = fopen(tmp, "w");
    if (!f)
    {
        LOG_WARN("无法写入 %s: %s", tmp, strerror(errno));
        return 0;
    }
    fprintf(f, "%s\n", content);
    fclose(f);
    chmod(tmp, 0600); /* userIndex 是会话令牌，别让同机其他用户读（Windows 上仅只读位） */
#ifdef _WIN32
    /* MSVCRT 的 rename 目标已存在时失败，用 MoveFileEx 原子替换 */
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING))
#else
    if (rename(tmp, path) != 0)
#endif
    {
        LOG_WARN("重命名 %s -> %s 失败: %s", tmp, path, strerror(errno));
        remove(tmp);
        return 0;
    }
    LOG_DEBUG("已写入 %s (%zu 字节)", path, strlen(content));
    return 1;
}

int state_read(const char* name, char* out, size_t n)
{
    char path[600];
    if (!state_path(path, sizeof path, name)) return 0;
    if (file_read_trim(path, out, n) && out[0]) return 1;

    /* 兼容老版本：CWD 下的同名文件 */
    if (strcmp(state_dir(), ".") != 0 && file_read_trim(name, out, n) && out[0])
    {
        LOG_DEBUG("状态目录里没有 %s，使用当前目录的同名文件", name);
        return 1;
    }
    return 0;
}

void state_remove(const char* name)
{
    char path[600];
    if (!state_path(path, sizeof path, name)) return;
    if (remove(path) == 0) LOG_DEBUG("已删除 %s", path);
}
