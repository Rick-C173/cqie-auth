//
// compat.c - 平台差异的集中实现（socket 初始化/非阻塞/SO_ERROR、时间、睡眠）
//
// 网络层的双平台差异全部收敛在 http_min.c / auth.c -> compat.h -> 本文件这一条线上。
//
#define _POSIX_C_SOURCE 200809L /* fcntl / clock_gettime / nanosleep / localtime_r */

#include "compat.h"
#include "config.h" /* POSIX 默认配置/状态路径宏 */

#ifdef _WIN32

#include <direct.h>  /* _mkdir */
#include <io.h>      /* _isatty */
#include <stdio.h>   /* stdin/_fileno */

int sock_init(void)
{
    static int done;
    if (!done)
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
        done = 1;
    }
    return 1;
}

void sock_quit(void) { WSACleanup(); }

int sock_take_error(sock_t fd)
{
    int err = -1;
    int el = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&err, &el) != 0) return -1;
    return err;
}

int sock_nonblock(sock_t fd, int on)
{
    u_long mode = on ? 1 : 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
}

long long compat_mono_ms(void) { return (long long)GetTickCount64(); }

void compat_localtime(int* hour, int* min, int* sec, int* msec)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    *hour = st.wHour;
    *min = st.wMinute;
    *sec = st.wSecond;
    *msec = st.wMilliseconds;
}

void compat_msleep(int ms) { Sleep((DWORD)ms); }

int compat_mkdir(const char* path) { return _mkdir(path); }

void compat_console_utf8(void)
{
    /* 源码字符串是 UTF-8；控制台默认按 OEM/GBK(936) 解码会乱码。
     * 切到 65001(CP_UTF8) 后 conhost 按 UTF-8 渲染，PowerShell/cmd 直显中文。 */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

int compat_exe_dir(char* out, size_t n)
{
    wchar_t wpath[600];
    DWORD len = GetModuleFileNameW(NULL, wpath, (DWORD)(sizeof wpath / sizeof *wpath));
    if (len == 0 || len >= sizeof wpath / sizeof *wpath) return 0;
    /* 程序内字符串统一 UTF-8；W 版 API + 显式转换保证中文/空格路径安全 */
    int need = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, (int)n, NULL, NULL);
    if (need <= 0 || (size_t)need > n) return 0;
    char* slash = strrchr(out, '\\');
    if (!slash) return 0;
    *slash = 0;
    return out[0] ? 1 : 0;
}

int compat_default_config(char* out, size_t n)
{
    char dir[600];
    if (!compat_exe_dir(dir, sizeof dir)) return 0;
    int r = snprintf(out, n, "%s\\cqie-auth.conf", dir);
    return r > 0 && (size_t)r < n;
}

int compat_default_state(char* out, size_t n)
{
    char dir[600];
    if (!compat_exe_dir(dir, sizeof dir)) return 0;
    int r = snprintf(out, n, "%s\\state", dir);
    return r > 0 && (size_t)r < n;
}

void compat_stdin_is_tty(void) { return _isatty(_fileno(stdin)); }

void compat_echo(int on)
{
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    if (!GetConsoleMode(h, &mode)) return; /* 输入被重定向时无控制台，静默 */
    if (on) mode |= ENABLE_ECHO_INPUT;
    else    mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(h, mode);
}

void* compat_lock_file(const char* path)
{
    /* 共享模式 0 = 独占：第二个实例打开直接失败；句柄随进程退出自动释放 */
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    return h;
}

void compat_unlock_file(void* h)
{
    if (h) CloseHandle((HANDLE)h);
}

#else /* POSIX */

#include <stdio.h>
#include <string.h>  /* strrchr（exe 目录切分） */
#include <sys/stat.h> /* mkdir */
#include <time.h>
#include <unistd.h>   /* isatty */
#include <termios.h>  /* 密码输入关回显 */
#include <fcntl.h>    /* 单实例锁 */
#include <sys/file.h> /* flock */

int compat_stdin_is_tty(void) { return isatty(0); }

void compat_echo(int on)
{
    struct termios t;
    if (tcgetattr(0, &t) != 0) return; /* 输入被重定向时非终端，静默 */
    if (on) t.c_lflag |= ECHO;
    else    t.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(0, TCSANOW, &t);
}

void* compat_lock_file(const char* path)
{
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return NULL;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) /* 非阻塞：已被持有立即失败 */
    {
        close(fd);
        return NULL;
    }
    return (void*)(intptr_t)fd;
}

void compat_unlock_file(void* h)
{
    if (h) close((int)(intptr_t)h);
}

int sock_take_error(sock_t fd)
{
    int err = -1;
    socklen_t el = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0) return -1;
    return err;
}

int sock_nonblock(sock_t fd, int on)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK)) < 0 ? -1 : 0;
}

long long compat_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void compat_localtime(int* hour, int* min, int* sec, int* msec)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    *hour = tm.tm_hour;
    *min = tm.tm_min;
    *sec = tm.tm_sec;
    *msec = (int)(ts.tv_nsec / 1000000);
}

void compat_msleep(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

int compat_mkdir(const char* path) { return mkdir(path, 0700); }

void compat_console_utf8(void) { /* POSIX 终端本就是 UTF-8，无需处理 */ }

int compat_exe_dir(char* out, size_t n)
{
    ssize_t len = readlink("/proc/self/exe", out, n - 1);
    if (len <= 0) return 0;
    out[len] = 0;
    char* slash = strrchr(out, '/');
    if (!slash) return 0;
    *slash = 0;
    return out[0] ? 1 : 0;
}

int compat_default_config(char* out, size_t n)
{
    (void)out; (void)n;
    return 0; /* POSIX：返回空，调用方回退编译期宏/环境变量链 */
}

int compat_default_state(char* out, size_t n)
{
    (void)out; (void)n;
    return 0; /* POSIX：返回空，state_init 内部走 环境变量→宏 链 */
}

#endif
