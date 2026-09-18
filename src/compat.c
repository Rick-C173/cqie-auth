//
// compat.c - 平台差异的集中实现（socket 初始化/非阻塞/SO_ERROR、时间、睡眠）
//
// 网络层的双平台差异全部收敛在 http_min.c / auth.c -> compat.h -> 本文件这一条线上。
//
#define _POSIX_C_SOURCE 200809L /* fcntl / clock_gettime / nanosleep / localtime_r */

#include "compat.h"

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

int compat_stdin_is_tty(void) { return _isatty(_fileno(stdin)); }

void compat_echo(int on)
{
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    if (!GetConsoleMode(h, &mode)) return; /* 输入被重定向时无控制台，静默 */
    if (on) mode |= ENABLE_ECHO_INPUT;
    else    mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(h, mode);
}

#else /* POSIX */

#include <stdio.h>
#include <sys/stat.h> /* mkdir */
#include <time.h>
#include <unistd.h>   /* isatty */
#include <termios.h>  /* 密码输入关回显 */

int compat_stdin_is_tty(void) { return isatty(0); }

void compat_echo(int on)
{
    struct termios t;
    if (tcgetattr(0, &t) != 0) return; /* 输入被重定向时非终端，静默 */
    if (on) t.c_lflag |= ECHO;
    else    t.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(0, TCSANOW, &t);
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

#endif
