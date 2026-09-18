//
// log.c - 分级日志实现
//
// 两条独立通道：
//   1) log_emit()   —— 终端/文件的分级日志，受 -v/-q 控制（人看的）
//   2) log_status() —— 每次运行一条结果到 syslog（机器看的审计轨迹，
//                      OpenWrt 上由 logd 收，`logread` 查看）
//
#define _POSIX_C_SOURCE 200809L   /* clock_gettime（compat 层的 POSIX 实现也要） */
#include "log.h"
#include "config.h"
#include "compat.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if USE_SYSLOG
#include <syslog.h>
#endif

static int g_level = LOG_LEVEL_WARN;
static FILE* g_fp;
static long long g_start_ms; /* 程序启动时的单调时钟，算累计耗时用 */
static int g_started;
static char g_first_err[256]; /* 本次运行第一条 ERROR，给 syslog 报告根因用 */
static int g_syslog_on = 1;   /* --no-syslog 运行期关闭 syslog 状态行 */

const char* log_first_error(void) { return g_first_err; }

void log_set_syslog(int on) { g_syslog_on = on; }

#if USE_SYSLOG
void log_status(const char* fmt, ...)
{
    static int opened;
    if (!g_syslog_on) return; /* --no-syslog：本次运行不留痕 */
    if (!opened)
    {
        /* LOG_PID 让 `logread` 里能按 pid 把同一次运行的多行归到一起。
         * 刻意不加 LOG_CONS：没有 /dev/log 时不要往控制台喷东西。 */
        openlog(SYSLOG_IDENT, LOG_PID | LOG_NDELAY, LOG_USER);
        opened = 1;
    }
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    syslog(SYSLOG_LEVEL, "%s", msg);
}
#else
void log_status(const char* fmt, ...) { (void)fmt; }
#endif

static const char* level_name(int level)
{
    switch (level)
    {
    case LOG_LEVEL_ERROR: return "ERROR";
    case LOG_LEVEL_WARN: return "WARN ";
    case LOG_LEVEL_INFO: return "INFO ";
    case LOG_LEVEL_DEBUG: return "DEBUG";
    default: return "TRACE";
    }
}

long log_tick_ms(void)
{
    if (!g_started) return 0;
    return (long)(compat_mono_ms() - g_start_ms);
}

void log_init(int level, const char* file)
{
    g_level = level;
    g_start_ms = compat_mono_ms();
    g_started = 1;
    if (file && file[0])
    {
        g_fp = fopen(file, "a"); /* 追加，便于 cron 累积 */
        if (!g_fp)
            fprintf(stderr, "[log] 无法写入日志文件 %s，仅输出到终端\n", file);
    }
}

void log_set_level(int level) { g_level = level; }
int log_level(void) { return g_level; }

/* 过滤规则集中在这里，log_emit 与 log_enabled 共用，避免两处各写一份走样 */
int log_enabled(int level)
{
    if (g_level == LOG_LEVEL_QUIET) return level == LOG_LEVEL_ERROR;
    return level <= g_level;
}

void log_close(void)
{
    if (g_fp)
    {
        fclose(g_fp);
        g_fp = NULL;
    }
#if USE_SYSLOG
    closelog();
#endif
}

void log_emit(int level, const char* fmt, ...)
{
    if (!log_enabled(level)) return;

    /* 前缀：[时:分:秒.毫秒 +累计秒] 级别 */
    int hh, mm, ss, msec;
    compat_localtime(&hh, &mm, &ss, &msec);
    long tick = log_tick_ms();
    char head[64];
    snprintf(head, sizeof head, "[%02d:%02d:%02d.%03d +%ld.%03lds] %s ",
             hh, mm, ss, msec,
             tick / 1000, tick % 1000, level_name(level));

    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    /* 记下第一条 ERROR 当根因，供 syslog 那条状态行说明失败原因。
     * 有意截断到 256 字节（状态行不需要全文），显式写比 snprintf 更明确。 */
    if (level == LOG_LEVEL_ERROR && !g_first_err[0])
    {
        size_t n = strlen(msg);
        if (n >= sizeof g_first_err) n = sizeof g_first_err - 1;
        memcpy(g_first_err, msg, n);
        g_first_err[n] = 0;
    }

    fprintf(stderr, "%s%s\n", head, msg);
    if (g_fp)
    {
        fputs(head, g_fp);
        fputs(msg, g_fp);
        fputc('\n', g_fp);
        fflush(g_fp);
    }
}
