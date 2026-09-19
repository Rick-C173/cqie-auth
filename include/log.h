//
// log.h - 分级日志（诊断信息走 stderr，结果仍走 stdout）
//
#ifndef LOG_H
#define LOG_H

#include <stddef.h>

/*
 * 级别数值越大越啰嗦，默认 LOG_WARN。
 * 设计约定：**结果**（userIndex、注销响应、已在线…）照旧走 stdout，方便管道/脚本；
 * 所有**诊断信息**走 stderr，可用 --log 落文件，不污染脚本输出。
 */
enum
{
    LOG_LEVEL_QUIET = -1, /* -q：只输出错误 */
    LOG_LEVEL_ERROR = 0, /* 出错 */
    LOG_LEVEL_WARN = 1, /* 警告（默认） */
    LOG_LEVEL_INFO = 2, /* -v：流程细节（queryString、公钥、userIndex…） */
    LOG_LEVEL_DEBUG = 3, /* -vv：HTTP 状态/耗时、表单字段、状态文件路径 */
    LOG_LEVEL_TRACE = 4 /* -vvv：请求头、响应体全文 */
};

/* level 为 LOG_LEVEL_*；file 非 NULL 时同时追加写入该文件 */
void log_init(int level, const char* file);
void log_close(void);

/*
 * 该级别当前是否会被输出（过滤规则与 log_emit 一致）。
 * 用于在**构造日志参数之前**提前退出：像逐字符扫描 3KB 表单这种活，
 * 级别不够时不该白做。典型用法：
 *     if (!log_enabled(LOG_LEVEL_DEBUG)) return;
 */
int log_enabled(int level);

/* 自进程启动以来的毫秒数，用于日志里的耗时统计 */
long log_tick_ms(void);

/*
 * 写一条"认证状态"到系统日志（syslog；OpenWrt 上是 logd → `logread`）。
 *
 * 与 log_emit 是两条独立通道：
 *   - 不受 -q / -v 影响，**每次都写**（这是留给 logread 的审计轨迹）
 *   - 只进 syslog，不写 stderr（人看的细节已由 LOG_INFO 覆盖，避免刷屏）
 *   - 可用 log_set_syslog(0) 运行期关闭（对应 --no-syslog）
 * USE_SYSLOG=0 时是空操作。
 */
void log_status(const char* fmt, ...);

/* 运行期开关 syslog 状态行（--no-syslog）；默认开启（USE_SYSLOG=1 时） */
void log_set_syslog(int on);

/*
 * 本次运行遇到的**第一条** ERROR 消息；没有则返回空串。
 * 只记第一条：后续往往是对同一次失败的补充输出（如"响应内容: ..."），
 * 第一条才是根因。供 log_status 报告失败原因。
 */
const char* log_first_error(void);

/* 内部使用，一般用下面的宏 */
void log_emit(int level, const char* fmt, ...);

#define LOG_ERROR(...) log_emit(LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_WARN(...)  log_emit(LOG_LEVEL_WARN,  __VA_ARGS__)
#define LOG_INFO(...)  log_emit(LOG_LEVEL_INFO,  __VA_ARGS__)
#define LOG_DEBUG(...) log_emit(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_TRACE(...) log_emit(LOG_LEVEL_TRACE, __VA_ARGS__)

#endif /* LOG_H */
