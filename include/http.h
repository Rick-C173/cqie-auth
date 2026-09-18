//
// Created by Rick on 2026/9/13.
//
#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>

typedef struct
{
    char* data;
    size_t len;
} http_buf;

/* http_req 的可选行为 */
#define HTTP_FOLLOW    1u   /* 跟随 302 跳转 */
#define HTTP_QUIET     4u   /* 静默：网络错误不写日志（探测在线/抓劫持页用） */

/*
 * 发送请求。post 非 NULL 则为 POST（自动带
 * Content-Type: application/x-www-form-urlencoded; charset=UTF-8）。
 * referer 非 NULL 则附带 Referer 头。out 非 NULL 则接收响应体（以 \0 结尾）。
 * flags 见上方 HTTP_* 宏。
 * 返回 HTTP 状态码；网络错误返回 -1（错误详情打到 stderr，等价 curl -S）。
 */
long http_req_ex(const char* url, const char* post, const char* referer,
                 unsigned flags, http_buf* out);

/* 等价于 http_req_ex(url, post, referer, 0, out) */
long http_req(const char* url, const char* post, const char* referer, http_buf* out);

/*
 * GET url，**不跟随跳转**，把首跳响应的 Location 头拷进 loc（无则置空串）。
 * 用于 redirectortosuccess.jsp 这类"只要 302 目标"的场景。
 * 返回 HTTP 状态码；网络错误返回 -1。
 */
long http_req_location(const char* url, char* loc, size_t locsz);

/* 是否已在线（探测多个 generate_204） */
int is_online(void);

/*
 * 源 IP 绑定（--interface）：设置后所有 HTTP 请求（探测 + 认证）的 socket
 * 在 connect 前 bind 该 IPv4 地址，强制从指定网卡出去。多网卡/多 WAN 时
 * 防止认证流量走错出口。
 * ip 传 NULL/空串恢复默认（由路由表决定）；格式非法返回 -1，成功返回 0。
 * http_source_ip() 返回当前绑定值（未绑定时为空串）。
 */
int http_set_source_ip(const char* ip);
const char* http_source_ip(void);

/*
 * 后端初始化 / 释放。自实现 HTTP 客户端无需初始化，均为空操作。
 * 进程内各调用一次：http_global_init() 放在所有请求之前，
 * http_cleanup() 放在退出之前。http_global_init 返回 0 表示初始化失败。
 */
int http_global_init(void);
void http_cleanup(void);

#endif /* HTTP_H */
