//
// http_min.c - 极简 HTTP/1.1 客户端（自实现 socket，不依赖任何库）
//
// 为什么自己写：libcurl + mbedtls 静态链接后占 833KB，是最终二进制的 93%，
// 而本项目 PORTAL_URL / PROBE_URL / PROBE_204_LIST 全是 http:// 明文，
// TLS 栈完全用不到。这里只实现"GET/POST + 少量 header + 读 body + 可选跟随 302"，
// 体积从 899KB 降到约 130KB。
//
// 已知不做的事（都是本项目用不到的）：
//   - 不支持 https（只认 http://）
//   - 不解析代理环境变量
//   - 每次请求新建连接，不发 keep-alive：portal 是内网 IP，connect 亚毫秒级，
//     复用省不了几毫秒；更关键的是无 Content-Length 的响应（AC 劫持页）要靠
//     "读到对端关闭"收尾，声明 keep-alive 会等来超时。Connection: close 是功能需要。
//
// 请求头按浏览器形态补齐（登录页 JS 用 jQuery ajax 提交）：POST 带
// X-Requested-With/Origin/JSON Accept，GET 带导航 Accept，全部带 Accept-Language。
// 纯加头字段，不增加任何耗时；Accept-Encoding 刻意不发（会引来 gzip，解不动）。
//
// 跨平台：socket/非阻塞/poll/错误码差异全部走 include/compat.h（Winsock2 或 POSIX）。
#define _POSIX_C_SOURCE 200809L   /* getaddrinfo / poll / strncasecmp */

#include "http.h"
#include "config.h"
#include "compat.h"
#include "log.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <ws2tcpip.h> /* inet_pton */
#else
#include <arpa/inet.h> /* inet_pton */
#endif

#define HDR_CAP   4096            /* 响应头上限，AC 的头很短 */
#define BODY_MAX  (256 * 1024)    /* 响应体防御性上限 */
#define MAX_HOPS  5               /* 跟随跳转的最大次数 */

/* jQuery $.ajax 的默认 Accept（登录页 JS 就是这么发的） */
#define ACCEPT_XHR "application/json, text/javascript, */*; q=0.01"
/* Chrome 导航请求的 Accept（截去冷门项，长度优先） */
#define ACCEPT_NAV "text/html,application/xhtml+xml,application/xml;q=0.9," \
                   "image/avif,image/webp,*/*;q=0.8"

typedef struct
{
    char host[256];
    char path[1024];
    int port;
} url_t;

/* ---------------------------------------------------------------- 工具 */

static const char* user_agent(void)
{
    static char buf[160];
    if (buf[0]) return buf;
    const char* cfg = HTTP_USER_AGENT;
    if (cfg && cfg[0])
        snprintf(buf, sizeof buf, "%s", cfg);
    else
        /* 本 AC 在缺少 UA 时返回 200 + 空 body，UA 的具体值不影响它的判断。 */
        snprintf(buf, sizeof buf, "%s", HTTP_USER_AGENT_FALLBACK);
    return buf;
}

static long remain_ms(long deadline)
{
    long left = deadline - log_tick_ms();
    return left < 0 ? 0 : left;
}

/* 往 b 追加数据（保持 NUL 结尾） */
static int buf_append(http_buf* b, const void* p, size_t n)
{
    char* nd = realloc(b->data, b->len + n + 1);
    if (!nd) return 0;
    b->data = nd;
    memcpy(nd + b->len, p, n);
    b->len += n;
    nd[b->len] = 0;
    return 1;
}

/* 只支持 http://，解析出 host / port / path（含 ?query） */
static int parse_url(const char* url, url_t* u)
{
    if (strncmp(url, "http://", 7) != 0) return 0;
    const char* p = url + 7;
    const char* slash = strchr(p, '/');
    const char* host_end = slash ? slash : p + strlen(p);

    const char* colon = NULL;
    for (const char* q = p; q < host_end; q++)
        if (*q == ':') colon = q;

    size_t hl = (size_t)((colon ? colon : host_end) - p);
    if (hl == 0 || hl >= sizeof u->host) return 0;
    memcpy(u->host, p, hl);
    u->host[hl] = 0;

    u->port = 80;
    if (colon)
    {
        int pv = atoi(colon + 1);
        if (pv > 0 && pv < 65536) u->port = pv;
    }

    if (slash) snprintf(u->path, sizeof u->path, "%s", slash);
    else snprintf(u->path, sizeof u->path, "/");
    return 1;
}

/* 非阻塞 connect + poll 控制超时；成功返回 fd，失败 SOCK_INVALID */
/* ---- 源 IP 绑定（--interface）：多网卡/多 WAN 时把认证流量钉在指定出口 ---- */
static char g_src_ip[64];

int http_set_source_ip(const char* ip)
{
    if (!ip || !ip[0])
    {
        g_src_ip[0] = 0; /* 空 = 恢复默认（由路由表决定出口） */
        return 0;
    }
    struct in_addr tmp;
    if (inet_pton(AF_INET, ip, &tmp) != 1) return -1; /* 非法 IPv4 地址 */
    snprintf(g_src_ip, sizeof g_src_ip, "%s", ip);
    return 0;
}

const char* http_source_ip(void) { return g_src_ip; }

static sock_t connect_timeout(const char* host, int port, long timeout_ms)
{
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    sock_t fd = SOCK_INVALID;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) return SOCK_INVALID;

    for (ai = res; ai; ai = ai->ai_next)
    {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == SOCK_INVALID) continue;

        if (sock_nonblock(fd, 1) != 0)
        {
            sock_close(fd);
            fd = SOCK_INVALID;
            continue;
        }

        /* 源 IP 绑定：connect 前 bind 指定地址，强制出口。portal/探测都是
         * IPv4，目标解析出 IPv6 时 bind 会失败跳过该地址（实际部署用不到）。 */
        if (g_src_ip[0])
        {
            struct sockaddr_in src;
            memset(&src, 0, sizeof src);
            src.sin_family = AF_INET;
            inet_pton(AF_INET, g_src_ip, &src.sin_addr);
            if (bind(fd, (struct sockaddr*)&src, sizeof src) != 0)
            {
                LOG_DEBUG("[http] bind 源 IP %s 失败，跳过该地址", g_src_ip);
                sock_close(fd);
                fd = SOCK_INVALID;
                continue;
            }
        }

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0)
        {
            /* POSIX 报 EINPROGRESS，Winsock 报 WSAEWOULDBLOCK（见 compat.h） */
            if (sock_errno != SOCK_ERR_INPROGRESS)
            {
                sock_close(fd);
                fd = SOCK_INVALID;
                continue;
            }
            struct pollfd pfd = {(int)fd, POLLOUT, 0};
            if (poll(&pfd, 1, (int)timeout_ms) <= 0)
            {
                sock_close(fd);
                fd = SOCK_INVALID;
                continue;
            }
            if (sock_take_error(fd) != 0)
            {
                sock_close(fd);
                fd = SOCK_INVALID;
                continue;
            }
        }
        /* 恢复阻塞模式，后续用 poll 卡超时 */
        sock_nonblock(fd, 0);
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static int send_all(sock_t fd, const char* buf, size_t len, long deadline)
{
    size_t off = 0;
    while (off < len)
    {
        long left = remain_ms(deadline);
        if (left <= 0) return 0;
        struct pollfd pfd = {(int)fd, POLLOUT, 0};
        if (poll(&pfd, 1, (int)left) <= 0) return 0;
        int w = (int)send(fd, buf + off, len - off, 0);
        if (w < 0)
        {
            if (sock_errno == SOCK_ERR_INTR) continue;
            return 0;
        }
        if (w == 0) return 0;
        off += (size_t)w;
    }
    return 1;
}

/* 读一块：超时/出错 -1，对端关闭 0 */
static ssize_t recv_some(sock_t fd, char* buf, size_t cap, long deadline)
{
    long left = remain_ms(deadline);
    if (left <= 0) return -1;
    struct pollfd pfd = {(int)fd, POLLIN, 0};
    if (poll(&pfd, 1, (int)left) <= 0) return -1;
    for (;;)
    {
        int r = (int)recv(fd, buf, cap, 0);
        if (r < 0 && sock_errno == SOCK_ERR_INTR) continue;
        return r;
    }
}

/*
 * 读取响应头直到出现空行 \r\n\r\n。
 * 返回本次读入 buf 的总字节数（通常已含 body 前段），失败 -1；
 * *hdr_end = body 在 buf 中的起始偏移。
 *
 * 注意：必须在**整个**缓冲区里找 \r\n\r\n，不能只看末尾 ——
 * 一次 recv 往往連响应头和 body 一起收到（实测 361 字节一把到齐），
 * 此时分隔符在缓冲区中间，只看末尾会误判成"头还没读完"。
 */
static ssize_t read_headers(sock_t fd, char* buf, size_t cap, long deadline, size_t* hdr_end)
{
    size_t n = 0;
    size_t scanned = 0;
    for (;;)
    {
        /* 只重扫新增部分的边界，避免每轮从头 O(n^2) */
        size_t start = scanned > 3 ? scanned - 3 : 0;
        for (size_t i = start; i + 4 <= n; i++)
        {
            if (memcmp(buf + i, "\r\n\r\n", 4) == 0)
            {
                *hdr_end = i + 4;
                return (ssize_t)n;
            }
        }
        scanned = n;
        if (n + 1 >= cap) return -1; /* 头太大，放弃 */
        ssize_t r = recv_some(fd, buf + n, cap - 1 - n, deadline);
        if (r <= 0) return -1; /* 超时，或对端提前关闭 */
        n += (size_t)r;
    }
}

/* 在响应头里查 header（大小写不敏感） */
static int hdr_get(const char* hdr, const char* name, char* out, size_t outsz)
{
    size_t nl = strlen(name);
    const char* eol = strstr(hdr, "\r\n"); /* 跳过状态行 */
    if (!eol) return 0;
    const char* p = eol + 2;

    while (*p && strncmp(p, "\r\n", 2) != 0)
    {
        const char* e2 = strstr(p, "\r\n");
        if (!e2) break;
        if (strncasecmp(p, name, nl) == 0 && p[nl] == ':')
        {
            const char* v = p + nl + 1;
            while (v < e2 && (*v == ' ' || *v == '\t')) v++;
            size_t i = 0;
            while (v < e2 && i + 1 < outsz) out[i++] = *v++;
            out[i] = 0;
            return 1;
        }
        p = e2 + 2;
    }
    return 0;
}

static int parse_status(const char* hdr)
{
    const char* sp = strchr(hdr, ' ');
    return sp ? atoi(sp + 1) : -1;
}

/*
 * 把 body 原始字节收进 raw。
 * clen >= 0 时按 Content-Length 精确读取；否则读到对端关闭。
 * 先原样收全（chunked 的解码在内存里做，避免边读边解绕缓冲区）。
 */
static int read_raw_body(sock_t fd, const char* first, size_t first_len,
                         long clen, long deadline, http_buf* raw)
{
    char tmp[4096];

    if (clen >= 0)
    {
        size_t total = (size_t)clen;
        size_t take = first_len < total ? first_len : total;
        if (take && !buf_append(raw, first, take)) return 0;
        size_t got = take;
        while (got < total)
        {
            size_t want = total - got;
            if (want > sizeof tmp) want = sizeof tmp;
            ssize_t r = recv_some(fd, tmp, want, deadline);
            if (r <= 0) return 0;
            if (!buf_append(raw, tmp, (size_t)r)) return 0;
            got += (size_t)r;
        }
        return 1;
    }

    /* 无 Content-Length：读到对端关闭（我们发了 Connection: close） */
    if (first_len && !buf_append(raw, first, first_len)) return 0;
    for (;;)
    {
        ssize_t r = recv_some(fd, tmp, sizeof tmp, deadline);
        if (r < 0) return 0;
        if (r == 0) return 1;
        if (raw->len + (size_t)r > BODY_MAX) return 0;
        if (!buf_append(raw, tmp, (size_t)r)) return 0;
    }
}

/* 内存里解 chunked：<hex 长度>\r\n<data>\r\n ... 0\r\n\r\n */
static int dechunk(const char* in, size_t inlen, http_buf* out)
{
    size_t i = 0;
    for (;;)
    {
        long sz = 0;
        int digits = 0;
        for (; i < inlen;)
        {
            char c = in[i++];
            if (c == '\r') continue;
            if (c == '\n') break;
            int v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else return 0;
            if (++digits > 8) return 0;
            sz = sz * 16 + v;
        }
        if (!digits) return 0;
        if (sz == 0) return 1; /* 结束块 */
        if (i + (size_t)sz > inlen) return 0;
        if (!buf_append(out, in + i, (size_t)sz)) return 0;
        i += (size_t)sz;
        if (i < inlen && in[i] == '\r') i++; /* 吃掉数据后的 CRLF */
        if (i < inlen && in[i] == '\n') i++;
    }
}

/* ---------------------------------------------------------------- 主流程 */

static long http_do(const char* url, const char* post, const char* referer,
                    unsigned flags, long timeout_s, http_buf* out,
                    char* loc_out, size_t loc_outsz)
{
    static int sigpipe_done;
    if (!sigpipe_done)
    {
#ifndef _WIN32
        signal(SIGPIPE, SIG_IGN); /* Windows 没有 SIGPIPE */
#endif
        if (!sock_init())
        {
            LOG_ERROR("[http] Winsock 初始化失败");
            return -1;
        }
        sigpipe_done = 1;
    }

    if (timeout_s <= 0) timeout_s = HTTP_TIMEOUT_S;

    char cur[1024];
    snprintf(cur, sizeof cur, "%s", url);

    int hops = (flags & HTTP_FOLLOW) ? MAX_HOPS : 1;
    long code = -1;

    for (int hop = 0; hop < hops; hop++)
    {
        url_t u;
        if (!parse_url(cur, &u))
        {
            if (!(flags & HTTP_QUIET))
                LOG_ERROR("[http] 只支持 http:// 地址: %s", cur);
            return -1;
        }

        long t0 = log_tick_ms();
        long deadline = t0 + timeout_s * 1000;

        sock_t fd = connect_timeout(u.host, u.port, (long)HTTP_CONNECT_TIMEOUT_S * 1000);
        if (fd == SOCK_INVALID)
        {
            LOG_DEBUG("[http] %s %s:%d -> 连接失败, %ld ms",
                      post ? "POST" : "GET", u.host, u.port, log_tick_ms() - t0);
            if (!(flags & HTTP_QUIET))
                LOG_ERROR("[http] 无法连接 %s:%d", u.host, u.port);
            return -1;
        }

        /* 拼请求：HTTP/1.1 + 浏览器式头。Host/Origin 缺省端口省略（与浏览器一致） */
        char hostport[300];
        if (u.port == 80)
            snprintf(hostport, sizeof hostport, "%s", u.host);
        else
            snprintf(hostport, sizeof hostport, "%s:%d", u.host, u.port);

        size_t pn = post ? strlen(post) : 0;
        size_t cap = 2048 + (referer ? strlen(referer) : 0) + pn;
        char* req = malloc(cap);
        if (!req)
        {
            sock_close(fd);
            return -1;
        }

        int rn = snprintf(req, cap,
                          "%s %s HTTP/1.1\r\n"
                          "Host: %s\r\n"
                          "Connection: close\r\n"
                          "User-Agent: %s\r\n"
                          "Accept: %s\r\n"
                          "Accept-Language: zh-CN,zh;q=0.9\r\n",
                          post ? "POST" : "GET", u.path, hostport, user_agent(),
                          post ? ACCEPT_XHR : ACCEPT_NAV);
        if (post)
            rn += snprintf(req + rn, cap - (size_t)rn,
                           "X-Requested-With: XMLHttpRequest\r\n"
                           "Origin: http://%s\r\n", hostport);
        if (referer)
            rn += snprintf(req + rn, cap - (size_t)rn, "Referer: %s\r\n", referer);
        if (post)
            rn += snprintf(req + rn, cap - (size_t)rn,
                           "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
                           "Content-Length: %lu\r\n", (unsigned long)pn);
        /* 注意别用 %zu：mingw 下这处直接调 snprintf 走 MSVCRT，%zu 未定义，
         * Content-Length 会打错（LOG_* 宏走 __mingw_vfprintf 才支持 %zu）。 */
        req[rn++] = '\r';
        req[rn++] = '\n';
        if (pn)
        {
            memcpy(req + rn, post, pn);
            rn += (int)pn;
        }

        LOG_TRACE("[http] 请求:\n%.*s", rn > 2048 ? 2048 : rn, req);

        if (!send_all(fd, req, (size_t)rn, deadline))
        {
            LOG_DEBUG("[http] %s:%d 发送失败", u.host, u.port);
            if (!(flags & HTTP_QUIET)) LOG_ERROR("[http] 发送请求失败");
            free(req);
            sock_close(fd);
            return -1;
        }
        free(req);

        char hdr[HDR_CAP];
        size_t hdr_end = 0;
        ssize_t got = read_headers(fd, hdr, sizeof hdr, deadline, &hdr_end);
        if (got < 0)
        {
            LOG_DEBUG("[http] %s:%d 读响应头失败/超时", u.host, u.port);
            if (!(flags & HTTP_QUIET)) LOG_ERROR("[http] 读响应失败（超时或连接被重置）");
            sock_close(fd);
            return -1;
        }
        /*
         * 把解析用的字符串提前截断。注意**不能**写 hdr[hdr_end]：
         * body 正好从 hdr_end 开始，那样会吃掉 body 的第一个字节。
         * hdr_end-2 落在结尾 \r\n\r\n 的前半，截在这里既不破坏头文本，
         * 也不碰 body（hdr_get 的循环遇到 NUL 自然结束）。
         */
        hdr[hdr_end - 2] = 0;

        code = parse_status(hdr);
        if (code < 0)
        {
            LOG_DEBUG("[http] 无法解析状态行");
            if (!(flags & HTTP_QUIET)) LOG_ERROR("[http] 响应不是合法 HTTP");
            sock_close(fd);
            return -1;
        }

        char loc[1024] = "";
        hdr_get(hdr, "Location", loc, sizeof loc);
        if (loc_out && loc_outsz && !loc_out[0] && loc[0])
            snprintf(loc_out, loc_outsz, "%s", loc);

        /* 探测类请求（out==NULL）只要状态码：拿到响应头就收工，不读 body */
        if (out)
        {
            free(out->data);
            out->data = NULL;
            out->len = 0; /* 每跳只要最终响应 */

            char te[64] = "", cl[64] = "";
            hdr_get(hdr, "Transfer-Encoding", te, sizeof te);
            hdr_get(hdr, "Content-Length", cl, sizeof cl);

            size_t body_have = (size_t)got - hdr_end;
            const char* body_ptr = hdr + hdr_end;

            long clen = -1;
            if (!strstr(te, "chunked") && cl[0]) clen = strtol(cl, NULL, 10);

            http_buf raw = {0};
            int okb = read_raw_body(fd, body_ptr, body_have, clen, deadline, &raw);
            if (okb)
            {
                if (strstr(te, "chunked"))
                    okb = dechunk(raw.data ? raw.data : "",
                                  raw.len, out);
                else if (raw.len) okb = buf_append(out, raw.data, raw.len);
            }
            if (!okb)
                LOG_DEBUG("[http] 响应体读取不完整（已得 %zu 字节）", out->len);
            free(raw.data);
        }

        long cost = log_tick_ms() - t0;
        LOG_DEBUG("[http] %s %s -> HTTP %ld, %zu 字节, %ld ms",
                  post ? "POST" : "GET", cur, code, out ? out->len : 0, cost);
        LOG_TRACE("[http] 请求头: User-Agent=%s%s", user_agent(),
                  referer ? " + Referer" : "");
        if (referer) LOG_TRACE("[http] Referer: %s", referer);

        sock_close(fd);

        /* 跟随跳转（仅 HTTP_FOLLOW 时） */
        if (code >= 300 && code < 400 && loc[0] && (flags & HTTP_FOLLOW))
        {
            if (strncmp(loc, "http://", 7) == 0)
            {
                snprintf(cur, sizeof cur, "%s", loc);
            }
            else if (loc[0] == '/')
            {
                snprintf(cur, sizeof cur, "http://%s:%d%s", u.host, u.port, loc);
            }
            else
            {
                LOG_DEBUG("[http] 不支持的跳转目标: %s", loc);
                break;
            }
            LOG_DEBUG("[http] 跟随跳转 -> %s", cur);
            continue;
        }
        break;
    }
    return code;
}

long http_req_ex(const char* url, const char* post, const char* referer,
                 unsigned flags, http_buf* out)
{
    return http_do(url, post, referer, flags, 0, out, NULL, 0);
}

long http_req(const char* url, const char* post, const char* referer, http_buf* out)
{
    return http_req_ex(url, post, referer, 0, out);
}

long http_req_location(const char* url, char* loc, size_t locsz)
{
    if (loc && locsz) loc[0] = 0;
    return http_do(url, NULL, NULL, 0, 0, NULL, loc, locsz);
}

/* ---------------------------------------------------------------- 并行在线探测 */

static const char* PROBE_204[] = {PROBE_204_LIST};
#define PROBE_MAX 16

/*
 * 并行探测的状态机。整个 is_online() 只有一个总 deadline（PROBE_TIMEOUT_S），
 * 5 个地址同时连：离线最坏耗时从 5×2s=10s 降到 ~2s；在线时同样 ~1 个 RTT 出结果。
 * 代价：无论在线与否每次探测都发全部 N 个请求（原来命中即停只发 1 个），
 * 每个 ~120 字节，一次登录多几 KB 内网流量，可忽略。
 *
 * DNS 解析仍是串行阻塞的（getaddrinfo 没有异步接口）：正常内网 DNS 每次
 * 几 ms 无感；DNS 本身坏掉时总耗时仍会被拖长，这是与旧实现相同的行为，
 * 不为此引入线程。
 */
typedef struct
{
    sock_t fd;              /* SOCK_INVALID = 未发起/已结束 */
    int phase;              /* 0=连接中 1=发送中 2=读状态行 3=完成 */
    int is204;
    char req[512];          /* 预拼好的 GET 请求 */
    size_t req_len, req_off;
    char buf[128];          /* 只需要状态行 */
    size_t buflen;
} probe_t;

static probe_t g_probe[PROBE_MAX];   /* 文件域：非重入；CLI 单线程，够用 */

/* 发起非阻塞 connect（不等待结果），DNS 失败返回 SOCK_INVALID */
static sock_t connect_start(const char* host, int port)
{
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);

    sock_t fd = SOCK_INVALID;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return SOCK_INVALID;
    for (ai = res; ai; ai = ai->ai_next)
    {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == SOCK_INVALID) continue;
        if (sock_nonblock(fd, 1) != 0)
        {
            sock_close(fd);
            fd = SOCK_INVALID;
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break; /* 本机地址立即连上 */
        if (sock_errno == SOCK_ERR_INPROGRESS) break;             /* 正在连，交给 poll */
        sock_close(fd);
        fd = SOCK_INVALID;
    }
    freeaddrinfo(res);
    return fd;
}

/* 推进单个探测的状态机；命中 204 时置 *hit */
static void probe_step(probe_t* p, int* hit)
{
    if (p->phase == 0) /* CONNECT：POLLOUT = 连上或失败，用 SO_ERROR 区分 */
    {
        if (sock_take_error(p->fd) != 0)
        {
            p->phase = 3;
            return;
        }
        p->phase = 1; /* 连上，顺势试发 */
    }

    if (p->phase == 1) /* SEND */
    {
        while (p->req_off < p->req_len)
        {
            int w = (int)send(p->fd, p->req + p->req_off, p->req_len - p->req_off, 0);
            if (w < 0)
            {
                int pe = sock_errno;
                if (pe == SOCK_ERR_INTR) continue;
                if (pe == SOCK_ERR_WOULDBLOCK) return;
                p->phase = 3;
                return;
            }
            if (w == 0)
            {
                p->phase = 3;
                return;
            }
            p->req_off += (size_t)w;
        }
        p->phase = 2; /* 发完，顺势试读 */
    }

    /* READ：只需要状态行，见到第一个 \n 就解析收工 */
    for (;;)
    {
        if (p->buflen >= sizeof p->buf)
        {
            p->phase = 3;
            return;
        }
        int r = (int)recv(p->fd, p->buf + p->buflen, sizeof p->buf - p->buflen, 0);
        if (r < 0)
        {
            int pe = sock_errno;
            if (pe == SOCK_ERR_INTR) continue;
            if (pe == SOCK_ERR_WOULDBLOCK) return;
            p->phase = 3;
            return;
        }
        if (r == 0)
        {
            p->phase = 3; /* 对端关闭（HTTP/1.0 也会先给状态行） */
            return;
        }
        p->buflen += (size_t)r;
        char* nl = memchr(p->buf, '\n', p->buflen);
        if (nl)
        {
            *nl = 0;
            p->is204 = (parse_status(p->buf) == 204);
            p->phase = 3;
            if (p->is204) *hit = 1;
            return;
        }
        /* 状态行还没收全，继续读（受总 deadline 限制） */
    }
}

int is_online(void)
{
    static int sigpipe_done;
    if (!sigpipe_done)
    {
#ifndef _WIN32
        signal(SIGPIPE, SIG_IGN);
#endif
        if (!sock_init())
        {
            LOG_ERROR("[probe] Winsock 初始化失败");
            return -1;
        }
        sigpipe_done = 1;
    }

    size_t n = sizeof PROBE_204 / sizeof *PROBE_204;
    if (n > PROBE_MAX) n = PROBE_MAX;
    long t0 = log_tick_ms();
    long deadline = t0 + (long)PROBE_TIMEOUT_S * 1000;

    /* 1) DNS（串行）+ 发起全部非阻塞 connect（并行） */
    size_t pending = 0;
    for (size_t i = 0; i < n; i++)
    {
        probe_t* p = &g_probe[i];
        memset(p, 0, sizeof *p);
        p->fd = SOCK_INVALID;
        url_t u;
        if (!parse_url(PROBE_204[i], &u)) continue;
        p->fd = connect_start(u.host, u.port);
        if (p->fd == SOCK_INVALID)
        {
            LOG_DEBUG("[probe] %s -> DNS/连接发起失败", PROBE_204[i]);
            continue;
        }
        p->req_len = (size_t)snprintf(p->req, sizeof p->req,
                                      "GET %s HTTP/1.1\r\n"
                                      "Host: %s:%d\r\n"
                                      "User-Agent: %s\r\n"
                                      "Accept: */*\r\n"
                                      "Connection: close\r\n\r\n",
                                      u.path, u.host, u.port, user_agent());
        pending++;
    }

    /* 2) 单个 poll 循环驱动所有探测 */
    int hit = 0;
    while (pending && !hit)
    {
        long left = remain_ms(deadline);
        if (left <= 0) break;

        struct pollfd pfds[PROBE_MAX];
        size_t idx[PROBE_MAX], m = 0;
        for (size_t i = 0; i < n; i++)
        {
            probe_t* p = &g_probe[i];
            if (p->fd == SOCK_INVALID || p->phase == 3) continue;
            pfds[m].fd = (int)p->fd;
            pfds[m].events = p->phase == 2 ? POLLIN : POLLOUT;
            pfds[m].revents = 0;
            idx[m++] = i;
        }
        if (!m) break;

        int r = poll(pfds, (nfds_t)m, (int)left);
        if (r <= 0) break; /* 超时（全部还没连上/没响应） */

        for (size_t k = 0; k < m; k++)
        {
            if (!pfds[k].revents) continue;
            probe_t* p = &g_probe[idx[k]];
            probe_step(p, &hit);
            if (p->phase == 3 && p->fd != SOCK_INVALID)
            {
                sock_close(p->fd);
                p->fd = SOCK_INVALID;
                pending--;
            }
            if (hit) break;
        }
    }

    /* 3) 收尾：关掉所有还开着的 fd */
    for (size_t i = 0; i < n; i++)
        if (g_probe[i].fd != SOCK_INVALID)
        {
            sock_close(g_probe[i].fd);
            g_probe[i].fd = SOCK_INVALID;
        }

    if (hit)
    {
        LOG_INFO("在线探测: 并行 %zu 个地址，命中 204 (%ld ms)", n, log_tick_ms() - t0);
        return 1;
    }
    LOG_INFO("在线探测: 并行 %zu 个地址均未返回 204 (%ld ms)", n, log_tick_ms() - t0);
    return 0;
}
