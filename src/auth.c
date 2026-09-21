//
// auth.c - 认证流程实现
//
// 登录对应原 main.sh，注销对应原 cqie-exit.sh，reauth 为新增的"先注销再认证"。
// 约定：结果（userIndex / 注销响应 / 已在线）走 stdout，诊断信息走 stderr（见 log.h）。
//
#define _POSIX_C_SOURCE 200809L /* getaddrinfo / inet_ntop（-std=c99 下需显式开启） */
#include "auth.h"
#include "config.h"
#include "bn.h"
#include "rsa.h"
#include "http.h"
#include "state.h"
#include "util.h"
#include "log.h"
#include "compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* g_portal; /* --portal 覆盖 */
static int g_dry_run; /* --dry-run：只到加密为止，不提交 */
static int g_plain;   /* --plain：跳过 RSA 加密，密码明文提交 */

void auth_set_portal(const char* url) { g_portal = (url && url[0]) ? url : NULL; }
void auth_set_dry_run(int on) { g_dry_run = on; }
void auth_set_plain(int on) { g_plain = on; }

/* ---- 运行期凭据（配置文件读取后注入；宏为编译期兜底，发布版默认空）---- */
static char g_user[128] = "", g_pass[256] = "", g_service[128] = "";
static char g_last_service[256] = ""; /* login 实际使用的运营商（探测命中或沿用配置） */
static char g_probe[512] = "";        /* 运行期探测地址（向导/配置文件 probe= 注入） */

void auth_set_credentials(const char* user, const char* pass, const char* service)
{
    if (user && user[0]) snprintf(g_user, sizeof g_user, "%s", user);
    if (pass && pass[0]) snprintf(g_pass, sizeof g_pass, "%s", pass);
    if (service && service[0]) snprintf(g_service, sizeof g_service, "%s", service);
}

/* 运行期值优先；未设置时回落编译期默认（-D 注入的口子） */
const char* auth_user(void) { return g_user[0] ? g_user : USER_ID; }
const char* auth_password(void) { return g_pass[0] ? g_pass : PASSWORD; }
const char* auth_service(void) { return g_service[0] ? g_service : SERVICE_NAME; }
const char* auth_last_service(void) { return g_last_service; }

void auth_set_probe(const char* url)
{
    snprintf(g_probe, sizeof g_probe, "%s", url ? url : "");
}

/* 生效的探测地址：运行期 probe= > 编译期 PROBE_URL */
static const char* probe_url(void)
{
    return g_probe[0] ? g_probe : PROBE_URL;
}

/*
 * 通过探测地址发现认证配置（向导用）：
 * 请求探测地址触发 AC 劫持，从认证页跳转 URL 提取 portal 基址（本次会话
 * 立即生效）并拉取运营商列表。成功返回 1。
 */
static int fetch_services(const char* qs, const char* referer, char* out, size_t outsz);

int auth_discover_portal(char* portal_out, size_t psz, char* list_out, size_t lsz)
{
    http_buf probe = {0};
    long code = http_req_ex(probe_url(), NULL, NULL, HTTP_QUIET, &probe);
    int ok = 0;
    char* redir = (code >= 0 && probe.data && probe.data[0])
                      ? fetch_redirect_url(probe.data) : NULL;
    if (redir && *redir)
    {
        /* portal 基址 = 认证页 URL 截断 /index.jsp 之前 */
        const char* cut = strstr(redir, "/index.jsp");
        size_t len = cut ? (size_t)(cut - redir) : strlen(redir);
        size_t c = len < psz - 1 ? len : psz - 1;
        memcpy(portal_out, redir, c);
        portal_out[c] = 0;
        auth_set_portal(portal_out); /* 发现即生效 */
        char qs[2048] = "";
        char* q = strchr(redir, '?');
        if (q && q[1]) snprintf(qs, sizeof qs, "%s", q + 1);
        list_out[0] = 0;
        if (qs[0])
            fetch_services(qs, portal_out, list_out, lsz);
        ok = 1;
    }
    free(redir);
    free(probe.data);
    return ok;
}

static const char* portal(void) { return g_portal ? g_portal : PORTAL_URL; }

/* 拼 portal 的接口地址：<portal>/InterFace.do?method=xxx */
static int portal_endpoint(char* buf, size_t n, const char* method)
{
    int r = snprintf(buf, n, "%s/InterFace.do?method=%s", portal(), method);
    return r > 0 && (size_t)r < n;
}

/*
 * 校园网环境预检：portal 是校园网内网地址，出了校园网 TCP 必然不可达；
 * 校园网内无论是否认证都可达——这是唯一可移植的"是否在校园网"判据。
 */
static int portal_reachable(void)
{
    const char* p = strstr(portal(), "http://");
    if (!p) return 0;
    p += 7;
    char host[128] = "";
    size_t i = 0;
    while (*p && *p != '/' && *p != ':' && i + 1 < sizeof host) host[i++] = *p++;
    int port = 80;
    if (*p == ':') port = atoi(p + 1);
    return http_host_reachable(host, port, HTTP_CONNECT_TIMEOUT_S * 1000L);
}

/* 打印表单内容，password 字段打码（日志里不留口令派生值） */
static void log_form(int level, const char* tag, const char* body)
{
    /* 级别不够时直接退出：否则每次 login 都白做一趟 3KB 的逐字符拷贝 + strncmp 扫描 */
    if (!log_enabled(level)) return;
    char out[3072];
    size_t o = 0;
    const char* p = body;
    while (*p && o + 1 < sizeof out)
    {
        if (!strncmp(p, "password=", 9))
        {
            const char* end = strchr(p, '&');
            size_t len = end ? (size_t)(end - p) - 9 : strlen(p) - 9;
            o += (size_t)snprintf(out + o, sizeof out - o,
                                  "password=<%u 字符,已打码>", (unsigned)len);
            if (!end) break;
            p = end;
            continue;
        }
        out[o++] = *p++;
    }
    out[o] = 0;
    log_emit(level, "%s %s", tag, out);
}

/*
 * hex 形式的 userIndex -> 可读形式（含 账号/IP）。解不出内容时回退为原文。
 * 原始 hex 始终是提交给服务端的值，这里只用于显示。
 */
static void ui_decode(const char* raw, char* out, size_t outsz)
{
    size_t n = hex_decode(raw, out, outsz - 1);
    out[n] = 0;
    if (!n)
    { /* 解不出内容：原样输出（放不下则截断，仅用于显示） */
        size_t m = strlen(raw);
        if (m >= outsz) m = outsz - 1;
        memcpy(out, raw, m);
        out[m] = 0;
    }
}


/*
 * 来源②"服务端要回"：GET <portal>/redirectortosuccess.jsp。
 * 服务端按源 IP 识别会话（无需任何凭据），把已认证 IP 重定向到 success.jsp，
 * Location 里带着当前会话的 userIndex（2026-09-18 真机确认：
 * Location: http://<portal>/eportal/./success.jsp?userIndex=<hex>）。
 * 仅认 3xx + Location；JS 跳转变体不支持（当前部署用不到）。
 * 成功返回 1，out 得到 hex 形式 userIndex。
 */
static int ui_fetch_remote(char* out, size_t outsz)
{
    char url[512];
    if (snprintf(url, sizeof url, "%s/redirectortosuccess.jsp", portal())
        >= (int)sizeof url)
        return 0;

    char loc[1024] = "";
    long code = http_req_location(url, loc, sizeof loc);
    LOG_DEBUG("redirectortosuccess.jsp -> HTTP %ld, Location=%s",
              code, loc[0] ? loc : "(无)");
    if (code < 300 || code >= 400 || !loc[0]) return 0;

    const char* p = strstr(loc, "userIndex=");
    if (!p) return 0;
    p += 10; /* strlen("userIndex=") */
    size_t i = 0;
    while (p[i] && p[i] != '&' && i < outsz - 1)
    {
        out[i] = p[i];
        i++;
    }
    out[i] = 0;
    return out[0] ? 1 : 0;
}

/* 响应记录：DEBUG 打长度，TRACE 打全文（截断 LOG_BODY_MAX） */
static void log_response(const char* tag, const http_buf* b)
{
    if (!b || !b->data)
    {
        LOG_WARN("%s: 无响应内容", tag);
        return;
    }
    LOG_DEBUG("%s: 收到 %zu 字节", tag, b->len);
    if (log_level() >= LOG_LEVEL_TRACE)
    {
        size_t n = b->len > LOG_BODY_MAX ? LOG_BODY_MAX : b->len;
        LOG_TRACE("%s 响应全文:\n%.*s%s", tag, (int)n, b->data,
                  b->len > n ? "\n  ...(已截断)" : "");
    }
}

/*
 * 新版 eportal 的运营商接口（真机抓包确认）：
 *   POST <portal>/userV2.do?method=getServices
 *   body = username=<账号>&search=?<queryString>（search 值整体 urlencode 一次）
 * 响应是 "名@名@名" 纯文本（可能带 JSON 引号）。成功返回 1 并把列表拷进 out。
 */
static int fetch_services(const char* qs, const char* referer, char* out, size_t outsz)
{
    char url[512];
    if (snprintf(url, sizeof url, "%s/userV2.do?method=getServices", portal())
        >= (int)sizeof url)
        return 0;

    char* search = malloc(strlen(qs) + 2);
    if (!search) return 0;
    search[0] = '?';
    strcpy(search + 1, qs);
    char* s_enc = urlencode(search);
    free(search);
    if (!s_enc) return 0;

    size_t bl = strlen(auth_user()) + strlen(s_enc) + 32;
    char* body = malloc(bl);
    if (!body)
    {
        free(s_enc);
        return 0;
    }
    snprintf(body, bl, "username=%s&search=%s", auth_user(), s_enc);
    free(s_enc);
    log_form(LOG_LEVEL_DEBUG, "getServices 表单:", body);

    http_buf resp = {0};
    long code = http_req(url, body, referer, &resp);
    free(body);

    int ok = 0;
    if (code >= 0 && resp.data && resp.data[0])
    {
        const char* s = resp.data;
        while (*s == ' ' || *s == '\r' || *s == '\n' || *s == '"') s++;
        const char* e = s + strlen(s);
        while (e > s && (e[-1] == ' ' || e[-1] == '\r' || e[-1] == '\n' || e[-1] == '"'))
            e--;
        size_t n = (size_t)(e - s);
        if (n && n < outsz)
        {
            memcpy(out, s, n);
            out[n] = 0;
            ok = 1;
        }
    }
    else
    {
        LOG_DEBUG("getServices 请求失败 (HTTP %ld)", code);
    }
    free(resp.data);
    return ok;
}

/* 在 "a@b@c" 运营商列表里精确匹配 name，命中则拷贝到 out */
/*
 * 自动回退的规避词表：命中这些关键词的运营商在自动回退/逐项尝试时
 * 排到所有普通项之后（"校园网"为限时套餐，误选会消耗免费时长）。
 * 精确配置命中的运营商不受影响。
 */
static const char* const SERVICE_AVOID[] = { "校园网" };

static int service_avoided(const char* p, size_t len)
{
    for (size_t i = 0; i < sizeof SERVICE_AVOID / sizeof *SERVICE_AVOID; i++)
    {
        size_t kwl = strlen(SERVICE_AVOID[i]);
        if (len < kwl) continue;
        for (size_t j = 0; j + kwl <= len; j++)
            if (memcmp(p + j, SERVICE_AVOID[i], kwl) == 0)
                return 1;
    }
    return 0;
}

static int service_pick(const char* list, const char* name, char* out, size_t outsz)
{
    const char* first = NULL;
    size_t first_len = 0;
    const char* first_ok = NULL; /* 第一个不命中规避词表的项（回退优先用它） */
    size_t first_ok_len = 0;
    const char* p = list;
    while (*p)
    {
        const char* e = strchr(p, '@');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len)
        {
            if (!first) { first = p; first_len = len; }
            if (!first_ok && !service_avoided(p, len))
            {
                first_ok = p;
                first_ok_len = len;
            }
            /*
             * 配置名精确命中优先；未命中/未配置时最后回退列表第一项——
             * 服务端只认列表内的值，沿用列表外的配置名必然被拒
             * （"您未绑定服务对应的运营商"），回退至少给自愈写回一个机会。
             */
            if (name[0] && strlen(name) == len && strncmp(p, name, len) == 0)
            {
                size_t c = len < outsz - 1 ? len : outsz - 1;
                memcpy(out, p, c);
                out[c] = 0;
                return 1;
            }
        }
        if (!e) break;
        p = e + 1;
    }
    /* 回退优先选非规避项（如"中国移动"），避免自动登录误选限时/计费套餐；
     * 列表全是规避项时才退回列表第一项。 */
    const char* pick = first_ok ? first_ok : first;
    size_t pick_len = first_ok ? first_ok_len : first_len;
    if (pick)
    {
        size_t c = pick_len < outsz - 1 ? pick_len : outsz - 1;
        memcpy(out, pick, c);
        out[c] = 0;
        return 1;
    }
    return 0;
}

int cmd_status(void)
{
    /* 三态退出码：0=在线 1=离线 2=能上外网但 portal 不可达（不在校园网）。
     * 旧脚本按布尔判断（0/非 0）仍然兼容。 */
    int online = is_online();
    int code = 1;
    const char* state = "未在线";
    if (online)
    {
        if (portal_reachable())
        {
            code = 0;
            state = "已在线";
        }
        else
        {
            code = 2;
            state = "已在线但不在校园网（portal 不可达）";
        }
    }
    puts(state);
    log_status("在线状态: %s", state);
    return code;
}

/* ---- 单实例锁：login/reauth/logout 互斥，防 cron 与手动并发写状态文件 ----
 * 注意 cmd_reauth 持锁后会再调 cmd_logout（它会再次尝试加锁），
 * 因此用同进程重入计数：嵌套加锁只计数，最外层解锁时才真正释放。 */
static void* g_session_lock;
static int g_lock_depth;

int auth_session_lock(void)
{
    if (g_lock_depth > 0)
    {
        g_lock_depth++;
        return 1;
    }
    char path[600];
    if (!state_path(path, sizeof path, ".lock")) return 0;
    g_session_lock = compat_lock_file(path);
    if (!g_session_lock)
    {
        LOG_ERROR("另一个实例正在运行（锁文件: %s）", path);
        log_status("跳过: 已有实例在运行");
        return 0;
    }
    g_lock_depth = 1;
    LOG_DEBUG("已持有单实例锁: %s", path);
    return 1;
}

void auth_session_unlock(void)
{
    if (g_lock_depth > 0 && --g_lock_depth == 0)
    {
        compat_unlock_file(g_session_lock);
        g_session_lock = NULL;
    }
}

/*
 * known_offline=1 表示调用方已经知道当前处于离线状态（reauth 刚注销完），
 * 可以直接跳过开头的 204 探测 —— 那最多是 5 个请求，纯属白跑。
 */
static int login_impl(int force, int known_offline)
{
    /* 凭据缺失早退：发布版不内置账号，引导用户写配置文件 */
    if (!auth_user()[0] || !auth_password()[0])
    {
        LOG_ERROR("未配置账号/密码：请编辑配置文件 %s（user=/password=/service= 三行），"
                  "或编译时 -DUSER_ID=\"...\" -DPASSWORD=\"...\" 注入", CONFIG_FILE);
        log_status("认证失败: 未配置账号/密码");
        return 1;
    }

    /* 所有需要释放的资源统一声明并置 NULL */
    char* redir = NULL;
    char* qs_enc = NULL;
    char* qse2 = NULL;
    char* body = NULL;
    char* svc_enc = NULL;
    char* lb = NULL;
    http_buf probe = {0}, info = {0}, resp = {0};
    char url[512];

    int ret = 1;
    LOG_INFO("===== 开始认证 (portal=%s, user=%s%s) =====",
             portal(), auth_user(), g_dry_run ? ", dry-run" : "");

    /* 1. 在线检测（reauth/dry-run 也要知道当前状态，方便解释后续行为） */
    int was_online;
    if (known_offline)
    {
        LOG_INFO("网络状态: 离线（刚注销，跳过在线探测）");
        was_online = 0;
    }
    else
    {
        was_online = is_online();
        LOG_INFO("网络状态: %s", was_online ? "已在线" : "未在线");
    }
    if (!force && !g_dry_run && was_online)
    {
        LOG_INFO("已在线，无需认证");
        puts("已在线");
        log_status("已在线，跳过认证");
        return 0;
    }
    if (force) LOG_INFO("force 模式：跳过在线短路，直接认证");
    if (g_dry_run && was_online)
        LOG_INFO("提示: 当前已在线，AC 一般不会下发劫持页，可能拿不到 queryString");

    /* 2. 抓劫持认证页，取 location.href（原脚本此处 2>/dev/null 静默失败） */
    LOG_DEBUG("探测 %s", probe_url());
    http_req_ex(probe_url(), NULL, NULL, HTTP_QUIET, &probe);
    LOG_DEBUG("探测页 %zu 字节", probe.len);
    redir = probe.data ? fetch_redirect_url(probe.data) : NULL;
    if (!redir || !*redir)
    {
        if (was_online)
            LOG_ERROR("未捕获认证页：当前已在线，AC 不下发劫持页（dry-run/logout 前请先断开或先注销）");
        else
            LOG_ERROR("已离线但未捕获认证页, 网络异常");
        goto done;
    }
    LOG_INFO("认证页跳转地址: %s", redir);

    /* queryString = 第一个 '?' 之后 */
    char* qs = strchr(redir, '?');
    if (!qs || !*++qs)
    {
        LOG_ERROR("queryString为空");
        goto done;
    }
    LOG_INFO("queryString(原文): %s", qs);
    qs_enc = urlencode(qs);
    if (!qs_enc) goto done;
    LOG_DEBUG("queryString(一次编码): %s", qs_enc);

    /* 3. pageInfo：获取 RSA 公钥与运营商列表 */
    char referer[2048];
    snprintf(referer, sizeof referer, "%s/index.jsp?%s", portal(), qs_enc);
    qse2 = urlencode(qs_enc); /* --data-urlencode：二次编码 */
    if (!qse2) goto done;
    body = malloc(strlen(qse2) + 32);
    if (!body) goto done;
    sprintf(body, "queryString=%s", qse2);
    LOG_TRACE("pageInfo 请求体: %s", body);

    if (!portal_endpoint(url, sizeof url, "pageInfo")) goto done;
    long code = http_req(url, body, referer, &info);
    /* 与原脚本一致：只看有没有拿到内容，不强制 200（AC 可能返回 302/其它状态但带 body） */
    if (code < 0 || !info.data || !info.data[0])
    {
        LOG_ERROR("pageInfo 请求失败 (HTTP %ld)", code);
        if (info.data) LOG_ERROR("响应内容: %.300s", info.data);
        LOG_DEBUG("若响应为空，先检查请求头：本 AC 缺少 User-Agent 时会返回 200 + 空 body");
        goto done;
    }
    if (code != 200)
        LOG_WARN("pageInfo 返回 HTTP %ld，继续按响应内容解析", code);
    log_response("pageInfo", &info);

    char e_hex[256] = "", n_hex[600] = "";
    extract_field(info.data, "publicKeyExponent", e_hex, sizeof e_hex);
    extract_field(info.data, "publicKeyModulus", n_hex, sizeof n_hex);
#if USE_ENCRYPT
    /* --plain 时用不到公钥，缺了也不拦（pageInfo 仍会请求：运营商列表还靠它） */
    if (!g_plain && (!e_hex[0] || !n_hex[0]))
    {
        LOG_ERROR("pageInfo 响应里没有 RSA 公钥，无法加密密码");
        LOG_ERROR("响应内容: %.300s", info.data);
        goto done;
    }
    LOG_INFO("RSA 公钥: e=%s(hex), n=%zu 字符 = %zu bit",
             e_hex, strlen(n_hex), strlen(n_hex) * 4);
    LOG_TRACE("publicKeyModulus = %s", n_hex);
#endif

    /* 运营商候选序列：
     * - 配置非空：单一候选（列表精确命中，或回退规避词表后的第一普通项）
     * - 配置为空：整个列表逐个尝试，规避词表项（校园网/免费等限时套餐）排最后；
     *   认证成功后把命中的运营商写回配置文件，下次直接精确命中 */
    char service[256] = "", svc_list[1024] = "";
    char cands[16][256];
    int ncand = 0;
    if (fetch_services(qs, referer, svc_list, sizeof svc_list))
    {
        LOG_INFO("运营商列表: %s", svc_list);
        if (auth_service()[0])
        {
            char picked[256] = "";
            if (service_pick(svc_list, auth_service(), picked, sizeof picked))
            {
                snprintf(cands[ncand++], sizeof cands[0], "%s", picked);
                if (strcmp(auth_service(), picked) == 0)
                    LOG_INFO("运营商: 列表命中 \"%s\"", picked);
                else
                    LOG_WARN("运营商: 配置值 \"%s\" 不在列表，改用 \"%s\"",
                             auth_service(), picked);
            }
            else
            {
                snprintf(cands[ncand++], sizeof cands[0], "%s", auth_service());
                LOG_WARN("运营商: 列表为空，沿用 \"%s\"", auth_service());
            }
        }
        else
        {
            /* 配置为空：两遍稳定分区——非规避项在前，规避项（校园网/免费等）在后 */
            for (int pass = 0; pass < 2 && ncand < 15; pass++)
            {
                const char* p = svc_list;
                while (*p && ncand < 15)
                {
                    const char* e = strchr(p, '@');
                    size_t len = e ? (size_t)(e - p) : strlen(p);
                    if (len && service_avoided(p, len) == pass)
                    {
                        size_t c = len < sizeof cands[0] - 1 ? len : sizeof cands[0] - 1;
                        memcpy(cands[ncand], p, c);
                        cands[ncand][c] = 0;
                        ncand++;
                    }
                    if (!e) break;
                    p = e + 1;
                }
            }
            LOG_INFO("运营商: 配置为空，按顺序尝试 %d 个候选（限时/计费类排后）", ncand);
        }
    }
    else
    {
        snprintf(cands[ncand++], sizeof cands[0], "%s", auth_service());
        LOG_WARN("运营商: 未能获取列表，沿用 \"%s\"", auth_service());
    }

    /* 4. 提取 mac，按需 RSA 加密密码 */
    char mac[64] = "";
    if (!extract_mac(qs, mac, sizeof mac))
        LOG_WARN("queryString 里没有 mac 参数，加密结果可能与服务端不匹配");
    LOG_DEBUG("mac: %s", mac);

    /* 1024 字符足够：1024bit 模数每分块 256 字符（可容 4 分块 = 504 字节明文），
     * 2048bit 模数每分块 512 字符（可容 2 分块）。原 8192 白占栈。 */
    char pwd_sub[1024];
    int enc = 0;
#if USE_ENCRYPT
    if (g_plain)
    {
        snprintf(pwd_sub, sizeof pwd_sub, "%s", auth_password());
        LOG_WARN("--plain：密码明文提交（明文会出现在网络与调试日志里，仅供排查用）");
    }
    else
    {
        if (!ruijie_rsa_encrypt(auth_password(), mac, e_hex, n_hex, pwd_sub, sizeof pwd_sub))
        {
            LOG_ERROR("RSA 加密失败 (公钥长度 %zu, 模数长度 %zu)", strlen(e_hex), strlen(n_hex));
            goto done;
        }
        enc = 1;
        size_t plain_len = strlen(auth_password()) + 1 + strlen(mac);
        LOG_INFO("密码已加密: %zu 字节明文(pwd>mac) -> %zu 字符密文, %zu 分块 x %d 字节",
                 plain_len, strlen(pwd_sub),
                 (plain_len + RSA_CHUNK - 1) / RSA_CHUNK, RSA_CHUNK);
    }
#else
    snprintf(pwd_sub, sizeof pwd_sub, "%s", PASSWORD);
    LOG_WARN("USE_ENCRYPT=0：本次明文提交密码（仅供调试）");
#endif

    /* 5. 提交登录：逐个候选尝试（配置为空时列表全量候选；成功即止并写回） */
    int login_ok = 0;
    for (int ci = 0; ci < ncand && !login_ok; ci++)
    {
        size_t cl = strnlen(cands[ci], sizeof service - 1);
        memcpy(service, cands[ci], cl);
        service[cl] = 0;
        snprintf(g_last_service, sizeof g_last_service, "%s", service);
        free(svc_enc);
        free(lb);
        free(resp.data);
        resp.data = NULL;
        svc_enc = urlencode(service);
        if (!svc_enc) goto done;
        size_t lbsz = strlen(auth_user()) + strlen(pwd_sub) + strlen(svc_enc)
            + strlen(qs_enc) + 256;
        lb = malloc(lbsz);
        if (!lb) goto done;
        snprintf(lb, lbsz,
                 "userId=%s&password=%s&service=%s&queryString=%s"
                 "&operatorPwd=&operatorUserId=&validcode=&passwordEncrypt=%s",
                 auth_user(), pwd_sub, svc_enc, qs_enc, enc ? "true" : "false");

        if (g_dry_run)
        {
            log_form(LOG_LEVEL_INFO, "将提交的表单(dry-run):", lb);
            LOG_INFO("dry-run: 探测/取公钥/加密均已完成，未提交登录");
            ret = 0;
            goto done;
        }

        log_form(LOG_LEVEL_DEBUG, "提交登录表单:", lb);
        if (!portal_endpoint(url, sizeof url, "login")) goto done;
        code = http_req(url, lb, referer, &resp); /* 浏览器登录时同源 XHR 必带 Referer */
        if (code < 0 || !resp.data || !resp.data[0])
        {
            LOG_ERROR("login 请求失败 (HTTP %ld)", code);
            if (resp.data) LOG_ERROR("响应内容: %.300s", resp.data);
            goto done; /* 网络错误与运营商无关，不做候选重试 */
        }
        if (code != 200)
            LOG_WARN("login 返回 HTTP %ld，继续按响应内容解析", code);
        log_response("login", &resp);

        /* 6. 提取 userIndex：有 = 该运营商认证成功 */
        char ui[1024] = "";
        extract_field(resp.data, "userIndex", ui, sizeof ui);
        if (ui[0])
        {
            if (ncand > 1)
                LOG_INFO("运营商 \"%s\" 认证成功（第 %d/%d 个候选）",
                         service, ci + 1, ncand);
            if (state_write(UI_FILE, ui))
            {
                char path[600];
                if (state_path(path, sizeof path, UI_FILE))
                    LOG_INFO("userIndex 已保存: %s", path);
            }
            else
            {
                LOG_WARN("userIndex 未写入状态目录，后续 logout 需要手动传 index");
            }
            /* 显示原始 hex（与提交给服务端的值一致）；要解码形式用 `userindex` 子命令 */
            printf("认证成功！ userIndex: %s\n", ui);
            ret = 0;
            login_ok = 1;
            break;
        }
        /* 该候选被拒：还有候选就继续试，没有则整体失败 */
        char msg[256] = "";
        extract_field(resp.data, "message", msg, sizeof msg);
        if (ci + 1 < ncand)
            LOG_WARN("运营商 \"%s\" 被拒（%s），尝试下一个候选",
                     service, msg[0] ? msg : "未知原因");
        else
        {
            LOG_ERROR("认证失败: %s", msg[0] ? msg : "(响应里没有 userIndex)");
            LOG_ERROR("响应内容: %.300s", resp.data);
            goto done;
        }
    }
    if (!login_ok)
        goto done; /* 全部候选未成功（防御：正常路径上面已处理） */


done:
    free(lb);
    free(svc_enc);
    free(body);
    free(qse2);
    free(qs_enc);
    free(redir);
    free(resp.data);
    free(info.data);
    free(probe.data);
    LOG_INFO("===== 认证结束: %s, 总耗时 %ld ms =====",
             ret == 0 ? "成功" : "失败", log_tick_ms());

    /* ---- 系统日志：每次运行一条结果（受 logread 查看，不受 -q/-v 影响）---- */
    if (ret == 0 && g_dry_run)
        log_status("dry-run: 已取到公钥并加密，未提交认证");
    else if (ret == 0)
        log_status("认证成功");
    else
        log_status("认证失败: %s",
                   log_first_error()[0] ? log_first_error() : "未知原因");
    return ret;
}

int cmd_login(int force)
{
    if (!auth_session_lock()) return 1;
    /* 校园网预检：探测可能显示"在线"（能上外网），但那不代表在校园网。
     * portal 不可达时明确退出，避免在家/热点上 cron 误报"已在线"。 */
    if (!portal_reachable())
    {
        LOG_ERROR("无法访问校园网 portal (%s)，当前可能不在校园网环境", portal());
        log_status("跳过: 不在校园网环境（portal 不可达）");
        return 1;
    }
    return login_impl(force, 0);
}

/* 发一次注销请求并处理结果。
 * 返回 0=服务端确认成功；1=服务端明确拒绝（会话可能本来就不存在）；
 * 2=网络错误。浏览器里的注销是从登录页发起的同源 XHR，补上 Referer 更像真人。 */
static int logout_once(const char* user_index)
{
    LOG_INFO("===== 注销 (userIndex=%s) =====", user_index);
    char body[1536];
    snprintf(body, sizeof body, "userIndex=%s", user_index);
    log_form(LOG_LEVEL_DEBUG, "提交注销表单:", body);

    char url[512], ref[256];
    if (!portal_endpoint(url, sizeof url, "logout"))
    {
        log_status("注销失败: portal 地址无效");
        return 2;
    }
    snprintf(ref, sizeof ref, "%s/index.jsp", portal());

    http_buf resp = {0};
    long code = http_req_ex(url, body, ref, HTTP_FOLLOW, &resp);
    log_response("logout", &resp);

    int ret;
    if (code < 0)
    {
        LOG_ERROR("logout 请求失败");
        ret = 2;
        log_status("注销失败: %s",
                   log_first_error()[0] ? log_first_error() : "网络错误");
    }
    else
    {
        char result[64] = "";
        if (resp.data) extract_field(resp.data, "result", result, sizeof result);
        if (!strcmp(result, "success"))
        {
            state_remove(UI_FILE); /* 会话已结束，状态文件不再有效 */
            LOG_INFO("注销成功，已清理状态文件");
            printf("下线成功! userIndex: %s\n", user_index);
            log_status("注销成功");
            ret = 0;
        }
        else
        {
            LOG_WARN("注销响应里没有 result=success%s%s（会话可能本来就不存在）",
                     result[0] ? ", result=" : "", result);
            log_status("注销未确认（会话可能本来就不存在）");
            ret = 1;
        }
    }
    free(resp.data);
    LOG_INFO("===== 注销结束: %s, 总耗时 %ld ms =====",
             ret == 0 ? "成功" : "未完成", log_tick_ms());
    return ret;
}

int cmd_logout(const char* user_index)
{
    if (!auth_session_lock()) return 1;
    /* 校园网预检：portal 不可达时三级来源全部无从谈起 */
    if (!portal_reachable())
    {
        LOG_ERROR("无法访问校园网 portal (%s)，当前可能不在校园网环境", portal());
        log_status("跳过: 不在校园网环境（portal 不可达）");
        return 1;
    }

    char stored[1024] = "";
    if (!user_index && state_read(UI_FILE, stored, sizeof stored) && stored[0])
        user_index = stored;

    int ret = 2; /* 2=网络错误 1=服务端未确认 0=确认成功 */
    if (user_index) ret = logout_once(user_index);

    /* 来源优先级：指定参数/存储值 -> 服务端要回。每级失败才降级。 */
    char remote[300] = "";
    if (ret != 0)
    {
        /* 服务端要回：状态文件丢失（tmpfs 重启）或存储值被拒时，
         * 问服务端要当前 IP 会话的 userIndex（存储值丢失时找回会话的唯一途径）。 */
        if (ui_fetch_remote(remote, sizeof remote) &&
            (!user_index || strcmp(remote, user_index) != 0))
        {
            LOG_INFO("服务端要回: redirectortosuccess.jsp 再试一次");
            ret = logout_once(remote);
        }
    }

    /* 两级来源（存储值 / 服务端要回）都落空通常意味着"本来就没有活跃会话"：
     * 服务端不会对未认证 IP 重定向。对 reauth 而言注销本就是尽力而为，
     * 降为 WARN 避免误导（用户容易误读成认证环节的问题）。 */
    if (ret != 0 && !user_index)
    {
        LOG_WARN("没有可用的 userIndex，跳过注销"
                 "（无存储值、服务端无活跃会话——可能本来就未登录）");
        log_status("注销跳过: 没有 userIndex（可能本来就未登录）");
        return 1;
    }
    /* 退出码沿用旧语义：服务端明确拒绝（会话可能本来就不存在）算软成功 exit 0；
     * 只有网络层面的失败才 exit 1。 */
    return ret == 2 ? 1 : 0;
}

int cmd_reauth(const char* user_index)
{
    if (!auth_session_lock()) return 1;
    /* 校园网预检（logout + login 两步都依赖 portal） */
    if (!portal_reachable())
    {
        LOG_ERROR("无法访问校园网 portal (%s)，当前可能不在校园网环境", portal());
        log_status("跳过: 不在校园网环境（portal 不可达）");
        return 1;
    }

    LOG_INFO("===== reauth: 先注销再认证 =====");
    if (user_index)
        LOG_INFO("第一步: 注销上一个会话（指定 userIndex）");
    else
        LOG_INFO("第一步: 注销上一个会话（无 userIndex 时向服务端要回）");
    if (cmd_logout(user_index) != 0)
        LOG_WARN("注销未确认，仍继续尝试重新认证");

    LOG_DEBUG("等待 %d ms 让 AC 释放会话", REAUTH_DELAY_MS);
    msleep(REAUTH_DELAY_MS);

    LOG_INFO("第二步: 重新认证");
    /* 刚注销完，确定处于离线状态，不必再跑一轮 204 探测 */
    return login_impl(1, 1);
}

int cmd_userindex(const char* hex)
{
    char buf[1024];
    if (!hex)
    {
        if (!state_read(UI_FILE, buf, sizeof buf) || !buf[0])
        {
            LOG_ERROR("没有可用的 userIndex：请先 login，或用 `userindex <hex>` 指定");
            return 1;
        }
        hex = buf;
    }
    char dec[513];
    ui_decode(hex, dec, sizeof dec);
    puts(dec);
    return 0;
}
