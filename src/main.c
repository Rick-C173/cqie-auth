//
// main.c - cqie-auth 命令行入口
//
//   cqie-auth login            登录（等价原 main.sh）
//   cqie-auth reauth [index]   先注销再认证
//   cqie-auth logout [index]   注销（等价原 cqie-exit.sh）
//   cqie-auth status           仅检测在线状态（0=在线, 1=离线）
//   cqie-auth userindex [hex]  输出解码后的 userIndex（省略参数时读状态文件）
//
// 动作 = 子命令，修饰 = 选项（-v/--log/--dry-run/--plain…），与 git/systemctl 的习惯一致。
//
#include "auth.h"
#include "config.h"
#include "compat.h"
#include "http.h"
#include "log.h"
#include "state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/stat.h> /* 配置文件权限检查 */
#endif

static void usage(FILE* out, const char* argv0)
{
#if CQIE_MINIMAL_HELP
    /* 精简版：OpenWrt 构建用，砍掉长说明（.rodata 里最大的一块），保留分区排版 */
    fprintf(out,
            "cqie-auth %s\n"
            "校园网(锐捷 eportal)认证工具\n"
            "\n"
            "用法:\n"
            "    %s <命令> [选项]\n"
            "\n"
            "命令:\n"
            "    login       认证上线（已在线短路；--force 强制）\n"
            "    reauth      先注销再重新认证（可带 index）\n"
            "    logout      注销下线（缺省读状态文件）\n"
            "    status      在线状态（退出码 0=在线, 1=离线）\n"
            "    userindex   解码 userIndex\n"
            "\n"
            "选项:\n"
            "    -v, --verbose      调试（-v 流程/-vv HTTP/-vvv 全文）\n"
            "    -q, --quiet        只输出错误\n"
            "        --log FILE     调试信息写入 FILE\n"
            "        --dry-run      探测+加密，不提交\n"
            "        --force        跳过\"已在线\"短路\n"
            "        --plain        密码明文提交（默认加密）\n"
            "        --portal URL   覆盖 portal 地址\n"
            "        --interface IP 绑定认证流量源 IP\n"
            "        --config FILE  凭据配置文件\n"
            "        --service NAME 覆盖运营商名\n"
            "        -u/-p USER/PWD 临时凭据（ps 可见，仅调试用）\n"
            "        --state-dir D  状态目录\n"
            "        --no-syslog    不写 syslog 状态行\n"
            "    -h, --help         帮助\n"
            "    -V, --version      版本\n"
            "\n"
            "日志: logread | grep cqie-auth\n",
            CQIE_VERSION, argv0);
#else
    fprintf(out,
            "cqie-auth %s - 校园网(锐捷 eportal)认证工具\n"
            "\n"
            "用法:\n"
            "    %s <命令> [选项]\n"
            "\n"
            "命令:\n"
            "    login       认证上线（已在线直接返回；--force 强制重走一次完整认证）\n"
            "    reauth      先注销当前会话，再重新认证（index 省略时读状态文件；换 IP / 卡计时用）\n"
            "    logout      注销下线（index 省略时读状态文件里的 userIndex）\n"
            "    status      只检测在线状态（退出码 0=在线, 1=离线）\n"
            "    userindex   解码显示 userIndex（hex 省略时读状态文件）\n"
            "    help        显示本帮助\n"
            "\n"
            "选项:\n"
            "    -v, --verbose      调试输出，可叠加：-v 流程 / -vv 加 HTTP 细节 / -vvv 加响应体全文\n"
            "    -q, --quiet        只输出错误\n"
            "        --log FILE     调试信息同时追加写入 FILE（适合 cron 事后排查）\n"
            "        --dry-run      只做探测+取公钥+加密，不提交登录（会自动带上 -v）\n"
            "        --force        跳过\"已在线\"短路，强制走一次完整认证（会话卡死时用）\n"
            "        --plain        密码明文提交（默认 RSA 加密；排查服务端解密问题时用）\n"
            "        --portal URL   覆盖 portal 地址（AC 换 IP 时不用重新编译）\n"
            "        --interface IP 绑定认证流量的源 IP（多网卡/多 WAN 时指定出口）\n"
            "        --config FILE  凭据配置文件（user/password/service 三行）\n"
            "        -u, --user U   临时指定账号（ps 可见，仅调试用）\n"
            "        -p, --pass P   临时指定密码（ps 可见，仅调试用）\n"
            "        --service NAME 覆盖运营商名（配置/探测结果之上的临时值）\n"
            "        --state-dir D  状态目录，默认 $CQIE_STATE_DIR 或 %s\n"
            "        --no-syslog    本次运行不写 syslog（logread 不留痕）\n"
            "    -h, --help         显示本帮助\n"
            "    -V, --version      显示版本\n"
            "\n"
            "调试级别（优先级从高到低）:\n"
            "    1) 命令行     -v / -vv / -vvv\n"
            "    2) 环境变量   CQIE_DEBUG=1|2|3\n"
            "    3) 编译期     make CFLAGS=-DDEBUG_DEFAULT=1\n"
            "\n"
            "输出约定:\n"
            "    调试信息走 stderr，结果（userIndex 等）走 stdout，互不干扰：\n"
            "        %s login -vv --log /tmp/cqie.log >/dev/null\n"
            "\n"
            "状态:\n"
            "    userIndex 存在 <状态目录>/userIndex（权限 0600），供 logout/reauth 使用。\n"
            "\n"
            "配置:\n"
            "    凭据从配置文件读取（key=value，# 注释），默认 %s，可用 --config\n"
            "    或 $CQIE_CONFIG 覆盖。三行即可：\n"
            "        user=学号\n"
            "        password=密码\n"
            "        service=运营商名      # 可留空，自动探测\n"
            "    建议权限 600。service 留空时自动探测运营商。\n"
            "    优先级：-u/-p/--service > 环境变量（CQIE_USER/CQIE_PASS/CQIE_SERVICE）\n"
            "    > 配置文件 > 编译期默认。"
#if USE_SYSLOG
            "\n"
            "系统日志:\n"
            "    每次运行都把认证结果写一条到 syslog（OpenWrt 上是 logd），查看：\n"
            "        logread | grep cqie-auth\n"
            "    只写结果行（认证成功/失败、注销成功/失败、在线状态），不含调试细节，\n"
            "    也不受 -q/-v 影响。单次关闭加 --no-syslog；整体关闭\n"
            "    用 make CFLAGS=-DUSE_SYSLOG=0。\n"
#endif
            ,
            CQIE_VERSION, argv0, STATE_DIR, argv0, CONFIG_FILE);
#endif
}

/* 取 --opt value / --opt=value 的值，没有则返回 NULL */
static const char* opt_val(int argc, char** argv, int* i, const char* name)
{
    const char* a = argv[*i];
    size_t n = strlen(name);
    if (!strncmp(a, name, n))
    {
        if (a[n] == '=') return a + n + 1;
        if (a[n] == 0 && *i + 1 < argc) return argv[++(*i)];
    }
    return NULL;
}

/*
 * 读凭据配置文件（key=value，# 注释；识别 user/password/service 三个键，
 * 其余忽略）。文件不存在返回 0（默认路径下这是正常的，属于可选项）。
 */
static int load_config_file(const char* path,
                            char* user, size_t usz,
                            char* pass, size_t psz,
                            char* svc, size_t ssz)
{
    FILE* fp = fopen(path, "r");
    if (!fp) return 0;

#ifndef _WIN32
    /* 权限检查：凭据文件应 600，过宽时提醒（Windows 无此模型，跳过） */
    struct stat st;
    if (stat(path, &st) == 0 && (st.st_mode & 077) != 0)
        fprintf(stderr, "[警告] 配置文件 %s 权限过宽，建议: chmod 600 %s\n",
                path, path);
#endif

    char line[512];
    while (fgets(line, sizeof line, fp))
    {
        char* s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == 0) continue;
        char* eq = strchr(s, '=');
        if (!eq) continue;
        *eq = 0;
        char* k = s;
        char* v = eq + 1;
        while (*v == ' ' || *v == '\t') v++; /* 去值前导空白 */
        size_t kl = strlen(k);
        while (kl && (k[kl - 1] == ' ' || k[kl - 1] == '\t')) k[--kl] = 0;
        size_t vl = strlen(v);
        while (vl && (v[vl - 1] == '\n' || v[vl - 1] == '\r' ||
                      v[vl - 1] == ' ' || v[vl - 1] == '\t'))
            v[--vl] = 0;
        if (!strcmp(k, "user")) snprintf(user, usz, "%s", v);
        else if (!strcmp(k, "password")) snprintf(pass, psz, "%s", v);
        else if (!strcmp(k, "service")) snprintf(svc, ssz, "%s", v);
        /* 其余键忽略：允许用户加自定义备注行 */
    }
    fclose(fp);
    return 1;
}

int main(int argc, char** argv)
{
    compat_console_utf8(); /* Windows：控制台码页切 UTF-8，否则中文乱码 */

    const char *cmd = NULL, *arg = NULL;
    const char *log_file = NULL, *state_opt = NULL, *portal_opt = NULL, *iface = NULL;
    const char *cfg_opt = NULL;
    const char *cli_user = NULL, *cli_pass = NULL, *cli_svc = NULL;
    int verbose = 0, quiet = 0, dry_run = 0, force = 0, plain = 0, no_syslog = 0;

    for (int i = 1; i < argc; i++)
    {
        const char* a = argv[i];
        if (a[0] == '-' && a[1] == 'v')
        {
            /* -v / -vv / -vvv */
            for (const char* p = a + 1; *p == 'v'; p++) verbose++;
            continue;
        }
        if (!strcmp(a, "--verbose"))
        {
            verbose++;
            continue;
        }
        if (!strcmp(a, "-q") || !strcmp(a, "--quiet"))
        {
            quiet = 1;
            continue;
        }
        if (!strcmp(a, "--dry-run"))
        {
            dry_run = 1;
            continue;
        }
        if (!strcmp(a, "--force"))
        {
            force = 1;
            continue;
        }
        if (!strcmp(a, "--plain"))
        {
            plain = 1;
            continue;
        }
        if (!strcmp(a, "--no-syslog"))
        {
            no_syslog = 1;
            continue;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help"))
        {
            usage(stdout, argv[0]);
            return 0;
        }
        if (!strcmp(a, "--version") || !strcmp(a, "-V"))
        {
            printf("cqie-auth %s\n", CQIE_VERSION);
            return 0;
        }
        const char* v;
        if ((v = opt_val(argc, argv, &i, "--log")))
        {
            log_file = v;
            continue;
        }
        if ((v = opt_val(argc, argv, &i, "--state-dir")))
        {
            state_opt = v;
            continue;
        }
        if ((v = opt_val(argc, argv, &i, "--portal")))
        {
            portal_opt = v;
            continue;
        }
        if ((v = opt_val(argc, argv, &i, "--interface")))
        {
            iface = v;
            continue;
        }
        if ((v = opt_val(argc, argv, &i, "--config")))
        {
            cfg_opt = v;
            continue;
        }
        if ((v = opt_val(argc, argv, &i, "-u")) || (v = opt_val(argc, argv, &i, "--user")))
        {
            cli_user = v;
            continue;
        }
        if ((v = opt_val(argc, argv, &i, "-p")) || (v = opt_val(argc, argv, &i, "--password")))
        {
            cli_pass = v;
            continue;
        }
        if ((v = opt_val(argc, argv, &i, "--service")))
        {
            cli_svc = v;
            continue;
        }
        if (a[0] == '-' && a[1])
        {
            fprintf(stderr, "未知选项: %s\n\n", a);
            usage(stderr, argv[0]);
            return 2;
        }
        if (!cmd) cmd = a;
        else if (!arg) arg = a;
        else
        {
            fprintf(stderr, "多余的参数: %s\n\n", a);
            usage(stderr, argv[0]);
            return 2;
        }
    }

    if (!cmd)
    {
        usage(stderr, argv[0]);
        return 2;
    }
    if (!strcmp(cmd, "help"))
    {
        usage(stdout, argv[0]);
        return 0;
    }

    /*
     * 调试档次（对外语义，见 config.h）：0=正常 1=流程 2=HTTP细节 3=全部
     * 内部级别比它大一档（WARN/INFO/DEBUG/TRACE）。
     * 优先级：-q > -v 个数 > $CQIE_DEBUG > 编译期 DEBUG_DEFAULT
     */
    int level;
    if (quiet)
    {
        level = LOG_LEVEL_QUIET;
    }
    else
    {
        int dlevel;
        if (verbose > 0)
        {
            dlevel = verbose;
        }
        else
        {
            const char* env = getenv("CQIE_DEBUG");
            dlevel = DEBUG_DEFAULT;
            if (env && env[0]) dlevel = atoi(env);
        }
        if (dry_run && dlevel < 1) dlevel = 1; /* dry-run 自动带流程日志 */
        if (dlevel < 0) dlevel = 0;
        if (dlevel > 3) dlevel = 3;
        level = LOG_LEVEL_WARN + dlevel;
    }
    log_init(level, log_file);
    log_set_syslog(!no_syslog); /* --no-syslog：本次运行不写 syslog 状态行 */

    /* 凭据配置文件：--config > $CQIE_CONFIG > 编译期默认（可选文件，缺席不报错） */
    {
        char cfg_user[128] = "", cfg_pass[256] = "", cfg_svc[128] = "";
        const char* cfg_path = cfg_opt ? cfg_opt : getenv("CQIE_CONFIG");
        int explicit_cfg = cfg_opt != NULL; /* 只有 --config 缺文件才报错；env 静默 */
        if (!cfg_path) cfg_path = CONFIG_FILE;
        if (load_config_file(cfg_path, cfg_user, sizeof cfg_user,
                             cfg_pass, sizeof cfg_pass, cfg_svc, sizeof cfg_svc))
        {
            LOG_DEBUG("凭据配置: %s", cfg_path);
        }
        else if (explicit_cfg)
        {
            fprintf(stderr, "配置文件不存在或不可读: %s\n\n", cfg_path);
            usage(stderr, argv[0]);
            return 2;
        }
        auth_set_credentials(cfg_user, cfg_pass, cfg_svc);
        /* 分层覆盖：配置文件 < 环境变量 < 命令行（setter 非空即覆盖，低→高依次调用） */
        auth_set_credentials(getenv("CQIE_USER"), getenv("CQIE_PASS"),
                             getenv("CQIE_SERVICE"));
        auth_set_credentials(cli_user, cli_pass, cli_svc);
    }
    LOG_DEBUG("日志级别=%d (0=正常 1=流程 2=HTTP细节 3=全部)%s", level - LOG_LEVEL_WARN,
              log_file ? "，同时写入日志文件" : "");

    state_init(state_opt);
    auth_set_portal(portal_opt);
    auth_set_dry_run(dry_run);
    auth_set_plain(plain);
    if (iface && http_set_source_ip(iface) != 0)
    {
        fprintf(stderr, "无效的源 IP: %s（--interface 需要 IPv4 地址，如 192.168.5.117）\n\n",
                iface);
        usage(stderr, argv[0]);
        return 2;
    }

    int ret;
    if (!strcmp(cmd, "login")) ret = cmd_login(force);
    else if (!strcmp(cmd, "reauth")) ret = cmd_reauth(arg);
    else if (!strcmp(cmd, "logout")) ret = cmd_logout(arg);
    else if (!strcmp(cmd, "status")) ret = cmd_status();
    else if (!strcmp(cmd, "userindex")) ret = cmd_userindex(arg);
    else
    {
        fprintf(stderr, "未知命令: %s\n\n", cmd);
        usage(stderr, argv[0]);
        ret = 2;
    }
    log_close();
    sock_quit(); /* POSIX 下是空操作；Windows 释放 Winsock */
    return ret;
}
