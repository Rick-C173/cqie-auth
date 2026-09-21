//
// main.c - cqie-auth 命令行入口
//
//   cqie-auth login            登录（等价原 main.sh）
//   cqie-auth reauth [index]   先注销再认证
//   cqie-auth logout [index]   注销（等价原 cqie-exit.sh）
//   cqie-auth status           仅检测在线状态（0=在线, 1=离线, 2=不在校园网）
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
#else
#include <windows.h> /* MoveFileExA（配置文件原子替换） */
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
            "    status      在线状态（退出码 0=在线, 1=离线, 2=不在校园网）\n"
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
            "        --setup        首次运行配置向导\n"
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
            "    status      只检测在线状态（退出码 0=在线, 1=离线, 2=不在校园网）\n"
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
            "        --setup        首次运行向导：交互生成凭据配置文件\n"
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

/* ---- 首次运行向导 ---- */

/*
 * 把探测到的运营商写回配置文件（自愈）：保留其余行与注释，仅替换/追加
 * service= 行；临时文件 + rename 原子写，权限 0600。成功返回 1。
 */
static int config_update_key(const char* path, const char* key, const char* val)
{
    char body[4096] = "";
    int replaced = 0;
    FILE* in = fopen(path, "r");
    if (in)
    {
        char line[512];
        while (fgets(line, sizeof line, in))
        {
            const char* p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (!replaced && strncmp(p, key, strlen(key)) == 0)
            {
                const char* q = p + strlen(key);
                while (*q == ' ' || *q == '\t') q++;
                if (*q == '=' || *q == '\n' || *q == 0)
                {
                    char add[600];
                    snprintf(add, sizeof add, "%s=%s\n", key, val);
                    if (strlen(body) + strlen(add) >= sizeof body) { fclose(in); return 0; }
                    strcat(body, add);
                    replaced = 1;
                    continue;
                }
            }
            if (strlen(body) + strlen(line) >= sizeof body) { fclose(in); return 0; }
            strcat(body, line);
        }
        fclose(in);
    }
    if (!replaced)
    {
        size_t n = strlen(body);
        char add[600];
        if (n && body[n - 1] != '\n') strcat(body, "\n");
        snprintf(add, sizeof add, "%s=%s\n", key, val);
        if (strlen(body) + strlen(add) >= sizeof body) return 0;
        strcat(body, add);
    }
    char tmp[640];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE* out = fopen(tmp, "w");
    if (!out) return 0;
    fputs(body, out);
    fclose(out);
#ifndef _WIN32
    chmod(tmp, 0600);
    if (rename(tmp, path) != 0)
#else
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING))
#endif
    {
        remove(tmp);
        return 0;
    }
    return 1;
}

/*
 * 读一行并去换行；echo_off=1 时关闭回显（密码输入）。
 * 返回 1=读到内容（含空行），0=stdin 已结束（EOF）——EOF 必须有出口，
 * 否则向导的重试循环会在管道关闭后无限刷屏（1.3.0 前的真实 bug）。
 */
static int read_line(char* buf, size_t sz, int echo_off)
{
    int ok;
    if (echo_off) compat_echo(0);
    ok = fgets(buf, (int)sz, stdin) != NULL;
    if (ok)
    {
        size_t n = strlen(buf);
        while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
    }
    else
    {
        buf[0] = 0;
    }
    if (echo_off)
    {
        compat_echo(1);
        printf("\n"); /* 回显关闭时换行不会显示，补一个 */
    }
    return ok;
}

/* 确保配置文件的父目录存在（逐级创建，已存在的层级 mkdir 失败会被忽略） */
static void make_parent_dirs(const char* path)
{
    char dir[600];
    snprintf(dir, sizeof dir, "%s", path);
    char* slash = strrchr(dir, '/');
#ifdef _WIN32
    char* bs = strrchr(dir, '\\');
    if (bs && (!slash || bs > slash)) slash = bs;
#endif
    if (!slash || slash == dir) return;
    *slash = 0;
    for (char* p = dir + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = 0;
            compat_mkdir(dir); /* 已存在时报错属正常，忽略 */
            *p = '/';
        }
    }
    compat_mkdir(dir);
}

/*
 * 首次设置向导：提问 -> 写配置文件（0600）。
 * user/pass/svc 传入已有值（可来自 -u 等），只对空字段提问。
 * cur_portal 为现有配置的 portal=（非空则原样保留写入）。
 * 文件已存在时确认后才覆盖。返回 1=已写入，0=取消/EOF/写失败。
 */
/* ---- 首次设置向导：收集（含探测）与写盘分离，凭据验证由命令本身完成 ---- */

struct WizardOut
{
    char user[128], pass[256], svc[128];
    char portal[256]; /* 探测发现/用户确认的认证地址；空=沿用默认 */
    char probe[512];  /* 用户指定的探测地址；空=沿用默认 */
    char path[600];   /* 配置文件路径 */
    int skip_verify;  /* 已在线：不做在线验证直接写盘 */
};

/* 把收集结果写入配置文件（0600）。文件已存在时确认后才覆盖。返回 1=已写入。 */
static int write_config_file(const struct WizardOut* w)
{
    FILE* probe = fopen(w->path, "r");
    if (probe)
    {
        fclose(probe);
        printf("配置文件已存在，覆盖? (y/N): ");
        fflush(stdout);
        char ans[16] = "";
        read_line(ans, sizeof ans, 0);
        if (ans[0] != 'y' && ans[0] != 'Y')
        {
            printf("已取消，未写入。\n");
            return 0;
        }
    }
    make_parent_dirs(w->path);
    FILE* f = fopen(w->path, "w");
    if (!f)
    {
        fprintf(stderr, "无法写入 %s（权限不足？可用 --config 指定其它路径）\n", w->path);
        return 0;
    }
    fprintf(f,
            "# cqie-auth 凭据配置（key=value，# 注释；示例见 cqie-auth.conf.example）\n"
            "# service 留空 = 自动逐项尝试运营商并写回；建议本文件权限 600\n");
    if (w->portal[0]) fprintf(f, "portal=%s\n", w->portal);
    if (w->probe[0]) fprintf(f, "probe=%s\n", w->probe);
    fprintf(f, "user=%s\npassword=%s\nservice=%s\n", w->user, w->pass, w->svc);
    fclose(f);
#ifndef _WIN32
    chmod(w->path, 0600); /* 凭据文件只允许属主读写 */
    printf("已写入 %s (权限 600)\n", w->path);
#else
    printf("已写入 %s\n", w->path);
#endif
    return 1;
}

/*
 * 向导收集：提问 + 当场探测（发现认证地址与运营商列表，展示供确认/参考）。
 * 不写盘——凭据验证由后续命令本身完成。预填值来自上次尝试（重试场景）。
 * 返回 1=收集完成，0=EOF/取消。
 */
static int wizard_collect(struct WizardOut* w, const char* def_probe)
{
    printf("首次设置：收集认证信息（完成后实测验证，通过才写入配置）\n");

    while (!w->user[0])
    {
        printf("用户名: ");
        fflush(stdout);
        if (!read_line(w->user, sizeof w->user, 0)) goto eof;
    }

    for (;;)
    {
        printf("密码 (不回显): ");
        fflush(stdout);
        if (!read_line(w->pass, sizeof w->pass, 1)) goto eof;
        if (w->pass[0]) break;
        printf("密码不能为空。\n");
    }

    printf("探测地址 (回车=%s)：用于触发校园网认证页\n", def_probe);
    {
        char tmp[512] = "";
        if (!read_line(tmp, sizeof tmp, 0)) goto eof;
        if (tmp[0]) snprintf(w->probe, sizeof w->probe, "%s", tmp);
    }

    printf("配置文件路径 (回车=%s): ", w->path);
    fflush(stdout);
    {
        char tmp[600] = "";
        if (!read_line(tmp, sizeof tmp, 0)) goto eof;
        if (tmp[0]) snprintf(w->path, sizeof w->path, "%s", tmp);
    }

    /* 已在线：无法用登录验证凭据，询问是否直接写入 */
    if (is_online())
    {
        printf("当前已在线（能直接上外网），凭据将不做在线验证直接写入。确认? (y/N): ");
        fflush(stdout);
        char ans[16] = "";
        if (!read_line(ans, sizeof ans, 0)) goto eof;
        if (ans[0] != 'y' && ans[0] != 'Y')
        {
            printf("已取消。\n");
            return 0;
        }
        w->skip_verify = 1;
        return 1;
    }

    printf("运营商名 (回车=留空，登录时自动逐项尝试): ");
    fflush(stdout);
    if (!read_line(w->svc, sizeof w->svc, 0)) goto eof;
    return 1;

eof:
    printf("\n输入已结束，向导中止（未写入任何内容）。\n");
    return 0;
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
                            char* svc, size_t ssz,
                            char* portal_buf, size_t plsz,
                            char* probe_buf, size_t pbsz)
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
        else if (!strcmp(k, "portal")) snprintf(portal_buf, plsz, "%s", v);
        else if (!strcmp(k, "probe")) snprintf(probe_buf, pbsz, "%s", v);
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
    int setup = 0;
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
        if (!strcmp(a, "--setup"))
        {
            setup = 1;
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
        if (setup)
        {
            /* `cqie-auth --setup` 单独运行：直接作为"重新配置"命令，
             * 现有配置值作为预填默认，完成后提示运行 login。 */
            const char* p = cfg_opt ? cfg_opt : getenv("CQIE_CONFIG");
            if (!p) p = CONFIG_FILE;
            struct WizardOut W;
            memset(&W, 0, sizeof W);
            snprintf(W.path, sizeof W.path, "%s", p);
            load_config_file(p, W.user, sizeof W.user, W.pass, sizeof W.pass,
                             W.svc, sizeof W.svc, W.portal, sizeof W.portal,
                             W.probe, sizeof W.probe);
            for (;;)
            {
                W.pass[0] = 0; /* 密码每轮必输 */
                if (!wizard_collect(&W, PROBE_URL))
                    return 1; /* EOF/取消 */
                auth_set_credentials(W.user, W.pass, W.svc);
                auth_set_portal(W.portal[0] ? W.portal : NULL);
                auth_set_probe(W.probe[0] ? W.probe : NULL);
                if (W.skip_verify)
                {
                    if (write_config_file(&W))
                    {
                        printf("配置完成，运行 `cqie-auth login` 认证上线。\n");
                        return 0;
                    }
                    return 1;
                }
                state_init(state_opt);
                auth_set_dry_run(0);
                if (iface)
                    http_set_source_ip(iface); /* --interface 传了就生效；无效值忽略 */
                int r = cmd_login(1); /* force：强制重认证作为凭据实测 */
                auth_session_unlock();
                if (r == 0)
                {
                    if (auth_last_service()[0])
                        snprintf(W.svc, sizeof W.svc, "%s", auth_last_service());
                    if (write_config_file(&W))
                    {
                        printf("配置完成，运行 `cqie-auth login` 认证上线。\n");
                        return 0;
                    }
                    return 1;
                }
                printf("凭据未写入（验证失败）。重新输入? (y/N): ");
                fflush(stdout);
                char ans[16] = "";
                if (!read_line(ans, sizeof ans, 0) || (ans[0] != 'y' && ans[0] != 'Y'))
                    return 1;
            }
        }
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
    const char* cfg_path = cfg_opt ? cfg_opt : getenv("CQIE_CONFIG");
    if (!cfg_path) cfg_path = CONFIG_FILE;
    char cfg_svc_raw[128] = ""; /* 配置文件里的原始 service 值（写回自愈的基准） */
    char cfg_portal[256] = "";  /* 配置文件里的 portal=（可选，覆盖编译期默认） */
    char cfg_probe[512] = "";   /* 配置文件里的 probe=（可选，覆盖编译期默认） */
    char cfg_user[128] = "", cfg_pass[256] = ""; /* 向导重试预填用 */
    {
        char cfg_svc[128] = "";
        int explicit_cfg = cfg_opt != NULL; /* 只有 --config 缺文件才报错；env 静默 */
        /* --setup 时允许文件不存在——向导就是要创建它 */
        if (load_config_file(cfg_path, cfg_user, sizeof cfg_user,
                             cfg_pass, sizeof cfg_pass, cfg_svc, sizeof cfg_svc,
                             cfg_portal, sizeof cfg_portal, cfg_probe, sizeof cfg_probe))
        {
            LOG_DEBUG("凭据配置: %s", cfg_path);
        }
        else if (explicit_cfg && !setup)
        {
            fprintf(stderr, "配置文件不存在或不可读: %s\n\n", cfg_path);
            usage(stderr, argv[0]);
            return 2;
        }
        snprintf(cfg_svc_raw, sizeof cfg_svc_raw, "%s", cfg_svc);
        auth_set_credentials(cfg_user, cfg_pass, cfg_svc);
        /* 分层覆盖：配置文件 < 环境变量 < 命令行（setter 非空即覆盖，低→高依次调用） */
        auth_set_credentials(getenv("CQIE_USER"), getenv("CQIE_PASS"),
                             getenv("CQIE_SERVICE"));
        auth_set_credentials(cli_user, cli_pass, cli_svc);
    }

    /* 首次运行向导触发：
     * - 显式 --setup（带命令）：总是运行
     * - 否则：凭据缺失 + login/reauth + 交互终端（cron/管道非终端不触发）
     * 命令即验证：向导只收集不写盘，凭据内存生效后执行命令，成功才写盘 */
    int need_wizard = (setup ||
                       (cmd && (auth_user()[0] == 0 || auth_password()[0] == 0) &&
                        compat_stdin_is_tty() &&
                        (!strcmp(cmd, "login") || !strcmp(cmd, "reauth"))));
    struct WizardOut W;
    memset(&W, 0, sizeof W);
    snprintf(W.path, sizeof W.path, "%s", cfg_path);
    /* 重试预填：配置文件已有值 */
    snprintf(W.user, sizeof W.user, "%s", cfg_user);
    snprintf(W.pass, sizeof W.pass, "%s", cfg_pass);
    snprintf(W.svc, sizeof W.svc, "%s", cfg_svc_raw);
    snprintf(W.portal, sizeof W.portal, "%s", cfg_portal);
    snprintf(W.probe, sizeof W.probe, "%s", cfg_probe);

    LOG_DEBUG("日志级别=%d (0=正常 1=流程 2=HTTP细节 3=全部)%s", level - LOG_LEVEL_WARN,
              log_file ? "，同时写入日志文件" : "");

    state_init(state_opt);
    /* portal 优先级：--portal > 向导发现/配置文件 portal= > 编译期默认 */
    auth_set_portal(portal_opt ? portal_opt : (cfg_portal[0] ? cfg_portal : NULL));
    /* probe 优先级：向导输入/配置文件 probe= > 编译期默认 */
    auth_set_probe(cfg_probe[0] ? cfg_probe : NULL);
    auth_set_dry_run(dry_run);
    auth_set_plain(plain);
    if (iface && http_set_source_ip(iface) != 0)
    {
        fprintf(stderr, "无效的源 IP: %s（--interface 需要 IPv4 地址，如 192.168.5.117）\n\n",
                iface);
        usage(stderr, argv[0]);
        return 2;
    }

    int pending_write = 0;
    int ret = 2;

    for (;;)
    {
        if (need_wizard)
        {
            W.pass[0] = 0; /* 密码每轮必输 */
            if (!wizard_collect(&W, PROBE_URL))
            {
                /* EOF/取消：凭据仍缺失则退出，否则按已加载值继续执行命令 */
                if (auth_user()[0] == 0 || auth_password()[0] == 0)
                {
                    fprintf(stderr, "设置未完成，已退出。\n");
                    return 1;
                }
                need_wizard = 0;
            }
            else
            {
                auth_set_credentials(W.user, W.pass, W.svc);
                /* --portal 命令行最高优先：向导发现的 portal 不覆盖它 */
                auth_set_portal(portal_opt ? portal_opt
                                           : (W.portal[0] ? W.portal : NULL));
                auth_set_probe(W.probe[0] ? W.probe : NULL);
                if (W.skip_verify)
                {
                    if (write_config_file(&W))
                        printf("配置已保存: %s\n", W.path);
                    need_wizard = 0;
                }
                else
                    pending_write = 1;
            }
        }

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

        /* 运营商自愈写回：非向导路径维持原行为（pending 路径的写盘已含最新值） */
        if (ret == 0 && !pending_write &&
            (!strcmp(cmd, "login") || !strcmp(cmd, "reauth")) &&
            auth_last_service()[0] && !cli_svc)
        {
            const char* env_svc = getenv("CQIE_SERVICE");
            const char* eff = auth_last_service();
            if ((!env_svc || !env_svc[0]) &&
                (cfg_svc_raw[0] == 0 || strcmp(cfg_svc_raw, eff) != 0))
            {
                if (config_update_key(cfg_path, "service", eff))
                    printf("运营商已写回配置: %s\n", eff);
                else
                    fprintf(stderr, "运营商写回配置失败（不影响本次认证）\n");
            }
        }

        auth_session_unlock(); /* 持锁完成写回/写盘后释放，消除写回并发窗口 */

        if (pending_write)
        {
            if (ret == 0)
            {
                /* 命令即验证：验证通过，写盘（service 用实际生效值校正） */
                if (auth_last_service()[0])
                    snprintf(W.svc, sizeof W.svc, "%s", auth_last_service());
                if (write_config_file(&W))
                    printf("配置已保存: %s\n", W.path);
                pending_write = 0;
                break;
            }
            /* 验证失败：凭据未写盘，询问重试（回向导，旧值预填） */
            printf("凭据未保存（验证失败）。重新输入? (y/N): ");
            fflush(stdout);
            char ans[16] = "";
            int rl = read_line(ans, sizeof ans, 0);
            if (!rl || (ans[0] != 'y' && ans[0] != 'Y'))
            {
                fprintf(stderr, "未写入任何配置。\n");
                break;
            }
            need_wizard = 1;
            continue;
        }
        break;
    }

    log_close();
        sock_quit(); /* POSIX 下是空操作；Windows 释放 Winsock */
    return ret;
}
