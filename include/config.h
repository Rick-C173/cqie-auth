//
// config.h - 校园网认证配置
//
// 所有默认值都用 #ifndef 包裹，因此可以在编译期用 -D 覆盖，例如：
//   make CFLAGS='-DPASSWORD="xxx"'
// 或在交叉编译 OpenWrt 包时通过 TARGET_CFLAGS 注入。
// 运行期可用命令行选项覆盖的项（--portal / --state-dir 等）见 cqie-auth help。
//
#ifndef CONFIG_H
#define CONFIG_H

#define CQIE_VERSION  "1.2.1"

/* ====== 认证信息 ======
 * 发布版凭据默认为空：运行时从配置文件读取（见 CONFIG_FILE，
 * key=value 三行：user= / password= / service=，# 注释）。
 * 也可用环境变量 CQIE_USER / CQIE_PASS / CQIE_SERVICE，或命令行
 * -u / -p / --service 临时覆盖。
 * 优先级：命令行 > 环境变量 > 配置文件 > 编译期默认。
 * 单文件党可用编译期注入（注意不要把带值的命令写进公开文档）：
 *   make CFLAGS='-DUSER_ID="xxx" -DPASSWORD="xxx" -DSERVICE_NAME="xxx"'
 * 优先级：配置文件 > 编译期默认。service 留空则自动探测（getServices）。 */
#ifndef USER_ID
#define USER_ID       ""
#endif
#ifndef PASSWORD
#define PASSWORD      ""
#endif
#ifndef SERVICE_NAME
#define SERVICE_NAME  ""
#endif
/* 凭据配置文件（可用 --config 或 $CQIE_CONFIG 覆盖） */
#ifndef CONFIG_FILE
#define CONFIG_FILE   "/etc/cqie-auth.conf"
#endif
#ifndef PORTAL_URL
#define PORTAL_URL    "http://10.253.3.84/eportal"
#endif
#ifndef PROBE_URL
#define PROBE_URL     "http://123.123.123.123"
#endif

/* 在线探测地址：任意一个返回 HTTP 204 即认为网络已通 */
#ifndef PROBE_204_LIST
#define PROBE_204_LIST \
    "http://204.ustclug.org/generate_204", \
    "http://connect.rom.miui.com/generate_204", \
    "http://wifi.vivo.com.cn/generate_204", \
    "http://connectivitycheck.gstatic.com/generate_204", \
    "http://connectivitycheck.platform.hicloud.com/generate_204"
#endif

/* ====== 行为开关 ====== */
#ifndef USE_ENCRYPT
#define USE_ENCRYPT   1        /* 1=RSA 加密提交密码  0=明文提交 */
#endif

#ifndef RSA_CHUNK
#define RSA_CHUNK     126      /* ohdave 风格分块大小（字节） */
#endif

/*
 * 分块十六进制补零方式：
 *   0 = 与原 shell 脚本一致：各分块十六进制拼接后，整体左侧补 '0' 到 4 的倍数
 *   1 = 每个分块各自左侧补 '0' 到模数十六进制宽度（1024bit 模数 -> 256 字符）
 * 密码 + mac 总长 <= 125 字节时只有一个分块，两种方式输出等价；
 * 只有使用超长密码（>125 字节）产生多个分块时才会有差别，
 * 此时若服务端按固定宽度切分密文，需要改成 1。
 */
#ifndef RSA_PAD_PER_BLOCK
#define RSA_PAD_PER_BLOCK 0
#endif

/* reauth（先注销再认证）里等 AC 释放上一个会话的时间，毫秒 */
#ifndef REAUTH_DELAY_MS
#define REAUTH_DELAY_MS   500
#endif

/* ====== 超时（秒） ====== */
#ifndef HTTP_TIMEOUT_S
#define HTTP_TIMEOUT_S         3   /* 原脚本 -m 3，路由器上适当放宽 */
#endif
#ifndef HTTP_CONNECT_TIMEOUT_S
#define HTTP_CONNECT_TIMEOUT_S 1   /* 原脚本 --connect-timeout 1 */
#endif
/*
 * 在线探测（PROBE_204_LIST）专用短超时：探测只需知道"通不通"。
 * 1.2.0 起所有地址并行发起（单 poll 循环），2s 是整组探测的总时限，
 * 最坏情况 = 2s（串行时代是 5 个地址逐个等，最坏 10s）。
 */
#ifndef PROBE_TIMEOUT_S
#define PROBE_TIMEOUT_S        2
#endif

/*
 * HTTP User-Agent。务必带上：本校园网的 AC 在请求缺少 UA 时会返回
 * 200 + 空 body（原脚本用的是 curl 命令行，curl 默认会发 UA，所以没踩到）。
 *
 * 默认伪装成 Windows 上的 Chrome：AC 只判断"有没有 UA"，不校验具体值，
 * 但浏览器 UA 不会在 AC 的设备指纹/日志里一眼暴露是命令行客户端。
 */
#ifndef HTTP_USER_AGENT
#define HTTP_USER_AGENT \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    " (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
#endif
/*
 * HTTP_USER_AGENT 留空时的后备值（自实现后端用）。历史遗留：最早用的
 * "curl/8.18.0"（curl 命令行的默认 UA），保留给想还原旧行为的人。
 */
#ifndef HTTP_USER_AGENT_FALLBACK
#define HTTP_USER_AGENT_FALLBACK "curl/8.18.0"
#endif

/*
 * 1 = 每次运行都把**认证结果**写一条到系统日志（syslog）。
 *
 * OpenWrt 上 syslog 由 logd 收，用 `logread` 查看，例如：
 *   logread | grep cqie-auth
 *   logread -e cqie-auth          # 只看匹配行
 *
 * 只写结果行（认证成功/失败、注销成功/失败、在线状态），不写调试细节；
 * 也没法用 -q 关掉——它是给 logread 留的审计轨迹，跟终端日志是两回事。
 * 宿主上没有 /dev/log 时会静默失败，不影响程序运行。
 * 0 = 完全关掉（不链 syslog 相关代码，省一点体积）。
 */
#ifndef USE_SYSLOG
#define USE_SYSLOG      1
#endif
/* syslog 里的程序名（logread 里显示为这个 [pid]） */
#ifndef SYSLOG_IDENT
#define SYSLOG_IDENT    "cqie-auth"
#endif
/*
 * 结果行的 syslog 优先级，默认 6 = LOG_INFO。
 * 标准优先级数值：0=emerg 1=alert 2=crit 3=err 4=warning 5=notice 6=info 7=debug
 * （用数字是为了让 config.h 不必包含 <syslog.h>）
 *
 * 注意：OpenWrt 的 logd 会按 /etc/config/system 里的 log_level 过滤。
 * 若你把它收紧过（比如 warning=4），info 会被丢掉，此时二选一：
 *   - 编译时改：-DSYSLOG_LEVEL=4
 *   - 或放宽 logd：uci set system.@system[0].log_level='notice'; uci commit; /etc/init.d/log restart
 */
#ifndef SYSLOG_LEVEL
#define SYSLOG_LEVEL    6
#endif

/* ====== 日志 ====== */
/* 未给 -v/-q 时的默认级别：0=正常(警告以上) 1=流程 2=HTTP细节 3=全部 */
#ifndef DEBUG_DEFAULT
#define DEBUG_DEFAULT          0
#endif
/*
 * 1 = 精简 --help/用法输出（去掉大段中文说明）。
 * OpenWrt 构建下打开，可以省几 KB 的 .rodata。
 */
#ifndef CQIE_MINIMAL_HELP
#define CQIE_MINIMAL_HELP      0
#endif
/* -vvv 时打印响应体的最大字节数，避免刷屏 */
#ifndef LOG_BODY_MAX
#define LOG_BODY_MAX           4096
#endif

/* ====== 状态文件（相对状态目录，见 state.h） ====== */
/* 状态目录：--state-dir > $CQIE_STATE_DIR > 本宏 */
#ifndef STATE_DIR
#define STATE_DIR     "/tmp/cqie-auth"
#endif
#ifndef UI_FILE
#define UI_FILE       "userIndex"   /* 登录成功后保存的 userIndex（logout/reauth 用） */
#endif
#ifndef NASIP_FILE
 #define NASIP_FILE    "nasip"       /* 登录时顺手存的 queryString.nasip（userIndex 丢失时拼接回退用） */
#endif

#endif /* CONFIG_H */
