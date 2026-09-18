#!/bin/bash
# tests/check.sh - 自检脚本（开发机上运行，路由器上不需要）
#
#   make check       或       bash tests/check.sh
#
# 三部分：
#   1) RSA 加密结果与“原 shell 脚本 + bc”的实现逐字节比对
#   2) 字符串解析（urlencode/字段提取/运营商/跳转/mac/hex 解码）与 shell 管道比对
#   3) 起一个模拟 AC 服务端，端到端跑 login/logout/status
#
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  [OK]   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; [ $# -gt 1 ] && printf '         期望: %s\n         实际: %s\n' "$2" "$3"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "== 0. 编译自检工具 =="
if ! ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -o "$TMP/harness" \
        "$ROOT/tests/harness.c" "$ROOT/src/bn.c" "$ROOT/src/rsa.c" "$ROOT/src/compat.c" "$ROOT/src/util.c"; then
    echo "编译 harness 失败"; exit 1
fi

# ---------------------------------------------------------------- 1. RSA
echo
echo "== 1. RSA 加密与原脚本(bc) 逐字节比对 =="
if ! have bc || ! have python3; then
    echo "  (缺少 bc 或 python3，跳过)"
else
    python3 - "$TMP" <<'PY'
import os, random, sys
tmp = sys.argv[1]
random.seed(20260913)
for bits, name in ((1024, "key1024.txt"), (2048, "key2048.txt")):
    n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
    open(os.path.join(tmp, name), "w").write("%x\n10001\n" % n)
PY
    MAC="4f3839eba7a850e699faecafa73feb81"
    for key in key1024 key2048; do
        E_HEX=$(sed -n 2p "$TMP/$key.txt")
        N_HEX=$(sed -n 1p "$TMP/$key.txt")
        for len in 3 12 126 127 130 252 253; do
            PWD_T=$(python3 -c "print('A'*$len)")
            C_OUT=$("$TMP/harness" rsa "$E_HEX" "$N_HEX" "$PWD_T" "$MAC")
            S_OUT=$(sh "$ROOT/tests/orig_rsa.sh" "$TMP/$key.txt" "$PWD_T" "$MAC")
            if [ "$C_OUT" = "$S_OUT" ]; then
                ok "$key  密码长度 $len  一致 (${#C_OUT} 字符)"
            else
                bad "$key  密码长度 $len  不一致" "${S_OUT:0:60}..." "${C_OUT:0:60}..."
            fi
        done
    done
fi

# ------------------------------------------------------- 2. 字符串解析
echo
echo "== 2. 字符串解析与 shell 管道比对 =="
sh_urlencode() {
    printf '%s' "$1" | LC_ALL=C awk 'BEGIN { for (i = 0; i < 256; i++) t[sprintf("%c", i)] = i }
    { n = length($0)
      for (i = 1; i <= n; i++) { c = substr($0, i, 1)
        if (c ~ /^[A-Za-z0-9._~-]$/) printf "%s", c; else printf "%%%02X", t[c] } } END { print "" }' \
    | head -c -1
}
sh_field()   { printf '%s' "$(cat "$2")" | tr ',' '\n' | sed -n "s/.*\"$1\"[^:]*:[ ]*\"\([^\"]*\)\".*/\1/p" | head -n1; }
sh_service() { printf '%s' "$(cat "$2")" | LC_ALL=C grep -o '<option[^>]*>[^<]*</option>' | LC_ALL=C grep -F "$1" | head -n1 | sed -n 's/.*value="\([^"]*\)".*/\1/p'; }
sh_redirect(){ sed -n "s/.*location\.href='\([^']*\)'.*/\1/p" "$1" | head -n1; }
sh_mac()     { printf '&%s' "$1" | sed -n 's/.*&mac=\([^&]*\).*/\1/p'; }
sh_hexdec()  { printf '%s' "$1" | xxd -r -p | awk '{print}'; }

cmp_sh() { # $1=名称 $2=C 输出 $3=shell 输出
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "[$3]" "[$2]"; fi
}

printf '%s' "<html><script>location.href='http://10.253.3.84/eportal/index.jsp?wlanuserip=1.2.3.4&wlanacname=AC&ssid=s&nasip=10.0.0.1&mac=4f3839eba7a850e699faecafa73feb81&t=wireless-v2';</script></html>" > "$TMP/probe.html"
printf '%s' '{"result":"success","publicKeyExponent":"010001","publicKeyModulus":"aabb","serviceList":[{"serviceName":"中国移动","serviceValue":"9"}],"message":""}' > "$TMP/info.json"
printf '%s' '{"version":"1.0","publicKeyExponent" :  "10001" ,"publicKeyModulus": "cafe","x":"y"}' > "$TMP/info2.json"
printf '%s' '<select><option value="1">校园网</option><option value="9" selected>中国移动</option></select>' > "$TMP/opts.html"

for s in "中国移动" "a b+c&d=e/f?g" "~-._AZaz09" ""; do
    cmp_sh "urlencode \"$s\"" "$("$TMP/harness" urlencode "$s")" "$(sh_urlencode "$s")"
done
cmp_sh "extract_field publicKeyExponent" "$("$TMP/harness" field publicKeyExponent "$TMP/info.json")" "$(sh_field publicKeyExponent "$TMP/info.json")"
cmp_sh "extract_field publicKeyModulus"  "$("$TMP/harness" field publicKeyModulus  "$TMP/info.json")" "$(sh_field publicKeyModulus  "$TMP/info.json")"
cmp_sh "extract_field 无该字段"           "$("$TMP/harness" field userIndex "$TMP/info.json")" "$(sh_field userIndex "$TMP/info.json")"
cmp_sh "extract_field 冒号前有空格"       "$("$TMP/harness" field publicKeyExponent "$TMP/info2.json")" "$(sh_field publicKeyExponent "$TMP/info2.json")"
cmp_sh "extract_service 命中"             "$("$TMP/harness" service 中国移动 "$TMP/opts.html")" "$(sh_service 中国移动 "$TMP/opts.html")"
cmp_sh "extract_service 无匹配"           "$("$TMP/harness" service 电信 "$TMP/opts.html")" "$(sh_service 电信 "$TMP/opts.html")"
cmp_sh "fetch_redirect_url"               "$("$TMP/harness" redirect "$TMP/probe.html")" "$(sh_redirect "$TMP/probe.html")"
cmp_sh "extract_mac"                      "$("$TMP/harness" mac 'wlanuserip=1&mac=4f38&t=x')" "$(sh_mac 'wlanuserip=1&mac=4f38&t=x')"
cmp_sh "extract_mac 多次出现取最后"       "$("$TMP/harness" mac 'mac=aaa&x=1&mac=bbb')" "$(sh_mac 'mac=aaa&x=1&mac=bbb')"
if have xxd; then
    for s in "6e6f6465313233343536" "6a7" "abcdEF" "6a7bXX" "6a 7b"; do
        cmp_sh "hex_print_decode \"$s\"" "$("$TMP/harness" hexdec "$s")" "$(sh_hexdec "$s")"
    done
fi

# ------------------------------------------- 2.5 USE_SYSLOG=0 分支可编译
echo
echo "== 2.5 关掉 syslog 时仍可构建（USE_SYSLOG=0 的空实现分支）=="
if ${CC:-cc} -O1 -std=c99 -I"$ROOT/include" -DUSE_SYSLOG=0 \
        -o "$TMP/nosyslog" "$ROOT"/src/*.c 2>"$TMP/nosyslog.err"; then
    if [ "$("$TMP/nosyslog" --version 2>/dev/null)" = "cqie-auth $(sed -n 's/^#define CQIE_VERSION *"\(.*\)"/\1/p' "$ROOT/include/config.h")" ]; then
        ok "USE_SYSLOG=0 可编译且能正常运行"
    else
        bad "USE_SYSLOG=0 构建产物运行异常" "输出版本号" "$("$TMP/nosyslog" --version 2>&1)"
    fi
else
    bad "USE_SYSLOG=0 时编译失败" "编译通过" "$(head -3 "$TMP/nosyslog.err")"
fi

# ------------------------------------------------------- 3. 端到端
echo
echo "== 3. 模拟 AC 端到端（login / reauth / logout / status / dry-run） =="
if ! have python3 || ! python3 -c 'import cryptography' 2>/dev/null; then
    echo "  (缺少 python3 或 cryptography 模块，跳过)"
else
    PORT=$((20000 + RANDOM % 20000))
    PWD_TEST="test-pass-123"
    # 测试凭据全部来自编译期注入；把默认配置文件指向不存在路径，
    # 防止读入开发机 /etc/cqie-auth.conf 的真实凭据（配置文件优先级更高）
    export CQIE_CONFIG="$TMP/no-such-cqie-auth.conf"
    cat > "$TMP/override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$PORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$PORT/probe"
#define USER_ID         "testuser"
#define PASSWORD        "$PWD_TEST"
#define SERVICE_NAME    "中国移动"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-default"
#define REAUTH_DELAY_MS 50
EOF
    if ! ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/override.h" \
            -o "$TMP/cqie-auth" "$ROOT"/src/*.c; then
        bad "编译带测试配置的 cqie-auth 失败"
    else
        python3 "$ROOT/tests/mock_ac.py" "$PORT" "$PWD_TEST" "$TMP/log.json" "$TMP/key.txt" \
            >/dev/null 2>"$TMP/mock.err" &
        MOCK_PID=$!
        # 等 mock 起来：用 TCP 探活，避免依赖宿主机的 curl 命令行
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" && break
            sleep 0.1
        done

        mkdir -p "$TMP/run"
        BIN="$TMP/cqie-auth"
        UI="$TMP/run/userIndex"
        UIDX="6e6f6465313233343536"
        UIDX_DEC="node123456"    # 上面的 hex 解码结果，stdout 里显示的是它

        # ---------- status：离线 ----------
        ( cd "$TMP" && "$BIN" status --state-dir "$TMP/run" ) >"$TMP/status.out" 2>&1
        [ "$?" = 1 ] && grep -q "未在线" "$TMP/status.out" \
            && ok "status: 离线返回 1 且输出「未在线」" \
            || bad "status: 离线应返回 1 并输出未在线" "1 未在线" "$(cat "$TMP/status.out")"

        # ---------- login ----------
        ( cd "$TMP" && "$BIN" login --state-dir "$TMP/run" ) >"$TMP/login.out" 2>"$TMP/login.err"
        LT=$?
        grep -q "认证成功！ userIndex: $UIDX" "$TMP/login.out" \
            && ok "login: 输出认证成功与原始 userIndex" \
            || bad "login: 未输出预期 userIndex" "认证成功！ userIndex: $UIDX" "$(cat "$TMP/login.out")"
        [ "$LT" = 0 ] && ok "login: 退出码 0" || bad "login: 退出码应为 0" "0" "$LT"
        [ "$(cat "$UI" 2>/dev/null | tr -d '\n')" = "$UIDX" ] \
            && ok "login: userIndex 写入 --state-dir 指定目录" \
            || bad "login: 状态文件内容不对" "$UIDX" "$(cat "$UI" 2>/dev/null)"
        [ "$(stat -c '%a' "$UI" 2>/dev/null)" = "600" ] \
            && ok "login: 状态文件权限 0600" \
            || bad "login: 状态文件权限应为 0600" "600" "$(stat -c '%a' "$UI" 2>/dev/null)"
        [ "$(cat "$TMP/run/nasip" 2>/dev/null | tr -d '\n')" = "10.0.0.1" ] \
            && ok "login: nasip 已从 queryString 存入状态目录（拼接回退的原料）" \
            || bad "login: nasip 文件缺失或内容不对" "10.0.0.1" "$(cat "$TMP/run/nasip" 2>/dev/null)"

        # ---------- userindex：读状态文件/显式传 hex，解码输出 ----------
        OUT=$("$BIN" userindex --state-dir "$TMP/run" 2>/dev/null)
        [ "$OUT" = "$UIDX_DEC" ] && ok "userindex: 读状态文件解码输出" \
            || bad "userindex: 解码输出不对" "$UIDX_DEC" "$OUT"
        OUT=$("$BIN" userindex "$UIDX" --state-dir "$TMP/run" 2>/dev/null)
        [ "$OUT" = "$UIDX_DEC" ] && ok "userindex: 显式传 hex 解码输出" \
            || bad "userindex: 显式 hex 解码不对" "$UIDX_DEC" "$OUT"
        "$BIN" userindex --state-dir "$TMP/empty" >/dev/null 2>&1
        [ "$?" = 1 ] && ok "userindex: 无状态文件返回 1" \
                   || bad "userindex: 无状态文件应返回 1"

        # ---------- reauth：先注销再认证 ----------
        ( cd "$TMP" && "$BIN" reauth --state-dir "$TMP/run" ) >"$TMP/reauth.out" 2>"$TMP/reauth.err"
        grep -q "下线成功" "$TMP/reauth.out" \
            && ok "reauth: 第一步确实先注销" \
            || bad "reauth: 没有先注销" "含「下线成功」" "$(head -c 200 "$TMP/reauth.out")"
        grep -q "认证成功！ userIndex: $UIDX" "$TMP/reauth.out" \
            && ok "reauth: 第二步重新认证成功" \
            || bad "reauth: 重新认证失败" "含 userIndex" "$(head -c 200 "$TMP/reauth.out")"
        [ "$(cat "$UI" 2>/dev/null | tr -d '\n')" = "$UIDX" ] \
            && ok "reauth: 认证后状态文件被重新写入" \
            || bad "reauth: 状态文件应被重新写入"

        # ---------- logout：成功后清理状态 ----------
        ( cd "$TMP" && "$BIN" logout --state-dir "$TMP/run" ) >"$TMP/logout.out" 2>&1
        grep -q "下线成功" "$TMP/logout.out" \
            && ok "logout: 服务端返回注销成功" \
            || bad "logout: 未拿到注销成功" "含「下线成功」" "$(cat "$TMP/logout.out")"
        [ ! -f "$UI" ] && ok "logout: 成功后清理了状态文件" \
                       || bad "logout: 成功后状态文件应被删除"

        # ---------- dry-run：不提交登录 ----------
        CNT_BEFORE=$(python3 -c "import json;print(json.load(open('$TMP/log.json'))['counts']['login'])")
        ( cd "$TMP" && "$BIN" login --dry-run --state-dir "$TMP/run" ) >"$TMP/dry.out" 2>&1
        CNT_AFTER=$(python3 -c "import json;print(json.load(open('$TMP/log.json'))['counts']['login'])")
        [ "$CNT_BEFORE" = "$CNT_AFTER" ] && ok "dry-run: 没有提交 login 请求（仍为 $CNT_AFTER 次）" \
            || bad "dry-run: 不应提交 login" "$CNT_BEFORE" "$CNT_AFTER"
        grep -q "RSA 公钥" "$TMP/dry.out" && ok "dry-run: 打印了公钥信息" \
            || bad "dry-run: 未打印公钥" "含「RSA 公钥」" "$(head -c 200 "$TMP/dry.out")"
        grep -q "password=<" "$TMP/dry.out" && ok "dry-run: 表单里的密码已打码" \
            || bad "dry-run: 表单应打印且密码打码" "含 password=<" "$(head -c 300 "$TMP/dry.out")"

        # ---------- 调试开关 / 状态目录优先级 ----------
        ( cd "$TMP" && CQIE_DEBUG=1 "$BIN" status ) >"$TMP/env.out" 2>"$TMP/env.err"
        grep -q "在线探测" "$TMP/env.err" \
            && ok "CQIE_DEBUG=1 生效（stderr 有流程日志）" \
            || bad "CQIE_DEBUG=1 未生效" "stderr 含「在线探测」" "$(head -c 200 "$TMP/env.err")"
        [ -d "$TMP/state-default" ] && ok "未指定 --state-dir 时使用编译期 STATE_DIR" \
                                    || bad "未使用编译期 STATE_DIR" "$TMP/state-default 应存在" "不存在"
        ( cd "$TMP" && CQIE_STATE_DIR="$TMP/state-env" "$BIN" status --state-dir "$TMP/run" ) >/dev/null 2>&1
        [ ! -d "$TMP/state-env" ] && ok "优先级: 命令行 --state-dir 覆盖 \$CQIE_STATE_DIR" \
            || bad "优先级不对: 命令行未覆盖环境变量"
        ( cd "$TMP" && CQIE_STATE_DIR="$TMP/state-env" "$BIN" status ) >/dev/null 2>&1
        [ -d "$TMP/state-env" ] && ok "环境变量 CQIE_STATE_DIR 被采用" \
            || bad "环境变量 CQIE_STATE_DIR 未生效"

        RES=$(python3 - "$TMP/log.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
c = d.get("counts") or {}
lg = d.get("login") or {}
lo = d.get("logout") or {}
pid = d.get("pageinfo") or {}
print("requests=%s" % ",".join(d.get("requests") or []))
print("login_count=%s" % c.get("login"))
print("logout_count=%s" % c.get("logout"))
print("match=%s" % ("PASS" if lg.get("match") else "FAIL"))
print("enc=%s" % lg.get("passwordEncrypt"))
print("service=%s" % lg.get("service"))
print("userid=%s" % lg.get("userId"))
print("double_enc=%s" % ("PASS" if pid.get("queryString_double_encoded") else "FAIL"))
print("user_agent=%s" % (pid.get("user_agent") or "(空)"))
print("logout_index=%s" % ("PASS" if lo.get("userIndex") == "6e6f6465313233343536" else "FAIL"))
print("getservices_count=%d" % c.get("getservices", 0))
print("gs_search_prefix=%s" % (d.get("getservices", {}).get("search", "")[:3]))
print("plain=%s" % (lg.get("password_decrypted") or ""))
print("xrw=%s" % (pid.get("xrw") or "(空)"))
print("origin=%s" % (pid.get("origin") or "(空)"))
print("pg_referer=%s" % (pid.get("referer") or "(空)"))
print("login_referer=%s" % (lg.get("referer") or "(空)"))
PY
)
        echo "$RES" | sed 's/^/          /'
        echo "$RES" | grep -q "^match=PASS"          && ok "服务端用私钥解出的密码 == 密码>mac" || bad "服务端解出的密码不匹配"
        echo "$RES" | grep -q "^enc=true"            && ok "passwordEncrypt=true"           || bad "passwordEncrypt 应为 true"
        echo "$RES" | grep -q "^service=中国移动"     && ok "service 取自 getServices 列表"   || bad "service 取值不对"
        echo "$RES" | grep -q "^double_enc=PASS"     && ok "pageInfo 的 queryString 二次编码" || bad "queryString 未二次编码"
        echo "$RES" | grep -q "^getservices_count=3" && ok "getServices 请求 3 次（login + reauth + dry-run）" || bad "getServices 次数不对"
        echo "$RES" | grep -q "^gs_search_prefix=?wl" && ok "getServices 的 search 为 ?+queryString（服务端解码后）" || bad "search 前缀不对"
        echo "$RES" | grep -q "^logout_index=PASS"   && ok "logout 带回同一个 userIndex"     || bad "logout 的 userIndex 不对"
        echo "$RES" | grep -q "^login_count=2"       && ok "login 请求 2 次（login + reauth）"  || bad "login 次数不对"
        echo "$RES" | grep -q "^logout_count=2"      && ok "logout 请求 2 次（reauth + logout）" || bad "logout 次数不对"
        echo "$RES" | grep -q "^requests=pageInfo,getServices,login,logout,pageInfo,getServices,login,logout,pageInfo,getServices" \
            && ok "请求顺序: login(getServices) → reauth(logout+login) → logout → dry-run" \
            || bad "请求顺序不符预期" "pageInfo,getServices,login,logout,pageInfo,getServices,login,logout,pageInfo,getServices" \
                   "$(echo "$RES" | sed -n 's/^requests=//p')"
        UA=$(echo "$RES" | sed -n 's/^user_agent=//p')
        if echo "$UA" | grep -q "^Mozilla/"; then
            ok "请求带浏览器 User-Agent（缺失时 AC 会返回空 body）: $UA"
        else
            bad "UA 不是浏览器形式或缺失（真实 AC 会因缺失返回空 body）" "Mozilla/5.0 ..." "${UA:-（空）}"
        fi
        echo "$RES" | grep -q "^xrw=XMLHttpRequest" \
            && ok "pageInfo 带 X-Requested-With（登录页 JS 是 jQuery ajax）" \
            || bad "缺少 X-Requested-With 头" "XMLHttpRequest" "$(echo "$RES" | sed -n 's/^xrw=//p')"
        echo "$RES" | grep -q "^origin=http://127.0.0.1:$PORT$" \
            && ok "pageInfo 带 Origin（缺省端口省略，与浏览器一致）" \
            || bad "Origin 不对" "http://127.0.0.1:$PORT" "$(echo "$RES" | sed -n 's/^origin=//p')"
        echo "$RES" | grep -q "^pg_referer=http://127.0.0.1:$PORT/eportal/index.jsp?" \
            && ok "pageInfo 带同源 Referer" \
            || bad "pageInfo 缺 Referer" "http://…/index.jsp?…" "$(echo "$RES" | sed -n 's/^pg_referer=//p')"
        echo "$RES" | grep -q "^login_referer=http://127.0.0.1:$PORT/eportal/index.jsp?" \
            && ok "login 带同源 Referer" \
            || bad "login 缺 Referer" "http://…/index.jsp?…" "$(echo "$RES" | sed -n 's/^login_referer=//p')"
        kill "$MOCK_PID" 2>/dev/null
        MOCK_PID=""
    fi
fi

# --------------------------------------------------- 3.4 login --force
echo
echo "== 3.4 login --force（跳过已在线短路） =="
if ! have python3 || ! python3 -c 'import cryptography' 2>/dev/null; then
    echo "  (缺少 python3 或 cryptography 模块，跳过)"
else
    FPORT=$((20000 + RANDOM % 20000))
    cat > "$TMP/f_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$FPORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$FPORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-force"
#define USER_ID         "testuser"
#define PASSWORD        "$PWD_TEST"
#define REAUTH_DELAY_MS 50
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/f_override.h" \
            -o "$TMP/cqie-force" "$ROOT"/src/*.c 2>"$TMP/force_cc.err"; then
        python3 "$ROOT/tests/mock_ac.py" "$FPORT" "$PWD_TEST" "$TMP/f_log.json" "$TMP/key.txt" \
            >/dev/null 2>&1 &
        FORCE_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$FPORT))==0 else 1)" && break
            sleep 0.1
        done

        ( cd "$TMP" && CQIE_DEBUG=1 "$TMP/cqie-force" login --force --state-dir "$TMP/run" \
            ) >"$TMP/force.out" 2>"$TMP/force.err"
        FT=$?
        [ "$FT" = 0 ] && grep -q "认证成功" "$TMP/force.out" \
            && ok "login --force: 强制重走认证成功" \
            || bad "login --force: 应成功完成认证" "退出码 0 且含「认证成功」" "$FT $(tail -2 "$TMP/force.err")"
        grep -q "force 模式" "$TMP/force.err" \
            && ok "login --force: 调试日志显示 force 模式生效" \
            || bad "login --force: 未进入 force 模式" "stderr 含「force 模式」" "$(tail -2 "$TMP/force.err")"
        python3 -c "import json;print('force_login_count=%d' % json.load(open('$TMP/f_log.json'))['counts']['login'])" \
            | grep -q "^force_login_count=1" \
            && ok "login --force: 服务端收到 1 次登录" \
            || bad "login --force: 登录次数不对" "1" "$(python3 -c "import json;print(json.load(open('$TMP/f_log.json'))['counts']['login'])")"
        kill $FORCE_MOCK 2>/dev/null
    else
        bad "login --force: 编译失败" "编译通过" "$(head -3 "$TMP/force_cc.err")"
    fi
fi

# --------------------------------------------------- 3.5 并行探测：命中 204
echo
echo "== 3.5 并行在线探测（204 命中路径） =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    PPORT=$((30000 + RANDOM % 20000))
    python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', $PPORT), H).serve_forever()
" >/dev/null 2>&1 &
    P204_PID=$!
    for _ in $(seq 1 50); do
        python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$PPORT))==0 else 1)" && break
        sleep 0.1
    done

    cat > "$TMP/p204.h" <<EOF
#define PROBE_204_LIST  "http://127.0.0.1:$PPORT/generate_204"
#define STATE_DIR        "$TMP/state-p204"
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/p204.h" \
            -o "$TMP/cqie-p204" "$ROOT"/src/*.c 2>"$TMP/p204.err"; then
        ( cd "$TMP" && CQIE_DEBUG=1 "$TMP/cqie-p204" status ) >"$TMP/p204.out" 2>&1
        RT=$?
        [ "$RT" = 0 ] && grep -q "已在线" "$TMP/p204.out" \
            && ok "并行探测: 命中 204 判定已在线" \
            || bad "并行探测: 命中 204 应输出已在线且退出码 0" "0 已在线" "$RT $(cat "$TMP/p204.out")"
        grep -q "命中 204" "$TMP/p204.out" \
            && ok "并行探测: 探测日志里报告命中" \
            || bad "并行探测: 未报告命中" "含「命中 204」" "$(cat "$TMP/p204.out")"
    else
        bad "并行探测: 编译失败" "编译通过" "$(head -3 "$TMP/p204.err")"
    fi
    kill $P204_PID 2>/dev/null
fi

# --------------------------------------------------- 3.6 userIndex 拼接回退
echo
echo "== 3.6 logout 的 userIndex 拼接回退（hex(nasip_本机IP_账号)） =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    SPORT=$((20000 + RANDOM % 20000))
    cat > "$TMP/s_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$SPORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$SPORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-synth"
#define USER_ID         "testuser"
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/s_override.h" \
            -o "$TMP/cqie-synth" "$ROOT"/src/*.c 2>"$TMP/synth_cc.err"; then
        # noredirect：本节专测拼接回退，关掉 redirect 路由让服务端要回失败
        python3 "$ROOT/tests/mock_ac.py" "$SPORT" "$PWD_TEST" "$TMP/s_log.json" "$TMP/key.txt" noredirect \
            >/dev/null 2>&1 &
        SYNTH_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$SPORT))==0 else 1)" && break
            sleep 0.1
        done

        mkdir -p "$TMP/state-synth"
        # 期望值：mock 劫持页里的 nasip=10.0.0.1；本机回环 IP 恒为 127.0.0.1；
        # 账号用编译期默认 USER_ID
        SYNTH_HEX=$(python3 -c "print('10.0.0.1_127.0.0.1_testuser'.encode().hex())")

        # 场景 A：没有 userIndex 文件、只有 nasip -> 直接拼接注销
        printf '10.0.0.1' > "$TMP/state-synth/nasip"
        ( cd "$TMP" && "$TMP/cqie-synth" logout --state-dir "$TMP/state-synth" ) \
            >"$TMP/synth.out" 2>"$TMP/synth.err"
        grep -q "下线成功" "$TMP/synth.out" \
            && ok "拼接回退 A: 无 userIndex 文件时拼接注销成功" \
            || bad "拼接回退 A: 应注销成功" "含「下线成功」" "$(cat "$TMP/synth.out")"
        A_IDX=$(python3 -c "import json;print(json.load(open('$TMP/s_log.json'))['logout']['userIndex'])")
        [ "$A_IDX" = "$SYNTH_HEX" ] \
            && ok "拼接回退 A: 服务端收到 hex(10.0.0.1_127.0.0.1_testuser)" \
            || bad "拼接回退 A: userIndex 值不对" "$SYNTH_HEX" "$A_IDX"

        # 场景 B：存储的 userIndex 被服务端拒绝（FORCEFAIL）-> 失败后自动改用拼接值
        printf 'FORCEFAIL' > "$TMP/state-synth/userIndex"
        ( cd "$TMP" && "$TMP/cqie-synth" logout --state-dir "$TMP/state-synth" ) \
            >"$TMP/synth2.out" 2>"$TMP/synth2.err"
        grep -q "下线成功" "$TMP/synth2.out" \
            && ok "拼接回退 B: 存储值被拒后自动改用拼接值重试成功" \
            || bad "拼接回退 B: 重试应成功" "含「下线成功」" "$(cat "$TMP/synth2.out")"
        [ ! -f "$TMP/state-synth/userIndex" ] \
            && ok "拼接回退 B: 成功后清理了失效的 userIndex 文件" \
            || bad "拼接回退 B: 失效文件应被删除"
        B_CNT=$(python3 -c "import json;print(json.load(open('$TMP/s_log.json'))['counts']['logout'])")
        [ "$B_CNT" = "3" ] \
            && ok "拼接回退 B: 服务端共收到 3 次注销（A 1 次 + B 先拒后成 2 次）" \
            || bad "拼接回退 B: 注销次数不对" "3" "$B_CNT"
        kill $SYNTH_MOCK 2>/dev/null
    else
        bad "拼接回退: 编译失败" "编译通过" "$(head -3 "$TMP/synth_cc.err")"
    fi
fi

# --------------------------------------------------- 3.7 --plain 明文提交
echo
echo "== 3.7 login --plain（密码明文提交，passwordEncrypt=false） =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    PPORT=$((20000 + RANDOM % 20000))
    cat > "$TMP/p_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$PPORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$PPORT/probe"
#define PASSWORD        "$PWD_TEST"
#define USER_ID         "testuser"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-plain"
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/p_override.h" \
            -o "$TMP/cqie-plain" "$ROOT"/src/*.c 2>"$TMP/plain_cc.err"; then
        python3 "$ROOT/tests/mock_ac.py" "$PPORT" "$PWD_TEST" "$TMP/p_log.json" "$TMP/key.txt" \
            >/dev/null 2>&1 &
        PLAIN_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$PPORT))==0 else 1)" && break
            sleep 0.1
        done

        ( cd "$TMP" && "$TMP/cqie-plain" login --plain --state-dir "$TMP/state-plain" ) \
            >"$TMP/plain.out" 2>"$TMP/plain.err"
        grep -q "认证成功" "$TMP/plain.out" \
            && ok "--plain: 明文提交登录成功（mock 按明文比对通过）" \
            || bad "--plain: 应登录成功" "含「认证成功」" "$(cat "$TMP/plain.out")"
        PL=$(python3 -c "import json;lg=json.load(open('$TMP/p_log.json'))['login'];print(lg['passwordEncrypt'],lg['password'])")
        [ "$PL" = "false $PWD_TEST" ] \
            && ok "--plain: 服务端收到 passwordEncrypt=false + 明文密码" \
            || bad "--plain: 服务端收到的不对" "false $PWD_TEST" "$PL"
        kill $PLAIN_MOCK 2>/dev/null
    else
        bad "--plain: 编译失败" "编译通过" "$(head -3 "$TMP/plain_cc.err")"
    fi
fi

# --------------------------------------------------- 3.8 reauth 指定 userIndex
echo
echo "== 3.8 reauth <index>（指定 userIndex 注销后再认证） =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    RPORT=$((20000 + RANDOM % 20000))
    cat > "$TMP/r_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$RPORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$RPORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-reauth"
#define USER_ID         "testuser"
#define PASSWORD        "$PWD_TEST"
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/r_override.h" \
            -o "$TMP/cqie-reauth" "$ROOT"/src/*.c 2>"$TMP/reauth_cc.err"; then
        python3 "$ROOT/tests/mock_ac.py" "$RPORT" "$PWD_TEST" "$TMP/r_log.json" "$TMP/key.txt" \
            >/dev/null 2>&1 &
        REAUTH_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$RPORT))==0 else 1)" && break
            sleep 0.1
        done

        mkdir -p "$TMP/state-reauth"
        printf 'STOREDOLDHEX' > "$TMP/state-reauth/userIndex"  # 干扰值：应改用指定值
        IDX_SPEC=$(python3 -c "print('10.0.0.1_127.0.0.1_REDACTED-USERID'.encode().hex())")

        ( cd "$TMP" && "$TMP/cqie-reauth" reauth "$IDX_SPEC" --state-dir "$TMP/state-reauth" ) \
            >"$TMP/reauth.out" 2>"$TMP/reauth.err"
        grep -q "下线成功" "$TMP/reauth.out" \
            && ok "reauth 指定: 注销步成功" \
            || bad "reauth 指定: 注销步应成功" "含「下线成功」" "$(cat "$TMP/reauth.out")"
        R_IDX=$(python3 -c "import json;print(json.load(open('$TMP/r_log.json'))['logout']['userIndex'])")
        [ "$R_IDX" = "$IDX_SPEC" ] \
            && ok "reauth 指定: 服务端收到指定的 userIndex（非状态文件旧值）" \
            || bad "reauth 指定: userIndex 不对" "$IDX_SPEC" "$R_IDX"
        grep -q "认证成功" "$TMP/reauth.out" \
            && ok "reauth 指定: 注销后重新登录成功" \
            || bad "reauth 指定: 应重新登录成功" "含「认证成功」" "$(cat "$TMP/reauth.out")"
        kill $REAUTH_MOCK 2>/dev/null
    else
        bad "reauth 指定: 编译失败" "编译通过" "$(head -3 "$TMP/reauth_cc.err")"
    fi
fi

# --------------------------------------------------- 3.9 --no-syslog 运行期开关
echo
echo "== 3.9 --no-syslog（运行期开关 syslog 状态行） =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    NPORT=$((20000 + RANDOM % 20000))
    # 劫持 syslog()：状态行改写到 $SYSCAP_FILE，验证默认写 / 传参不写
    cat > "$TMP/syscap.c" <<'EOF'
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
void test_openlog(const char* ident, int opt, int fac) { (void)ident; (void)opt; (void)fac; }
void test_closelog(void) {}
void test_syslog(int pri, const char* fmt, ...)
{
    const char* p = getenv("SYSCAP_FILE");
    if (!p || !p[0]) return;
    FILE* f = fopen(p, "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
    (void)pri;
}
EOF
    cat > "$TMP/nl_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$NPORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$NPORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-nosyslog"
#define USER_ID         "testuser"
#define PASSWORD        "$PWD_TEST"
#define USE_SYSLOG      1
void test_openlog(const char* ident, int opt, int fac);
void test_closelog(void);
void test_syslog(int pri, const char* fmt, ...);
#define openlog test_openlog
#define closelog test_closelog
#define syslog test_syslog
EOF
    # -U_FORTIFY_SOURCE：glibc 的 fortify 会把 syslog 包成 __syslog_chk 的 inline，
    # 覆盖掉下面的 #define syslog test_syslog，导致劫持失效（Ubuntu gcc 默认开）。
    if ${CC:-cc} -O2 -std=c99 -U_FORTIFY_SOURCE -I"$ROOT/include" -include "$TMP/nl_override.h" \
            -o "$TMP/cqie-nosyslog" "$ROOT"/src/*.c "$TMP/syscap.c" 2>"$TMP/nl_cc.err"; then
        python3 "$ROOT/tests/mock_ac.py" "$NPORT" "$PWD_TEST" "$TMP/nl_log.json" "$TMP/key.txt" \
            >/dev/null 2>&1 &
        NL_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$NPORT))==0 else 1)" && break
            sleep 0.1
        done

        # 场景 A：默认（不带参数）-> 状态行写入 syslog
        ( cd "$TMP" && SYSCAP_FILE="$TMP/syscap_a.txt" "$TMP/cqie-nosyslog" login --state-dir "$TMP/state-nosyslog" ) \
            >"$TMP/nl_a.out" 2>"$TMP/nl_a.err"
        grep -q "认证成功" "$TMP/nl_a.out" \
            && ok "--no-syslog A: 登录成功" \
            || bad "--no-syslog A: 应登录成功" "含「认证成功」" "$(cat "$TMP/nl_a.out")"
        grep -q "认证成功" "$TMP/syscap_a.txt" 2>/dev/null \
            && ok "--no-syslog A: 默认把「认证成功」状态行写入 syslog" \
            || bad "--no-syslog A: syslog 应有状态行" "含「认证成功」" "$(cat "$TMP/syscap_a.txt" 2>/dev/null)"

        # 场景 B：--no-syslog -> 不写
        ( cd "$TMP" && SYSCAP_FILE="$TMP/syscap_b.txt" "$TMP/cqie-nosyslog" logout --no-syslog --state-dir "$TMP/state-nosyslog" ) \
            >"$TMP/nl_b.out" 2>"$TMP/nl_b.err"
        grep -q "下线成功" "$TMP/nl_b.out" \
            && ok "--no-syslog B: 注销成功" \
            || bad "--no-syslog B: 应注销成功" "含「下线成功」" "$(cat "$TMP/nl_b.out")"
        [ ! -s "$TMP/syscap_b.txt" ] \
            && ok "--no-syslog B: 带 --no-syslog 时 syslog 无状态行" \
            || bad "--no-syslog B: 不应写 syslog" "空" "$(cat "$TMP/syscap_b.txt" 2>/dev/null)"
        kill $NL_MOCK 2>/dev/null
    else
        bad "--no-syslog: 编译失败" "编译通过" "$(head -3 "$TMP/nl_cc.err")"
    fi
fi

# --------------------------------------------------- 3.10 userIndex 服务端要回
echo
echo "== 3.10 logout 的 userIndex 服务端要回（redirectortosuccess.jsp） =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    R2PORT=$((20000 + RANDOM % 20000))
    cat > "$TMP/r2_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$R2PORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$R2PORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-remote"
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/r2_override.h" \
            -o "$TMP/cqie-remote" "$ROOT"/src/*.c 2>"$TMP/remote_cc.err"; then
        python3 "$ROOT/tests/mock_ac.py" "$R2PORT" "$PWD_TEST" "$TMP/r2_log.json" "$TMP/key.txt" \
            >/dev/null 2>&1 &
        R2_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$R2PORT))==0 else 1)" && break
            sleep 0.1
        done

        # 场景 A：存储值被拒 -> 服务端要回 -> 用 Location 里的值注销成功
        mkdir -p "$TMP/state-remote"
        printf 'FORCEFAIL' > "$TMP/state-remote/userIndex"
        ( cd "$TMP" && "$TMP/cqie-remote" logout --state-dir "$TMP/state-remote" ) \
            >"$TMP/remote_a.out" 2>"$TMP/remote_a.err"
        grep -q "下线成功" "$TMP/remote_a.out" \
            && ok "服务端要回 A: 存储值被拒后改用服务端值注销成功" \
            || bad "服务端要回 A: 应注销成功" "含「下线成功」" "$(cat "$TMP/remote_a.out")"
        A2_CNT=$(python3 -c "import json;print(json.load(open('$TMP/r2_log.json'))['counts']['logout'])")
        [ "$A2_CNT" = "2" ] \
            && ok "服务端要回 A: 共 2 次注销（FORCEFAIL + 服务端值）" \
            || bad "服务端要回 A: 注销次数不对" "2" "$A2_CNT"
        A2_IDX=$(python3 -c "import json;print(json.load(open('$TMP/r2_log.json'))['logout']['userIndex'])")
        [ "$A2_IDX" = "REMOTEFROMSERVER" ] \
            && ok "服务端要回 A: 注销用的是 Location 里的 userIndex" \
            || bad "服务端要回 A: userIndex 不对" "REMOTEFROMSERVER" "$A2_IDX"

        # 场景 B：状态目录全空（无 userIndex 也无 nasip，拼接不可用）-> 只靠服务端要回
        ( cd "$TMP" && "$TMP/cqie-remote" logout --state-dir "$TMP/state-remote2" ) \
            >"$TMP/remote_b.out" 2>"$TMP/remote_b.err"
        grep -q "下线成功" "$TMP/remote_b.out" \
            && ok "服务端要回 B: 无状态文件时从服务端拿到 userIndex 并注销" \
            || bad "服务端要回 B: 应注销成功" "含「下线成功」" "$(cat "$TMP/remote_b.out")"
        kill $R2_MOCK 2>/dev/null
    else
        bad "服务端要回: 编译失败" "编译通过" "$(head -3 "$TMP/remote_cc.err")"
    fi
fi

# --------------------------------------------------- 3.11 --interface 源 IP 绑定
echo
echo "== 3.11 --interface 源 IP 绑定 =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    IPORT=$((20000 + RANDOM % 20000))
    cat > "$TMP/i_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$IPORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$IPORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-iface"
#define USER_ID         "testuser"
#define PASSWORD        "$PWD_TEST"
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/i_override.h" \
            -o "$TMP/cqie-iface" "$ROOT"/src/*.c 2>"$TMP/iface_cc.err"; then
        python3 "$ROOT/tests/mock_ac.py" "$IPORT" "$PWD_TEST" "$TMP/i_log.json" "$TMP/key.txt" \
            >/dev/null 2>&1 &
        IF_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$IPORT))==0 else 1)" && break
            sleep 0.1
        done

        # 场景 A：绑定 127.0.0.12（loopback 段内另一地址）-> 服务端应看到它
        ( cd "$TMP" && "$TMP/cqie-iface" login --interface 127.0.0.12 --state-dir "$TMP/state-iface" ) \
            >"$TMP/iface_a.out" 2>"$TMP/iface_a.err"
        grep -q "认证成功" "$TMP/iface_a.out" \
            && ok "--interface A: 绑定源 IP 后登录成功" \
            || bad "--interface A: 应登录成功" "含「认证成功」" "$(cat "$TMP/iface_a.out")"
        CLT=$(python3 -c "import json;print(json.load(open('$TMP/i_log.json'))['login']['client_ip'])")
        [ "$CLT" = "127.0.0.12" ] \
            && ok "--interface A: 服务端看到的源 IP 是绑定的 127.0.0.12" \
            || bad "--interface A: 服务端看到的源 IP 不对" "127.0.0.12" "$CLT"

        # 场景 B：绑定本机不存在的地址 -> 所有连接失败（探测阶段静默，最终报未捕获认证页）
        ( cd "$TMP" && "$TMP/cqie-iface" login --interface 203.0.113.1 --state-dir "$TMP/state-iface" ) \
            >"$TMP/iface_b.out" 2>"$TMP/iface_b.err"
        RTB=$?
        [ "$RTB" != "0" ] && grep -q "未捕获认证页" "$TMP/iface_b.err" \
            && ok "--interface B: 绑定不可用地址时全部连接失败（绑定真实生效）" \
            || bad "--interface B: 应认证失败" "exit!=0 含「未捕获认证页」" "exit=$RTB $(tail -2 "$TMP/iface_b.err")"

        # 场景 C：非法 IP -> 参数校验直接拒绝
        ( cd "$TMP" && "$TMP/cqie-iface" login --interface 999.1.1.1 --state-dir "$TMP/state-iface" ) \
            >"$TMP/iface_c.out" 2>"$TMP/iface_c.err"
        RTC=$?
        [ "$RTC" = "2" ] && grep -q "无效的源 IP" "$TMP/iface_c.err" \
            && ok "--interface C: 非法 IP 被参数校验拒绝（exit 2）" \
            || bad "--interface C: 应 exit 2 并报无效源 IP" "exit=2" "exit=$RTC $(cat "$TMP/iface_c.err")"
        kill $IF_MOCK 2>/dev/null
    else
        bad "--interface: 编译失败" "编译通过" "$(head -3 "$TMP/iface_cc.err")"
    fi
fi

# --------------------------------------------------- 3.12 凭据配置文件
echo
echo "== 3.12 --config 凭据配置文件（user/password/service） =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    CPORT=$((20000 + RANDOM % 20000))
    cat > "$TMP/c_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$CPORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$CPORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-cfg"
#define USER_ID         ""
#define PASSWORD        ""
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/c_override.h" \
            -o "$TMP/cqie-cfg" "$ROOT"/src/*.c 2>"$TMP/cfg_cc.err"; then
        python3 "$ROOT/tests/mock_ac.py" "$CPORT" "$PWD_TEST" "$TMP/c_log.json" "$TMP/key.txt" \
            >/dev/null 2>&1 &
        C_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$CPORT))==0 else 1)" && break
            sleep 0.1
        done

        # 配置文件：凭据全走运行期（编译期默认已被清空）
        cat > "$TMP/cfg.conf" <<EOF
# 测试配置
user = cfguser001
password = $PWD_TEST
service = 测试运营商
EOF

        # 场景 A：--config 注入凭据 -> 登录成功，且账号/运营商来自配置文件
        ( cd "$TMP" && "$TMP/cqie-cfg" login --config "$TMP/cfg.conf" --state-dir "$TMP/state-cfg" ) \
            >"$TMP/cfg_a.out" 2>"$TMP/cfg_a.err"
        grep -q "认证成功" "$TMP/cfg_a.out" \
            && ok "配置文件 A: 凭据来自配置文件，登录成功" \
            || bad "配置文件 A: 应登录成功" "含「认证成功」" "$(cat "$TMP/cfg_a.out")"
        CJ=$(python3 -c "import json;j=json.load(open('$TMP/c_log.json'))['login'];print(j['userId'],j['service'])")
        [ "$CJ" = "cfguser001 测试运营商" ] \
            && ok "配置文件 A: 登录请求的账号与运营商均来自配置文件" \
            || bad "配置文件 A: 账号/运营商不对" "cfguser001 测试运营商" "$CJ"

        # 场景 B：--config 指向不存在的文件 -> 参数期报错 exit 2
        ( cd "$TMP" && "$TMP/cqie-cfg" login --config "$TMP/no-such.conf" --state-dir "$TMP/state-cfg" ) \
            >"$TMP/cfg_b.out" 2>"$TMP/cfg_b.err"
        RTC2=$?
        [ "$RTC2" = "2" ] && grep -q "配置文件不存在" "$TMP/cfg_b.err" \
            && ok "配置文件 B: 显式指定的配置文件缺失时报错（exit 2）" \
            || bad "配置文件 B: 应 exit 2" "exit=2" "exit=$RTC2 $(cat "$TMP/cfg_b.err")"

        # 场景 C：无配置文件且编译期凭据为空 -> 提示未配置账号
        ( cd "$TMP" && "$TMP/cqie-cfg" login --state-dir "$TMP/state-cfg" ) \
            >"$TMP/cfg_c.out" 2>"$TMP/cfg_c.err"
        RTC3=$?
        [ "$RTC3" = "1" ] && grep -q "未配置账号" "$TMP/cfg_c.err" \
            && ok "配置文件 C: 无凭据时给出明确引导（未配置账号/密码）" \
            || bad "配置文件 C: 应报未配置账号" "exit=1 含「未配置账号」" "exit=$RTC3 $(tail -2 "$TMP/cfg_c.err")"
        kill $C_MOCK 2>/dev/null
    else
        bad "配置文件: 编译失败" "编译通过" "$(head -3 "$TMP/cfg_cc.err")"
    fi
fi

# --------------------------------------------------- 3.13 凭据通道与优先级
echo
echo "== 3.13 -u/-p/--service 与环境变量（凭据多通道） =="
if ! have python3; then
    echo "  (缺少 python3，跳过)"
else
    MPORT=$((20000 + RANDOM % 20000))
    cat > "$TMP/m_override.h" <<EOF
#define PORTAL_URL      "http://127.0.0.1:$MPORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$MPORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state-multi"
#define USER_ID         ""
#define PASSWORD        ""
EOF
    if ${CC:-cc} -O2 -std=c99 -I"$ROOT/include" -include "$TMP/m_override.h" \
            -o "$TMP/cqie-multi" "$ROOT"/src/*.c 2>"$TMP/multi_cc.err"; then
        python3 "$ROOT/tests/mock_ac.py" "$MPORT" "$PWD_TEST" "$TMP/m_log.json" "$TMP/key.txt" \
            >/dev/null 2>&1 &
        M_MOCK=$!
        for _ in $(seq 1 50); do
            python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$MPORT))==0 else 1)" && break
            sleep 0.1
        done

        # 场景 A：命令行 -u/-p -> 登录成功且账号来自 CLI
        ( cd "$TMP" && "$TMP/cqie-multi" login -u cliuser -p "$PWD_TEST" --state-dir "$TMP/state-multi" ) \
            >"$TMP/multi_a.out" 2>"$TMP/multi_a.err"
        grep -q "认证成功" "$TMP/multi_a.out" \
            && ok "凭据通道 A: -u/-p 登录成功" \
            || bad "凭据通道 A: 应登录成功" "含「认证成功」" "$(cat "$TMP/multi_a.out")"
        MA=$(python3 -c "import json;print(json.load(open('$TMP/m_log.json'))['login']['userId'])")
        [ "$MA" = "cliuser" ] \
            && ok "凭据通道 A: 服务端收到 CLI 的账号 cliuser" \
            || bad "凭据通道 A: 账号不对" "cliuser" "$MA"

        # 场景 B：环境变量 CQIE_USER/CQIE_PASS -> 登录成功且账号来自 env
        ( cd "$TMP" && CQIE_USER=envuser CQIE_PASS="$PWD_TEST" \
          "$TMP/cqie-multi" login --state-dir "$TMP/state-multi" ) \
            >"$TMP/multi_b.out" 2>"$TMP/multi_b.err"
        grep -q "认证成功" "$TMP/multi_b.out" \
            && ok "凭据通道 B: 环境变量登录成功" \
            || bad "凭据通道 B: 应登录成功" "含「认证成功」" "$(cat "$TMP/multi_b.out")"
        MB=$(python3 -c "import json;print(json.load(open('$TMP/m_log.json'))['login']['userId'])")
        [ "$MB" = "envuser" ] \
            && ok "凭据通道 B: 服务端收到环境变量的账号 envuser" \
            || bad "凭据通道 B: 账号不对" "envuser" "$MB"

        # 场景 C：优先级 CLI > 配置文件（配置给 cfguser，命令行给 cliuser2）
        cat > "$TMP/multi.conf" <<EOF
user=cfguser
password=$PWD_TEST
EOF
        ( cd "$TMP" && "$TMP/cqie-multi" login -u cliuser2 --config "$TMP/multi.conf" --state-dir "$TMP/state-multi" ) \
            >"$TMP/multi_c.out" 2>"$TMP/multi_c.err"
        grep -q "认证成功" "$TMP/multi_c.out" \
            && ok "凭据通道 C: CLI + 配置文件同时存在时登录成功" \
            || bad "凭据通道 C: 应登录成功" "含「认证成功」" "$(cat "$TMP/multi_c.out")"
        MC=$(python3 -c "import json;print(json.load(open('$TMP/m_log.json'))['login']['userId'])")
        [ "$MC" = "cliuser2" ] \
            && ok "凭据通道 C: CLI 覆盖配置文件（收到 cliuser2）" \
            || bad "凭据通道 C: 账号不对" "cliuser2" "$MC"
        kill $M_MOCK 2>/dev/null
    else
        bad "凭据通道: 编译失败" "编译通过" "$(head -3 "$TMP/multi_cc.err")"
    fi
fi

echo
echo "==================== 结果：通过 $PASS 项，失败 $FAIL 项 ===================="
[ "$FAIL" -eq 0 ]
