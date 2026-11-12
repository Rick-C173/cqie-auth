#!/usr/bin/env bash
# MISRA C:2012 门禁（make misra）
#
# 双配置扫描：A = POSIX（真实系统头文件），B = _WIN32（windows.cfg + 补充库）。
# 零"未豁免违规"才算通过；规则级放行清单见 scripts/misra_suppressions.txt，
# 逐条偏离理由与缓解措施成文于 docs/MISRA.md；站点级豁免用行内
# /* cppcheck-suppress ... */ 并注明原因。
set -u
cd "$(dirname "$0")/.."

command -v cppcheck >/dev/null 2>&1 || {
    echo "错误: 缺少 cppcheck（sudo apt install cppcheck）" >&2
    exit 2
}

ADDON="${CPPCHECK_ADDON:-}"
if [ -z "$ADDON" ]; then
    ADDON=$(ls /usr/lib/*/cppcheck/addons/misra.py /usr/share/cppcheck/addons/misra.py 2>/dev/null | head -1)
fi
if [ -z "$ADDON" ] || [ ! -f "$ADDON" ]; then
    echo "错误: 未找到 misra.py 插件（cppcheck 2.x 自带）" >&2
    exit 2
fi

COMMON=(--enable=all --addon="$ADDON" --inline-suppr
        --suppressions-list=scripts/misra_suppressions.txt
        --std=c17 -Iinclude
        -I/usr/include -I/usr/include/x86_64-linux-gnu
        --template='[{file}:{line}]: {id}')

residual=0
for pass_name in A B; do
    if [ "$pass_name" = "A" ]; then
        extra=(--library=posix)
    else
        extra=(-D_WIN32 --library=windows --library=posix --library="$(pwd)/scripts/misra_lib.cfg")
    fi
    out=$(cppcheck "${COMMON[@]}" "${extra[@]}" src/*.c 2>&1) || true
    hits=$(printf '%s\n' "$out" | grep -E 'misra-c2012-[0-9]+\.[0-9]+' | grep -v '/usr/include' || true)
    if [ -n "$hits" ]; then
        echo "== 配置 $pass_name：未豁免违规 =="
        printf '%s\n' "$hits"
        residual=1
    fi
done

if [ "$residual" -eq 0 ]; then
    echo "MISRA 门禁通过：双配置扫描 0 条未豁免违规（成文偏差见 docs/MISRA.md）"
    exit 0
fi
echo "MISRA 门禁失败：存在未豁免违规（新代码引入？先看 docs/MISRA.md 的偏差流程）" >&2
exit 1
