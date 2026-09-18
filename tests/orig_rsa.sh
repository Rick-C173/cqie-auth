#!/bin/sh
# 原 main.sh 里的 RSA 加密实现（bc 版），仅用于回归对比：验证 C 版输出与之逐字节一致。
#
# 用法: sh tests/orig_rsa.sh <keyfile> <pwd> <mac>
#   keyfile 第 1 行 = 模数 n (hex)，第 2 行 = 指数 e (hex)
RSA_MODULUS_HEX=$(sed -n 1p "$1")
RSA_EXPONENT_HEX=$(sed -n 2p "$1")
_pwd="$2"
_mac="$3"

chunk=126
rsa_e=$(printf 'ibase=16; %s\n' "$(echo "$RSA_EXPONENT_HEX" | tr 'a-f' 'A-F')" | bc)
rsa_n=$(printf 'ibase=16; %s\n' "$(echo "$RSA_MODULUS_HEX"  | tr 'a-f' 'A-F')" | bc)

set -- $(printf '%s>%s' "$_pwd" "$_mac" | LC_ALL=C awk '
BEGIN { for (i = 0; i < 256; i++) t[sprintf("%c", i)] = i }
{ for (i = length($0); i >= 1; i--) printf "%d ", t[substr($0, i, 1)] }')

len=$#
pad=$(( (chunk - len % chunk) % chunk ))
i=0; while [ $i -lt $pad ]; do set -- "$@" 0; i=$((i+1)); done
len=$((len + pad))

{
    cat <<'EOF'
obase=16
define p(m, e, n) { auto r, b
    r = 1; b = m % n
    while (e > 0) {
        if (e % 2) r = r * b % n
        b = b * b % n
        e = e / 2
    }
    return (r)
}
EOF
    printf 'n = %s\n' "$rsa_n"
    i=1
    while [ $i -le $len ]; do
        bc_expr=0; j=0; k=$i
        while [ $k -lt $((i + chunk)) ]; do
            eval "b1=\${$k}; b2=\${$((k+1))}"
            w=$(( b1 + b2 * 256 ))
            if [ $w -ne 0 ]; then
                if [ "$bc_expr" = 0 ]; then bc_expr="$w * 65536^$j"
                else bc_expr="$bc_expr + $w * 65536^$j"; fi
            fi
            k=$((k+2)); j=$((j+1))
        done
        printf 'p(%s, %s, n)\n' "$bc_expr" "$rsa_e"
        i=$((i + chunk))
    done
} | bc | tr -d '\\\n' | tr 'A-Z' 'a-z' | awk '{
    s = $0
    while (length(s) % 4 != 0) s = "0" s
    printf "%s ", s
}' | sed 's/ $//'
