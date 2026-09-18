# 编译流程说明

`cqie-auth` 的所有构建都通过顶层 `Makefile` 驱动。下面按「先跑通，再调优」的顺序写。

## 1. 三条主路径

| 目的 | 命令 | 产物 |
| --- | --- | --- |
| 宿主开发与回归 | `make` | `cqie-auth`（动态链 libc） |
| 完整自检 | `make check` | 同上，跑完 64 项断言 |
| 路由器产物 | `make openwrt` | `cqie-auth.owrt`（aarch64 静态单文件） |
| 部署到路由器 | `make deploy HOST=root@10.0.0.1` | 拷文件 + 建状态目录 |

最短路径：

```bash
make && make check                          # 宿主
make openwrt                                # 交叉编译
make deploy HOST=root@<路由器 IP>           # 部署
```

> **WSL 提示**：在 Windows 上构建/测试一律走
> `wsl.exe -d Ubuntu-26.04 -- bash -lc "cd /home/rick/cqie_auth && make"`。
> 直接在 Git Bash 里跑会因为找不到 musl 工具链而失败。

## 2. Make 目标

| 目标 | 作用 |
| --- | --- |
| `make` (= `all`) | 编译当前宿主二进制 `cqie-auth` |
| `make strip` | `strip` 宿主二进制 |
| `make clean` | 删 `build/`、`cqie-auth`、`*.owrt` |
| `make check` | 跑 `tests/check.sh`：RSA 逐字节比对 + 字符串解析对拍 + 模拟 AC 端到端（共 64 项） |
| `make openwrt` | 交叉编译 aarch64/musl 静态单文件 `cqie-auth.owrt` |
| `make openwrt-size` | 跑 `size` 看节区（仅在 `sstrip` 之前有意义） |
| `make deploy HOST=...` | 在 `openwrt` 之上额外 `sh deploy.sh $HOST` |

## 3. Make 变量

```bash
make [VAR=val ...] [target]
```

| 变量 | 默认 | 用途 |
| --- | --- | --- |
| `CC` | `gcc` | 宿主编译器（交叉编译走 Makefile 内部硬编码的 `OWRT_CC`，不接受覆盖） |
| `STRIP` | `strip` | 宿主 `strip` 命令 |
| `SDK_DIR` | `/home/rick/openwrt-sdk-24.10.6` | OpenWrt SDK 根目录 |
| `CFLAGS` `LDFLAGS` `LDLIBS` | — | 标准 make 变量，会被追加 |
| `HOST` | — | `make deploy` 的目标，形如 `root@10.0.0.1` |

示例：

```bash
make openwrt                        # 交叉编译（零外部依赖，无需 SDK 预备）
make deploy HOST=root@192.168.1.1
make CC=clang CFLAGS='-O3 -Wall'    # 用 clang 试编宿主
```

## 4. 编译期选项（`-D` 宏）

所有配置宏都在 `include/config.h`，用 `#ifndef` 包裹，因此任何一项都可在命令行覆盖：

```bash
make CFLAGS='-DPASSWORD="xxx" -DSTATE_DIR=\"/etc/cqie-auth\"'
```

最常用的几项（完整列表见 `config.h`）：

| 宏 | 默认 | 说明 |
| --- | --- | --- |
| `USER_ID` | `""`（空） | 学号/账号。发布版不内置凭据，运行时读配置文件（见下） |
| `PASSWORD` | `""`（空） | 密码。**别把真实密码提交到 git**，也不要把带值的编译命令写进公开文档 |
| `SERVICE_NAME` | `""`（空） | 运营商选项，留空则自动探测（getServices） |
| `CONFIG_FILE` | `/etc/cqie-auth.conf` | 凭据配置文件（key=value：user/password/service），可用 `--config` 或 `$CQIE_CONFIG` 覆盖 |
| `PORTAL_URL` | `http://10.253.3.84/eportal` | eportal 地址 |
| `PROBE_URL` | `http://123.123.123.123` | 探测劫持页用 |
| `PROBE_204_LIST` | 5 个常用 204 地址 | 在线探测，**并行**请求，任一返回 204 即判定在线 |
| `STATE_DIR` | `"/tmp/cqie-auth"` | 状态目录。**OpenWrt 构建已注入 `/etc/cqie-auth`**（/tmp 是 tmpfs，重启丢 userIndex） |
| `USE_ENCRYPT` | `1` | `1`=RSA 加密密码 / `0`=明文提交 |
| `RSA_CHUNK` | `126` | ohdave 风格分块大小 |
| `RSA_PAD_PER_BLOCK` | `0` | 多分块时十六进制补零方式（见 config.h 注释） |
| `HTTP_TIMEOUT_S` | `5` | 总超时 |
| `HTTP_CONNECT_TIMEOUT_S` | `2` | 连接超时 |
| `PROBE_TIMEOUT_S` | `2` | 探测**总**超时：所有地址并行，离线最坏 ~2s（旧串行版是 5×2s=10s） |
| `HTTP_USER_AGENT` | Windows Chrome UA | 默认伪装成浏览器；**必须带 UA**，否则 AC 返回空 body |
| `HTTP_USER_AGENT_FALLBACK` | `"curl/8.18.0"` | `HTTP_USER_AGENT` 留空时的后备值（旧行为） |
| `USE_SYSLOG` | `1` | 写一条结果到 syslog（OpenWrt 上 `logread` 可看） |
| `SYSLOG_IDENT` | `"cqie-auth"` | syslog 程序名 |
| `SYSLOG_LEVEL` | `6` | syslog 优先级数值（6=LOG_INFO）。**用数字**，避免拉入 `<syslog.h>` |
| `DEBUG_DEFAULT` | `0` | 没指定 `-v/-q` 时的日志级别 |
| `CQIE_MINIMAL_HELP` | `0` | `1`=精简帮助（OpenWrt 构建已自动打开） |
| `REAUTH_DELAY_MS` | `800` | reauth 里注销后等 AC 释放会话的延时 |

OpenWrt 构建会在 `Makefile` 里自动加 `CQIE_MINIMAL_HELP=1` 与 `STATE_DIR="/etc/cqie-auth"`。

## 5. HTTP 客户端

`src/http_min.c` 是自实现的 socket HTTP/1.1 客户端：零外部依赖、静态产物 ~130 KB、
只支持 `http://`（本项目所有 URL 都是明文）。曾有 libcurl 后端，因 curl+mbedtls
占静态产物 93% 体积已删除（需要时从 git 历史找回 `src/http.c`）。

在线探测（`PROBE_204_LIST`）是**并行**的：所有地址同时发起非阻塞 connect，
单个 poll 循环驱动，共享一个 `PROBE_TIMEOUT_S` 总超时。命中任一 204 即判定在线。

## 6. 运行期选项

`cqie-auth` 二进制本身：

```
用法: cqie-auth <命令> [选项]

命令:
  login                上线（已在线则直接返回 0）
  reauth               注销 → 等待 → 强制重新登录（会话卡死时用）
  logout [index]       注销；不指定 index 时用状态目录里的 userIndex
  status               在线探测，返回 0（已在线）/ 1（未在线）
  userindex [hex]      输出解码后的 userIndex（省略参数时读状态文件；纯查询，不写 syslog）

选项:
  -v|-vv|-vvv          调试级别（可重复）
  -q                   静默（覆盖 -v）
  --log FILE           调试日志落文件（默认 stderr）
  --dry-run            login: 只探测+取公钥+加密，不提交
  --portal URL         覆盖 PORTAL_URL
  --state-dir DIR      覆盖状态目录
  --help  --version
```

环境变量：

| 变量 | 作用 |
| --- | --- |
| `CQIE_DEBUG` | 同 `-v`，值为 `1`/`2`/`3` |
| `CQIE_STATE_DIR` | 同 `--state-dir`，命令行优先 |

## 7. OpenWrt 交叉编译

### 7.1 目标与 SDK

路由器为 **TR3000 / OpenWrt 24.10.6 / mediatek-filogic / aarch64_cortex-a53**，
与 Makefile 默认的 SDK 路径完全一致：

```
SDK_DIR = /home/rick/openwrt-sdk-24.10.6
工具链  = staging_dir/toolchain-aarch64_cortex-a53_gcc-13.3.0_musl
目标    = staging_dir/target-aarch64_cortex-a53_musl
```

若 SDK 路径不同，临时覆盖：

```bash
make openwrt SDK_DIR=/path/to/your-sdk
```

### 7.2 交叉编译——零准备

```bash
make openwrt
# 产物：cqie-auth.owrt（~130 KB，零外部依赖，无需在 SDK 预编任何库）
```

### 7.3 关键编译选项

```make
-Os -flto -ffunction-sections -fdata-sections \      # 体积优先
-fno-asynchronous-unwind-tables -fno-unwind-tables \  # 省异常表
-fno-ident -fmerge-all-constants \                    # 去 ident、合并常量
-Wall -Wextra -std=c99
-DSTATE_DIR='"/etc/cqie-auth"' -DCQIE_MINIMAL_HELP=1
```

链接：

```make
-static -flto -Wl,--gc-sections -Wl,-O2 -Wl,--as-needed
```

strip 链：

```make
aarch64-openwrt-linux-musl-strip --strip-all
sstrip                                                # 再削一层节区头
```

### 7.4 验证产物

```bash
make openwrt
# --- 产物 ---
# -rwxr-xr-x 1 rick rick 131600 ... cqie-auth.owrt
# cqie-auth.owrt: ELF 64-bit LSB executable, ARM aarch64, ...
# --- 动态依赖（应为空）---
# (无 NEEDED 条目 = 纯静态)

# 再做一次功能性验证（不需要真路由器）：
qemu-aarch64 ./cqie-auth.owrt --version
qemu-aarch64 ./cqie-auth.owrt status -v               # 会真发 HTTP 请求
```

## 8. 部署

```bash
make deploy HOST=root@192.168.1.1
```

`deploy.sh` 做的事：

1. `scp cqie-auth.owrt root@HOST:/usr/bin/cqie-auth`
2. SSH 上去 `chmod +x`、建 `/etc/cqie-auth`（状态目录，overlay 持久）
3. 提示常用命令

或者手动：

```bash
scp cqie-auth.owrt root@HOST:/usr/bin/cqie-auth
ssh root@HOST 'chmod +x /usr/bin/cqie-auth && mkdir -p /etc/cqie-auth'
ssh root@HOST 'cqie-auth login -vvv'                  # 会真上线
ssh root@HOST 'logread | grep cqie-auth'              # 看 syslog 写入
```

## 9. 故障排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `pageInfo 请求失败` | 没带 User-Agent | 确认 `HTTP_USER_AGENT` 没被置空；默认是 Chrome UA |
| 探测很慢、`logread` 里在线探测超时 | DNS 坏了（getaddrinfo 阻塞，无超时控制） | 检查路由器 DNS 配置；connect/读阶段有 2s 总超时，DNS 阶段没有 |
| 路由器重启后 `logout` 失败 | 状态目录在 /tmp | 确认产物用了 `STATE_DIR="/etc/cqie-auth"`（Makefile 已自动注入） |
| `logread` 看不到 cqie-auth 行 | logd 把 info 过滤了 | `uci set system.@system[0].log_level='notice'; uci commit; /etc/init.d/log restart`，或编译时 `-DSYSLOG_LEVEL=4` |
| `.config` 被改坏只剩几行 | 用 `scripts/config/conf` 改的 | 直接重写 `CONFIG_x=y` 行 + `make defconfig` 即可恢复（defconfig 以现有值为默认值） |
| WSL 找不到 `qemu-aarch64` | 没装 | `sudo apt install qemu-user`（包名是 `qemu-user`，**不是** `qemu-user-static`） |
| `tests/*.sh` 在 WSL 下报语法错 | git 用 `core.autocrlf=true` 把 LF 检出成 CRLF | 项目有 `.gitattributes (* text=auto eol=lf)`，克隆后 `git add --renormalize .` 即可 |

## 10. 环境约束与已知坑

- **/tmp 是 tmpfs**（OpenWrt）。任何"会话令牌"类状态文件都该放在 `/etc/...` 或 `/var/...`。
- **`-D_POSIX_C_SOURCE` 别在 Makefile 里全局加**：各 .c 自带的 `_POSIX_C_SOURCE 200809L` 已声明。
- **`-DSTATE_DIR='"/etc/cqie-auth"'`**：注意 `-D` 的引号嵌套，外层用单引号、内层用双引号，宏展开后才是合法字符串字面量。
- **`readelf -d cqie-auth.owrt`** 在 sstrip 之后会报 "no section header"，**正常**——这只是节区头没了，不影响运行。要量节区大小就在 `strip` 后、`sstrip` 前拷一份。
- **用户会并行改这个仓库**：提交前一定 `git status` / `git log --oneline -5` 看一下。