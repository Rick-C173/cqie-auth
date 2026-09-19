# cqie-auth

锐捷 ePortal（瑞捷网页认证）校园网命令行认证工具。纯 C 实现、零外部依赖的单二进制，
为 OpenWrt 路由器设计，也支持 Linux / Windows。

> 本工具只自动化浏览器已有的网页认证流程，请遵守所在学校的网络管理规定。

## 特性

- **单二进制、零依赖**：自实现 HTTP 客户端（libcurl 静态链接要 833KB，这里约 130KB）
- **凭据与代码分离**：账号/密码/运营商写在配置文件里，改密码不用重新编译
- **并行在线探测**：多个 204 地址同时探测，离线判定最坏 ~2s
- **注销三级兜底**：状态文件 → 服务端要回（redirectortosuccess.jsp）→ 拼接回退
- **运维友好**：结果走 stdout / 诊断走 stderr；syslog 审计行可关；`--log` 落文件
- **源 IP 绑定**：多网卡 / 多 WAN 时用 `--interface` 指定认证出口
- **校园网预检**：portal 不可达时明确退出（不再误报"已在线"），家里跑 cron 一目了然

## 平台支持

| 平台 | 构建方式 | 产物 |
| --- | --- | --- |
| OpenWrt (aarch64) | `make openwrt` | `cqie-auth.owrt`（静态链接，零依赖） |
| Linux x86_64 | `make linux` 或 `make` | `cqie-auth` |
| Windows x64 | `make windows`（mingw-w64） | `cqie-auth.exe` |

## 快速开始（OpenWrt）

```sh
# 1. 部署（开发机上；也可从 Release 页直接下载 cqie-auth.owrt）
scp cqie-auth.owrt root@192.168.1.1:/usr/bin/cqie-auth
ssh root@192.168.1.1 'chmod 755 /usr/bin/cqie-auth && mkdir -p /etc/cqie-auth && chmod 700 /etc/cqie-auth'

# 2. 在路由器上运行 login——首次会进入交互式向导
cqie-auth login
```

向导会依次询问用户名、密码（不回显、输两遍）、运营商名（直接回车=自动探测），
写入 `/etc/cqie-auth.conf`（权限 600）后**当场继续认证**。

也可以手动编辑配置文件（示例见 [cqie-auth.conf.example](cqie-auth.conf.example)），
key=value 格式、`#` 注释、建议权限 600：

```
user=20250001
password=your-password
service=中国移动
```

`service` 可以留空，工具会通过运营商接口自动探测。

示例配置见仓库中的 [cqie-auth.conf.example](cqie-auth.conf.example)。

```sh
# 3. 认证上线
cqie-auth login

# 查看状态 / 注销 / 重认证
cqie-auth status
cqie-auth logout
cqie-auth reauth        # 先注销再重新认证（换 IP / 会话卡死时用）
```

定时保活示例（crontab，每 30 分钟检查一次，在线时秒退）：

```
*/30 * * * * /usr/bin/cqie-auth login
```

## 命令与选项

```
cqie-auth login [--force]     认证上线（已在线直接返回）
cqie-auth reauth [index]      先注销再重新认证
cqie-auth logout [index]      注销下线（三级 userIndex 来源自动兜底）
cqie-auth status              查询在线状态（退出码 0=在线, 1=离线）
cqie-auth userindex [hex]     解码显示 userIndex
```

常用选项：

| 选项 | 说明 |
| --- | --- |
| `--config FILE` | 凭据配置文件（默认 `/etc/cqie-auth.conf`，可用 `$CQIE_CONFIG` 覆盖） |
| `--setup` | 显式运行首次配置向导（凭据缺失且在终端上运行 login 时也会自动触发） |
| `-u, --user` / `-p, --pass` | 临时指定账号/密码（`ps` 可见，仅调试用） |
| `--service NAME` | 临时覆盖运营商名 |
| `--portal URL` | 覆盖 eportal 地址（换学校/换 AC 不用重新编译） |
| `--interface IP` | 绑定认证流量的源 IP（多网卡/多 WAN） |
| `--force` | 跳过“已在线”短路，强制走一次完整认证 |
| `--plain` | 密码明文提交（默认 RSA 加密；排查服务端解密问题时用） |
| `--no-syslog` | 本次运行不写 syslog 审计行 |
| `-v/-vv/-vvv` | 调试输出：流程 / HTTP 细节 / 响应全文 |
| `--dry-run` | 只探测+取公钥+加密，不提交登录 |

凭据来源优先级：**命令行 `-u/-p/--service` > 环境变量 `CQIE_USER`/`CQIE_PASS`/`CQIE_SERVICE` > 配置文件 > 编译期默认**。

## 从源码编译

```sh
make            # 本机 Linux
make windows    # Windows x64（需 x86_64-w64-mingw32-gcc）
make openwrt    # OpenWrt aarch64（需 musl 交叉工具链，交叉编译变量见 Makefile）
make check      # 端到端自检（需 python3 + cryptography，开发机用）
```

编译期可用 `-D` 覆盖一切默认值（`USER_ID` / `PASSWORD` / `PORTAL_URL` 等），
但发布版凭据默认为空，推荐用配置文件。全部编译期选项见
[include/config.h](include/config.h) 内注释（均 `#ifndef` 包裹，支持 `-D` 覆盖）。

## 调试

```sh
cqie-auth login -vv --log /tmp/cqie.log   # HTTP 细节 + 落文件
cqie-auth login -vvv                      # 响应体全文
logread | grep cqie-auth                  # OpenWrt 查看历史认证结果
```

## 安全说明

- 配置文件请保持 `600` 权限；客户端必须还原密码明文交给认证服务端，
  因此本地存储只能做到混淆级防护，`root` 权限下无法绝对保密
- 登录成功后的 `userIndex`（含账号和 IP）保存在状态目录，同样注意权限

## 协议概览

```
探测 204 ──被拦截──> 劫持页提取 queryString
                          │
                          ▼
        POST pageInfo（二次编码）──> RSA 公钥 + 运营商列表
                          │
                          ▼
        RSA(password>mac) ──> POST login ──> userIndex 落盘
```

## License

[MIT](LICENSE)
