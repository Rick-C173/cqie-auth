# luci-app-cqie-auth

[cqie-auth](https://github.com/Rick-C173/cqie-auth)（锐捷 ePortal 校园网认证命令行工具）的 LuCI 网页界面。

## 功能

- **认证状态**页：在线/未在线/不在校园网 徽标（5 秒自动轮询）、账号、最近认证日志（logread），一键 上线 / 下线 / 重新认证
- **账号设置**页：编辑 `/etc/cqie-auth.conf`（用户名/密码/运营商/认证服务器/探测地址），密码留空表示保持不变，明文不回传前端；支持删除配置（`cqie-auth reset`）

所有操作经 rpcd 子进程调用 `/usr/bin/cqie-auth` 命令行，Web 进程不直接碰凭据。

## 依赖

- OpenWrt 21.02+（LuCI 客户端渲染框架）
- `luci-base`
- `cqie-auth`（本仓库 `openwrt/cqie-auth` 包，或按主 README 手动 scp 二进制）

## 安装（源码编译）

1. 把本目录与 `../cqie-auth` 拷进 OpenWrt buildroot：

```sh
cp -r openwrt/cqie-auth        <buildroot>/package/
cp -r openwrt/luci-app-cqie-auth <buildroot>/package/
```

> 注意：`luci-app-cqie-auth` 若放进 `feeds/luci/applications/` 也可构建
> （Makefile 同时兼容两种位置，优先用 `feeds/luci/luci.mk`）。

2. `./scripts/feeds update -a && ./scripts/feeds install -a`（首次），
   `make menuconfig` 里选中 `Network -> cqie-auth` 与
   `LuCI -> Applications -> luci-app-cqie-auth`，编译：

```sh
make package/cqie-auth/compile V=s
make package/luci-app-cqie-auth/compile V=s
```

3. 把生成的两个 ipk 传到路由器安装：

```sh
scp bin/packages/<arch>/cqie-auth_*.ipk bin/packages/<arch>/luci-app-cqie-auth_*.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'opkg install /tmp/cqie-auth_*.ipk /tmp/luci-app-cqie-auth_*.ipk'
```

安装后刷新 LuCI，菜单 `网络 -> 校园网认证`。

## 使用

1. `账号设置` 填用户名/密码保存（等价 `cqie-auth --setup` 的落盘，但不做在线验证）
2. `认证状态` 页点 **上线**；或路由器上配置 cron 保活（见主 README）
3. 日志区域可直接看到最近认证结果，无需 `logread` 手查

## 与命令行的关系

- 界面只负责读写 `/etc/cqie-auth.conf` 与调用 `status/login/logout/reauth/reset`
- 向导的"在线验证后才写盘"语义在网页端不适用（网页保存即写盘）；凭据错误时
  上线按钮会明确失败并在日志区显示原因
