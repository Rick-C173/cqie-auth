#
# Copyright (C) 2026 Rick_C173
#
# This is free software, licensed under the MIT License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-cqie-auth
PKG_VERSION:=1.9.0
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for cqie-auth（锐捷 ePortal 校园网认证）
LUCI_DESCRIPTION:=状态轮询 / 一键上下线 / 账号配置编辑，经 rpcd 调用 cqie-auth 命令行。需先安装 cqie-auth。
LUCI_DEPENDS:=+luci-base
LUCI_PKGARCH:=all

PKG_MAINTAINER:=Rick_C173 <rick_c173@qq.com>
PKG_LICENSE:=MIT

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
