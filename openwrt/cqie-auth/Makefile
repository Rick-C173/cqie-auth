#
# Copyright (C) 2026 Rick_C173
#
# This is free software, licensed under the MIT License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=cqie-auth
PKG_VERSION:=1.9.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Rick-C173/cqie-auth.git
# 发布跟随 git tag；本地调试时改成任意 ref/commit 即可
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)

PKG_MAINTAINER:=Rick_C173 <rick_c173@qq.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/cqie-auth
  SECTION:=net
  CATEGORY:=Network
  TITLE:=锐捷 ePortal 校园网认证工具（命令行）
  URL:=https://github.com/Rick-C173/cqie-auth
  DEPENDS:=+libpthread
endef

define Package/cqie-auth/description
  锐捷 ePortal（瑞捷网页认证）校园网命令行认证工具。
  纯 C、零外部依赖的单二进制，为 OpenWrt 路由器设计。
  首次运行 cqie-auth login 进入交互式向导；cqie-auth doctor 环境诊断。
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) \
		-DSTATE_DIR='"/etc/cqie-auth"' -DCQIE_MINIMAL_HELP=1 \
		-I$(PKG_BUILD_DIR)/include \
		-o $(PKG_BUILD_DIR)/cqie-auth \
		$(wildcard $(PKG_BUILD_DIR)/src/*.c) \
		$(TARGET_LDFLAGS) -lpthread
endef

define Package/cqie-auth/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cqie-auth $(1)/usr/bin/
endef

$(eval $(call BuildPackage,cqie-auth))
