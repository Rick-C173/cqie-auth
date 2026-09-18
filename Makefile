# ====== 可按需修改 ======
CC      ?= gcc
STRIP   ?= strip

# HTTP 客户端是自实现的 socket 版（src/http_min.c）：
# 零外部依赖、静态链接约 130KB、只支持 http://（本项目所有 URL 都是明文）。

CFLAGS  += -O2 -Wall -Wextra -std=c99 -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

BIN     := cqie-auth
BUILD   := build

SRCS    := src/bn.c src/rsa.c src/http_min.c src/util.c src/log.c src/state.c \
           src/compat.c src/auth.c src/main.c
OBJS    := $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))

# ==========================================================================
# OpenWrt 交叉编译：make openwrt
#
# 产出 aarch64/musl 静态单文件二进制 cqie-auth.owrt，直接 scp 到路由器
# /usr/bin/ 即可运行（路由器 = TR3000, OpenWrt 24.10.6, mediatek/filogic,
# aarch64_cortex-a53 —— 与下面的 SDK 一致）。零外部依赖，无需预编任何库。
# ==========================================================================
SDK_DIR    ?= /home/rick/openwrt-sdk-24.10.6
OWRT_TC    := $(SDK_DIR)/staging_dir/toolchain-aarch64_cortex-a53_gcc-13.3.0_musl
OWRT_STG   := $(SDK_DIR)/staging_dir/target-aarch64_cortex-a53_musl
OWRT_CC    := $(OWRT_TC)/bin/aarch64-openwrt-linux-musl-gcc
OWRT_STRIP := $(OWRT_TC)/bin/aarch64-openwrt-linux-musl-strip
OWRT_SIZE  := $(OWRT_TC)/bin/aarch64-openwrt-linux-musl-size
OWRT_SSTRIP:= $(SDK_DIR)/staging_dir/host/bin/sstrip

# -Os 优先体积；LTO + gc-sections 去死代码；-fno-unwind-tables 省异常表。
# 不要在这里再 -D_POSIX_C_SOURCE：log.c/util.c/state.c/http_min.c 各自已声明。
OWRT_CFLAGS := -Iinclude -I$(OWRT_STG)/usr/include \
               -Os -flto -ffunction-sections -fdata-sections \
               -fno-asynchronous-unwind-tables -fno-unwind-tables \
               -fno-ident -fmerge-all-constants \
               -Wall -Wextra -std=c99 \
               -DSTATE_DIR='"/etc/cqie-auth"' \
               -DCQIE_MINIMAL_HELP=1

OWRT_LDFLAGS := -static -flto -Wl,--gc-sections -Wl,-O2 -Wl,--as-needed \
                -L$(OWRT_STG)/usr/lib

OWRT_LIBS   := -lpthread

OWRT_BIN := cqie-auth.owrt

.PHONY: all clean strip check openwrt openwrt-size linux windows deploy

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

strip: all
	$(STRIP) $(BIN)

# 开发机上的自检：RSA 与原脚本逐字节比对 + 字符串解析比对 + 模拟 AC 端到端
check: all
	bash tests/check.sh

# 交叉编译出 OpenWrt 可运行的静态二进制（单步编译，LTO 才能跨文件优化）
# STAGING_DIR 必须指向 target 目录，工具链靠它定位目标 sysroot
openwrt:
	STAGING_DIR=$(OWRT_STG) $(OWRT_CC) $(OWRT_CFLAGS) $(OWRT_LDFLAGS) \
	    -o $(OWRT_BIN) $(SRCS) $(OWRT_LIBS)
	$(OWRT_STRIP) --strip-all $(OWRT_BIN)
	-$(OWRT_SSTRIP) $(OWRT_BIN)
	@echo "--- 产物 ---"
	@ls -l $(OWRT_BIN)
	@file $(OWRT_BIN)
	@echo "--- 动态依赖（应为空）---"
	@readelf -d $(OWRT_BIN) | grep -E 'NEEDED|SONAME' || echo "(无 NEEDED 条目 = 纯静态)"

openwrt-size: openwrt
	$(OWRT_SIZE) $(OWRT_BIN)

# ==========================================================================
# 本机 Linux 构建：make linux（单步编译等价于 make，便于 CI 一步出二进制）
# ==========================================================================
linux:
	$(CC) $(CFLAGS) $(LDFLAGS) -Iinclude -o $(BIN) $(SRCS) $(LDLIBS)

# ==========================================================================
# Windows 构建：make windows（需 mingw-w64：sudo apt install gcc-mingw-w64-x86-64）
#
# 产出 x86_64 静态 cqie-auth.exe（-static，不依赖 mingw 运行时 DLL）。
# 平台差异由 include/compat.h 收敛：Winsock2/WSAPoll/GetTickCount64/Sleep/
# MoveFileEx；syslog 在 Windows 无对应物，编译期整体关闭（-DUSE_SYSLOG=0）。
# 状态目录默认 "."（当前目录），可用 --state-dir 或 CQIE_STATE_DIR 覆盖。
# ==========================================================================
WIN_CC    := x86_64-w64-mingw32-gcc
WIN_CFLAGS := -Iinclude -Os -flto -ffunction-sections -fdata-sections \
              -fno-asynchronous-unwind-tables -fno-ident \
              -Wall -Wextra -std=c99 \
              -D_WIN32_WINNT=0x0601 -D__USE_MINGW_ANSI_STDIO=1 \
              -DUSE_SYSLOG=0 -DSTATE_DIR='"."' -DCONFIG_FILE='"cqie-auth.conf"'
WIN_LDFLAGS := -static -flto -Wl,--gc-sections -s
WIN_LIBS   := -lws2_32
WIN_BIN    := cqie-auth.exe

windows:
	command -v $(WIN_CC) >/dev/null || { echo "缺少 mingw-w64: sudo apt install gcc-mingw-w64-x86-64"; exit 1; }
	$(WIN_CC) $(WIN_CFLAGS) $(WIN_LDFLAGS) -o $(WIN_BIN) $(SRCS) $(WIN_LIBS)
	@echo "--- 产物 ---"
	@ls -l $(WIN_BIN)
	@file $(WIN_BIN)

deploy: openwrt
	sh deploy.sh $(HOST)

clean:
	rm -rf $(BUILD) $(BIN) $(OWRT_BIN) $(WIN_BIN) cqie-auth-nossl.owrt
