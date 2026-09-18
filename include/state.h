//
// state.h - 状态文件（queryString / userIndex 的存放位置与读写）
//
#ifndef STATE_H
#define STATE_H

#include <stddef.h>

/*
 * 解析状态目录，优先级：
 *   1) --state-dir 命令行参数
 *   2) $CQIE_STATE_DIR 环境变量
 *   3) 编译期 STATE_DIR（config.h，默认 /tmp/cqie-auth）
 * 目录按 0700 创建；创建/写入不可用（只读 rootfs 等）时回退到当前目录并告警。
 * 返回最终使用的目录。
 */
const char* state_init(const char* cli_dir);
const char* state_dir(void);

/* 拼出状态文件绝对路径，buf 不够返回 0 */
int state_path(char* buf, size_t n, const char* name);

/* 原子写（临时文件 + rename，权限 0600），末尾补换行；成功返回 1 */
int state_write(const char* name, const char* content);

/*
 * 读取并去掉首尾空白；状态目录里没有时回退到当前目录同名文件
 * （兼容老版本把 userIndex.txt 写在 CWD 的行为）。成功返回 1。
 */
int state_read(const char* name, char* out, size_t n);

/* 删除状态文件（不存在也算成功） */
void state_remove(const char* name);

#endif /* STATE_H */
