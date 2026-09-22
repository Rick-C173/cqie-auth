//
// auth.h - 认证流程（登录 / 重新认证 / 退出 / 在线状态）
//
#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

/*
 * 运行期覆盖项（来自命令行），不设置则用 config.h 里的编译期默认值。
 * portal_url 传 NULL 或空串表示恢复默认。
 */
void auth_set_portal(const char* portal_url);
/* 运行期覆盖探测地址（向导/配置文件 probe= 注入）；NULL/空 = 恢复编译期默认 */
void auth_set_probe(const char* url);
void auth_set_dry_run(int on);
/* --plain：跳过 RSA 加密，密码明文提交（passwordEncrypt=false）。
 * 仅 USE_ENCRYPT=1 编译时有意义；USE_ENCRYPT=0 时本来就走明文。 */
void auth_set_plain(int on);

/*
 * 通过探测地址发现认证配置（首次设置向导用）：
 * 请求探测地址触发 AC 劫持，从认证页跳转 URL 提取 portal 基址（本次会话
 * 立即生效）并拉取运营商列表。成功返回 1（portal_out=认证基址，
 * list_out="A@B@C" 运营商列表）；失败返回 0（不在校园网/探测地址不可用）。
 */
int auth_discover_portal(char* portal_out, size_t psz, char* list_out, size_t lsz);

/*
 * doctor - 环境诊断子命令（只读：不加锁、不登录、不写文件）。
 * 逐环检查外网连通/探测地址/认证服务器/运营商列表/配置完整性，
 * verdict 直接给下一步建议。返回 0=全部正常，1=存在异常。
 */
int cmd_doctor(const char* cfg_path);

/*
 * 运行期凭据（来自配置文件）：user/password/service 三项，传 NULL/空串
 * 表示该项不设置，回落编译期默认（发布版默认为空）。
 * auth_user/auth_password/auth_service 返回生效值（永不返回 NULL）。
 */
void auth_set_credentials(const char* user, const char* pass, const char* service);
const char* auth_user(void);
const char* auth_password(void);
const char* auth_service(void);

/* 最近一次 login 实际使用的运营商（探测命中或沿用配置的最终值）。
 * login 未运行过时为空串。供"运营商自愈写回配置"判断用。 */
const char* auth_last_service(void);

/*
 * 单实例锁（login/reauth/logout 互斥，防并发写状态文件）。
 * auth_session_lock 成功返回 1；被其它实例持有时返回 0 并打印提示。
 * auth_session_unlock 释放（未持锁时为空操作）；进程退出也会自动释放。
 */
int auth_session_lock(void);
void auth_session_unlock(void);

/*
 * 登录：已在线直接返回 0；否则抓认证页 -> 取公钥 -> 加密密码 -> 提交登录
 * -> 把 userIndex 写入状态目录。
 * force=1 时跳过"已在线"短路，强制走一次完整认证（reauth 用）。
 * 成功返回 0（dry_run 模式下走完探测+加密即算成功，返回 0）。
 */
int cmd_login(int force);

/*
 * 先注销再认证：用指定的 userIndex 注销（省略时读状态目录；存储值失败时依次
 * 尝试"服务端要回"和"拼接回退"，失败只警告），等待 REAUTH_DELAY_MS 后强制
 * 重新登录。用于会话卡死 / 换设备 / 定时刷新。
 */
int cmd_reauth(const char* user_index);

/*
 * 注销：user_index 为 NULL 时读状态目录里的 userIndex（对应原 cqie-exit.sh）。
 * userIndex 来源优先级：指定参数/存储值 -> 服务端要回（redirectortosuccess.jsp
 * 按源 IP 识别会话，302 Location 带回 userIndex）-> 拼接 hex(nasip_IP_账号)。
 * 请求发出成功返回 0，网络失败返回 1。
 */
int cmd_logout(const char* user_index);

/* 在线状态：已在线返回 0，未在线返回 1 */
int cmd_status(void);

/*
 * 把 userIndex 解码后打印到 stdout（hex 形式 -> 可读的 账号/IP 形式）。
 * hex 为 NULL 时读状态目录里的 userIndex.txt；解不出内容时原样输出。
 * 没有可用的 userIndex 返回 1，成功返回 0。这是纯查询，不写 syslog。
 */
int cmd_userindex(const char* hex);

#endif /* AUTH_H */
