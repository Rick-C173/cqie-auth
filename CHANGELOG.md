# Changelog

格式基于 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循
[语义化版本](https://semver.org/)。

## [1.4.1] - 2026-09-19

### Fixed
- `is_online()` 探测初始化失败时返回 -1，被调用方按"在线"误判——现收敛为
  只返回 1/0（`status` 在该路径下也不再误报"已在线"）
- HTTP 响应 Content-Length 分支补防御性上限（256KB，与无 CL 分支一致），
  异常/恶意超长声明不再照单全收

### Added
- **单实例锁**：`login` / `reauth` / `logout` 通过状态目录下 `.lock` 互斥
  （POSIX flock / Windows 独占打开，进程退出自动释放），防止 cron 与手动
  执行并发写状态文件；`status` / `userindex` 不受锁影响

## [1.4.0] - 2026-09-19

### Added
- **校园网环境预检**：`login` / `reauth` / `logout` 入口检查 portal 可达性，
  不可达时报"可能不在校园网环境"并退出——在家跑 cron 不再误报"已在线"
- mock 新增 204 探测端点（自检用）

### Changed
- 注销拼接回退前置在线探测：离线时直接跳过（无会话，拼接必然失败）

## [1.3.0] - 2026-09-19

### Fixed
- 首次运行向导在 stdin EOF 时死循环（管道/SSH 断连触发），现中止并提示
- `cqie-auth --setup` 单独运行不生效，现作为独立配置命令

## [1.2.3] - 2026-09-19

### Fixed
- 修正 `bn_from_hex` 过时注释（BN_LIMBS 40→64 遗留）

## [1.2.2] - 2026-09-19

### Changed
- 注销时无可用 userIndex 的 ERROR 降为 WARN 并澄清语义（≈本来就未登录）

## [1.2.1] - 2026-09-19

### Fixed
- 配置文件 `service=` 留空时，自动取 `getServices` 运营商列表第一项
  （对齐浏览器默认选中行为；此前会提交空运营商导致认证失败）

## [1.2.0] - 2026-09-19

### Added
- **首次运行交互式向导**：凭据缺失且在终端上运行 login/reauth 时自动进入，
  依次询问用户名/密码（不回显、输两遍）/运营商（可留空自动探测），
  写入配置文件（0600）后当场继续认证
- `--setup` 显式触发向导；compat 层新增终端检测与回显开关

## [1.1.0] - 2026-09-19

### Added
- **凭据多通道**：`-u/--user`、`-p/--pass`、`--service` 命令行参数与
  `CQIE_USER` / `CQIE_PASS` / `CQIE_SERVICE` 环境变量
- 优先级：命令行 > 环境变量 > 配置文件 > 编译期默认
- `cqie-auth.conf.example` 示例配置

### Changed
- `BUILD.md` 移出版本库（本地私有文档）

## [1.0.0] - 2026-09-18

### Added
- 首个公开版本：锐捷 ePortal 校园网认证命令行工具
- 纯 C 单二进制、自实现 HTTP、零外部依赖（OpenWrt aarch64 / Linux x86_64 / Windows x64）
- 凭据与代码分离：配置文件读取（user/password/service）
- 并行 204 在线探测；RSA 加密登录；logout 三级 userIndex 来源
  （存储值 / 服务端要回 / 拼接回退）
- `--config`、`--portal`、`--state-dir`、`--interface` 源 IP 绑定、`--plain`、
  `--no-syslog`、`--dry-run`、`-v/-vv/-vvv` 等运行期选项
- mock 端到端自检（`make check`）
