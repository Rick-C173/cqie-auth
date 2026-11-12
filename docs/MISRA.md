# MISRA C:2012 合规记录（MISRA）

> 本项目自 1.9.5 起以 **cppcheck 2.19 + misra.py 插件**为工具，按 MISRA C:2012
> （含 Amendment 2/3）对 `src/*.c`（含经 include 的头文件）做**双配置全量扫描**，
> 达到"**所有规则要么满足、要么有成文偏离**"的合规定义。
> 本文即偏离记录（deviation record）；门禁命令 `make misra`，零未豁免违规为通过条件。
> 策略变更说明见 `docs/CODING.md` 第 8 节。

## 1. 工具与范围

- **检查器**：cppcheck 2.19.0 + addons/misra.py（覆盖 MISRA C:2012 约 90 条可检规则；
  Directive 4.x 与少数不可静态判定规则不在其覆盖面内）
- **配置 A（POSIX，主门禁）**：`--library=posix` + 解析真实系统头文件
  （`-I/usr/include -I/usr/include/x86_64-linux-gnu`）——真实原型使 17.3（隐式声明）
  与 21.6（stdio）等规则获得准确判定
- **配置 B（_WIN32）**：`-D_WIN32 --library=windows --library=posix` +
  `scripts/misra_lib.cfg`（补齐 mingw 头文件在 Linux 上不可得的原型）——
  覆盖 `#ifdef _WIN32` 分支
- **扫描对象**：`src/*.c`（头文件经 TU 传递覆盖）；`/usr/include` 系统头自身
  的发现不计入（超出项目代码范围）
- **豁免体系**：规则级放行 = `scripts/misra_suppressions.txt`（本文逐条给理由）；
  站点级放行 = 行内 `/* cppcheck-suppress misra-c2012-X.Y 原因 */`

## 2. 修复统计（基线 1777 → 门禁 0 未豁免）

1.9.5 一次性修复约 **1160 条**违规，主要类别：

| 类别 | 规则 | 修复方式 |
| --- | --- | --- |
| 语句体复合化 | 15.6 | clang-tidy `readability-braces-around-statements` 迭代修复 + 自研单行展开脚本 |
| 忽略返回值 | 17.7 | `(void)` 前缀（279 处脚本 + 3 处手工） |
| 隐式声明 | 17.3 | 真实系统头文件解析（POSIX 侧） |
| 优先级括号 | 12.1 | `sizeof(X)` 操作数括号化（三目/逻辑链见偏差 12.1） |
| 本质类型 | 10.4/10.3/10.6 | 字面量 `U` 化、char 比较显式化、hexval ASCII 常量 |
| 位运算 | 10.1 | `1U`/移位计数显式转换 |
| 声明卫生 | 12.3/8.7/8.9/2.5/2.2 | 拆多变量声明、static 化、块作用域化、删死代码 |
| 资源与检查 | 22.8/22.9 | fopen/fclose/strtol 后的 errno 与判空纪律 |
| 控制流 | 13.3/13.4/13.5/14.2/15.4/15.7/17.8 | 副作用出表达式、赋值出条件、循环单出口重构 |

## 3. 偏离记录（规则级）

以下规则整体偏离（`scripts/misra_suppressions.txt`），每条给出理由与缓解措施。
条数为 1.9.5 合规化时的基线数量。

| 规则 | 级别 | 条数 | 偏离理由 | 缓解措施 |
| --- | --- | --- | --- | --- |
| 15.5 | Advisory | ~172 | `goto done` 单出口清理是本项目核心错误处理模式（见 CODING.md §5）；重构为嵌套标志位反而降低可读性 | goto 仅限函数尾清理、不前跳不跨资源生命周期；clang-tidy + 覆盖率 100% 门禁 |
| 12.1 | Advisory | ~132 | 检查器对"括号一致性"按上下文判定（同一表达式形态在不同 TU 结果不同，实测 `(len < psz - 1) ? a : b` 一处通过另一处告警）；已括号化全部 `sizeof` 操作数与三目条件，逻辑/比较链保持 C 惯用法 | sizeof 类已全部修复；运算符优先级行为由 146 项端到端测试覆盖 |
| 14.4 | Advisory | ~86 | `if (ptr)` / `if (!x)` 为 C 惯用法，`!= NULL` 噪音大于收益 | clang-tidy `clang-analyzer` 族覆盖空指针缺陷 |
| 18.4 | Advisory | ~58 | 指针遍历是 C 字符串处理基本操作，数组下标重写降低可读性 | 所有越界面均有 `out, outsz` 尺寸对约束（CODING.md §4） |
| 21.3 | Required | ~34 | CLI 工具使用堆分配；全部符合"上界可推导"模式（CODING.md §4），`malloc` 结果均判 NULL | clang-analyzer-unix（泄漏/溢出）+ 测试覆盖 |
| 11.5 | Required | ~9 | `malloc/realloc/memchr` 返回 `void*` 的赋值是库 API 形态 | 同 21.3 |
| 11.3 | Required | ~3 | `(struct sockaddr*)` 强转是 BSD socket API 的标准用法 | 地址族由 `getaddrinfo`/`AF_*` 判别保证 |
| 17.1 | Required | ~6 | `log_emit/log_status` 需要变参（printf 风格日志） | 格式串与实参由 `-Wformat=2` 编译期强校验 |
| 21.6 | Required | 0 | stdio（printf/fopen/snprintf）是 CLI 工具的本质能力。使用真实系统头文件后检查器不再报此项，按政策仍成文记录偏离 | stdout/stderr 分流、密码打码（CODING.md §6） |
| 21.8 | Required | ~8 | `getenv`（Amendment 2 纳入禁用）支撑环境变量覆盖层（CQIE_USER/CQIE_STATE_DIR 等），是容器/cron 场景的既定配置通道 | CLI 参数 > 环境变量 > 配置文件的分层覆盖已在测试中验证 |
| 22.8/22.9 | Required | ~6+~6 | 检查器局限：glibc 将 `errno` 展开为 `*__errno_location()`，代码中 `errno == 0` 的比较在转储里没有 `errno` 记号可匹配，任何 errno 纪律写法都无法被识别 | 代码已按 errno 纪律书写（`errno = 0` → 调用 → `errno == 0` 判定 + 数值范围校验）；行为由测试覆盖 |
| 15.2 | Required | ~8 | 检查器在嵌套作用域中查找 `done:` 标签失败（标签在函数作用域、goto 在循环内，为合法前向跳转） | 与 15.1 同族：goto 仅限函数尾清理 |
| 15.4 | Advisory | ~2 | 认证候选重试循环内多处 `goto done` 清理出口（15.1/15.5 同族）；hop 循环为检查器归属误报 | 单出口重构已尽力（向导/派发/解码/连接/探测循环均已收敛到 ≤1 break/goto） |
| 21.1 | Required | ~6 | `_POSIX_C_SOURCE`/`_WIN32_WINNT` 是 POSIX/Windows 标准要求的特性测试宏，必须使用保留名 | 每处 `#define` 有用途注释；clang-tidy `bugprone-reserved-identifier` 行内 NOLINT 说明 |
| 21.5 | Required | ~1 | `signal(SIGPIPE, SIG_IGN)` 防止对端关闭导致的写中断（POSIX socket 服务端常见做法） | 仅 SIGPIPE 一处；Windows 无此信号（编译期剔除） |
| 21.10 | Required | ~2 | `time.h`（clock_gettime）用于日志耗时与时间戳，无替代方案 | 仅取单调时钟，不做本地时间语义依赖 |
| 17.3 | Required | 24 | 仅 _WIN32 配置：mingw 头文件在 Linux 上不可得，检查器视角原型缺失 | POSIX 配置 0 条；Windows 侧由 mingw gcc（隐式声明 = 编译错误）兜底 |
| 20.1 | Required | ~18 | 检查器把 `#define` 的宏值记号误计为"代码记号"，对先宏后 include 的合法排布误报；特性测试宏必须先于 include（POSIX 要求） | 实际排布满足规则本义（include 前仅预处理指令） |
| 10.8 | Required | ~11 | 指针差值 `(size_t)(e - s)` 与字节合成 `(char)((hi << 4) | v)` 的惯用强转；重写为循环计数/临时变量降低可读性且无缺陷收益 | 差值两侧同源缓冲、字节合成值域经测试覆盖 |
| 5.5 | Advisory | ~2 | `sock_init/sock_quit` 在 POSIX 配置是宏、在 Windows 配置是函数——跨配置 shim，两种配置互斥存在 | 各配置内无实际冲突；由三平台编译门禁覆盖 |
| 2.5 | Advisory | ~7 | 平台 shim 宏（`WIN32_LEAN_AND_MEAN`/`poll→WSAPoll`/`sock_init` 等）在另一配置中"未被使用"属预期；DNS_TIMEOUT_MS 在用（检查器跨配置误报） | 行内 `cppcheck-suppress` 逐条注明 |

## 4. 站点级豁免（行内 cppcheck-suppress）

| 位置 | 规则 | 理由 |
| --- | --- | --- |
| `src/log.c` openlog | 10.1 | syslog 便利宏（LOG_PID 等）为 glibc 有符号位标志 |
| `src/main.c` stat 权限检查 | 10.1/10.4 | `mode_t`/`S_IRWXG` 系统宏混算 |
| `src/state.c` S_ISDIR ×2 | 10.4 | glibc `S_ISDIR` 宏内部混算 |
| `src/util.c` 字节合成 | 10.1 | 见 10.8 族偏离 |
| `include/compat.h` shim 宏 ×6 | 2.5 | 平台 shim（含 `sock_init/sock_quit`） |
| `src/http_min.c` DNS_TIMEOUT_MS | 2.5 | 在用宏的跨配置误报 |
| `src/util.c`/`src/http_min.c` 测试入口 | 8.7 | `tests/harness.c` 使用的测试通道 API |

## 5. 偏离流程

新增代码触发未豁免违规时：优先**修改代码满足规则**；确属惯用法/不可修时，
在本文对应规则行更新理由与条数（规则级）或添加带原因的行内豁免（站点级），
并同步更新 `docs/CODING.md` 第 8 节引用。规则级清单变更必须与本文件同步评审。
