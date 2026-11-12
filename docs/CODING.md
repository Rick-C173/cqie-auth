# 编码规范（CODING）

> 本项目遵循"**成文规范 + 工具强制**"的体系：本文件定义规则，工具链
> （gcc / clang-tidy / clang-format / CI）负责强制执行。任何规则变更必须
> 同步修改对应的检查器配置，保证"写的即查的"。
>
> 与 MISRA C 的关系见第 8 节：选择性采纳其缺陷防御类条款，惯用法类条款
> 显式偏离并记录理由——不做"为合规而合规"的全量改写。

## 1. 语言与编译门禁（make 强制）

- C99（`-std=c99`），POSIX.1-2008 特性测试宏按需声明（`_POSIX_C_SOURCE 200809L`）
- 告警面：`-Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wformat=2`
  **零告警**；Linux(x86_64/aarch64 musl) 与 Windows(mingw) 三平台同等标准
- 无外部依赖：HTTP 客户端自实现（http_min.c），链接仅 libc/libwinsock

## 2. 静态分析门禁（.clang-tidy，CI 可复现）

- 引擎：clang-tidy（LLVM 24+，与 CLion 捆绑版同源），检查集见 `.clang-tidy`
- 覆盖：`bugprone-*`（缺陷模式）、`cert-*`（CERT C 对应项）、
  `clang-analyzer` core / security / unix / valist
- `WarningsAsErrors: bugprone-*, clang-analyzer-security.*`
- **误报处理**：行内 `/* NOLINT(check): 理由 */`，必须写明理由
  （现行唯一豁免：`_POSIX_C_SOURCE` 特性测试宏，POSIX 标准要求的保留名）
- 本地复现命令（WSL，CLion 捆绑引擎）：
  ```sh
  /mnt/d/JetBrains/CLion/bin/clang/wsl/x64/bin/clang-tidy src/xxx.c -- \
      -Iinclude -std=c99 -isystem /usr/lib/gcc/x86_64-linux-gnu/15/include \
      -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include
  ```

## 3. 风格（.clang-format 强制，CLion Reformat 即规范）

- Allman 大括号（独占一行）、4 空格缩进、列宽 100、不拆长字符串字面量
- 指针星号贴类型：`char* p`、`FILE* in`
- `switch` 的 `case` 缩进一层；`include` 保持手写顺序不重排
- **命名**：模块前缀 snake_case（`auth_` `http_` `state_` `compat_` `log_` `util_`，
  命令入口 `cmd_`）；文件域 static 全局 `g_` 前缀；宏/常量 UPPER_CASE；类型 `_t` 后缀
- 注释：中文，解释**为什么**（设计决策 / 历史 bug 编号 / 平台差异），不逐行翻译代码

## 4. 内存与字符串安全（CERT 精神，强制）

- **禁止** `strcat` / `strcpy` / `sprintf`：拼接用 `snprintf(dst+off, sizeof dst-off, ...)`
  定界追加，拷贝用 `memcpy` 精确长度（`clang-analyzer-security.insecureAPI` 为 ERROR）
- **禁止** `atoi` / `atol`：一律 `strtol(s, NULL, 10)`（cert-err34-c）
- 堆分配优先"**上界可推导**"模式：分配尺寸与循环边界可直接证明
  （urlencode 的 `malloc(3n+1)` 上界），避免依赖两遍遍历判定一致的写法
- `malloc` 结果必须判 NULL；所有出参函数签名带 `out, outsz` 尺寸对
- 凭据/状态文件：0600 权限 + tmp 文件 rename 原子写

## 5. 错误处理与控制流

- 多资源释放统一 `goto done` 单出口模式——本项目对 MISRA 15.1 的**显式偏离**：
  goto 仅用于函数尾部统一清理，不前跳、不跨资源生命周期
- 交互输入 EOF 必须有显式出口（1.3.0 死循环教训：管道/重定向下 fgets 立即返回 NULL）
- API 返回值只用 0/1 布尔语义，**禁止 -1 三态**（is_online 教训，1.4.1 修复）
- 失败路径必须 `LOG_ERROR` 根因并 `log_status` 一条结果行

## 6. 输出与日志

- 结果走 **stdout**、诊断走 **stderr**，互不污染（脚本可安全重定向）
- syslog 每次运行只写一条结果行（不含调试细节，`--no-syslog` 可关）
- 日志中密码字段必须打码（`log_form` 的 `password=<N 字符,已打码>`）

## 7. 版本与变更纪律

- 改 `src/` `include/` `Makefile` `tests/` 前先加 `CQIE_VERSION`
  （修复 +0.0.1 / 加功能 +0.1.0 / 大版本 +1.0.0）；纯文档不加
- `CHANGELOG.md` 每版本必记（Keep a Changelog 格式）
- 提交前 `make` + `make check` 全过；push tag `v*` 自动触发 Release

## 8. MISRA C 偏离记录（选择性采纳）

MISRA C:2012 面向安全关键领域（汽车/医疗）。本项目**采纳**其与 CLI 工具
匹配的缺陷防御类条款（经上方工具落地），**偏离**惯用法类条款并记录如下：

| MISRA 条款 | 内容 | 偏离理由 |
| --- | --- | --- |
| 14.4 | 条件须"本质布尔" | `if (ptr)` / `if (!x)` 为 C 惯用法，`!= NULL` 噪音大于收益 |
| 15.1 / 15.5 | 禁 goto / 限 break-continue | `goto done` 统一清理是本项目核心错误处理模式（受控使用） |
| 15.6 | 语句体须复合语句 | 短保护语句（`if (!p) return 0;`）单行更清晰 |
| 17.7 | 非 void 返回值不得丢弃 | 部分采纳：关键调用检查返回值；诊断输出类（printf/LOG_*）豁免 |
| 18.4 | 禁指针算术 | 指针遍历是 C 字符串处理基本操作，数组下标重写降低可读性 |

## 9. 测试纪律

- `make check`：端到端自检（mock AC + 真机协议比对），当前 146 项；新增行为必配断言
- 覆盖率门禁：CI 语句覆盖率 100%（cov_agg.py 聚合）
- 修复 bug 时先在 check.sh 复现（红）再修（绿）
