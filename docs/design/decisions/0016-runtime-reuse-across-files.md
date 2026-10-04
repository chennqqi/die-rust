# ADR 0016：同一 file_type 的规则运行时跨文件复用

Status: Accepted
Last updated: 2026-08-04

## Context

当前 `scan_bytes`（`crates/die-engine/src/scanner.rs:293-405`）对每个文件
的每个 file_type group 执行完整的 runtime 生命周期：

1. `RquickjsRuntime::new()` — 创建 QuickJS runtime + context，设置
   memory/stack limit、interrupt handler、full intrinsics
2. `register_host_api(host)` — 注册 `Binary`/`X`/`File` JS 对象桥接
3. `load_database(framework)` — `register_globals()` eval 一大段全局函数
   定义，再 eval `_init` 脚本和 `read` include 脚本
4. `init(host)` — eval type_init 脚本（如 `var File = Binary; var X = Binary;`）
5. 对每条规则调用 `evaluate_rule_source()` — 规则源码包在 IIFE 中执行
6. `shutdown()`

扫描下一个文件时步骤 1-4 全部重来。其中步骤 1、3、4 的输入（runtime 配置、
framework 脚本、type_init 脚本）对同一 file_type 是**固定不变**的，只有步骤 2
的 host 数据和步骤 5 的规则执行结果随文件变化。

在批量扫描场景（CLI `--recursive` 扫描目录、未来服务化常驻进程处理多请求），
假设扫描 N 个 PE 文件，当前需要 N 次 runtime 创建 + N 次 framework 加载。
`database_load` benchmark 显示并行加载全库约 160ms，而单文件 PE 扫描约 89ms
（含原生解析），其中 runtime 创建和 framework 加载占非平凡比例。

ADR 0006 第 "兼容层" 明确要求 per-rule lexical wrapper 模拟 Qt evaluate 行为，
且每次上游同步必须重跑 persistent var/function dependency audit。规则源码已用
IIFE 隔离 `detect` 声明（`backend_rquickjs.rs:604-612`），但规则顶层 `var`/全局
赋值仍可能泄漏到全局作用域，跨文件复用 runtime 时这些状态会影响后续文件的
检测结果。

## Decision

Proposed：在 `scan_bytes` 内部，对同一 file_type group 的 runtime 实现受控
复用，复用边界由差分测试和状态审计共同约束。

### 复用范围

- **复用对象**：`RquickjsRuntime` 实例，包含已加载的 framework（globals +
  init + read include）和已执行的 type_init 脚本。
- **复用粒度**：同一 `scan_bytes` 调用内，同一 file_type 的 runtime 在多个
  规则评估之间已天然复用（当前行为）。本 ADR 扩展为**跨文件**复用：在
  `Scanner` 或等价有状态对象中缓存 per-file_type 的 runtime，后续文件命中
  同一 file_type 时跳过步骤 1-4。
- **不复用的情况**：
  - runtime 发生未捕获异常或 OOM/limit 触发后，销毁并重建（ADR 0006
    "context 在 interrupt/exception 后只有通过明确恢复测试才能复用"）。
  - file_type group 的规则集合发生变化（database 重新加载）。
  - 显式 `Scanner::reset()` 调用。

### 状态隔离

跨文件复用前必须清理上一文件遗留的可变状态：

1. **结果数组**：`__diec_results` 已在 `evaluate_rule_source` 开头清空
  （`backend_rquickjs.rs:589`），无需额外处理。
2. **cancel flag**：已在 `evaluate_rule_source` 开头 clear
   （`backend_rquickjs.rs:582`），无需额外处理。
3. **host API 桥接**：`register_host_api` 将 `Binary`/`X`/`File` 绑定到
   特定 `Arc<HostApi>`。复用时必须替换为新文件的 host。需要评估
   `HostApiBridge::register` 是否支持覆盖已注册的全局对象，或需要新增
   `update_host` 方法。
4. **规则全局副作用**：规则顶层 `var`/全局赋值可能跨文件泄漏。这是核心
   风险，必须通过 persistent state audit 验证。

### Persistent state audit

实现前必须完成以下审计，作为 Implementation exit 门禁：

- 对固定规则集的全部 1186 条规则，静态扫描顶层 `var`/全局赋值（非 IIFE
  内、非 `detect` 函数内），列出可能泄漏到全局的变量清单。
- 对清单中的每个变量，判断是否：
  - (a) 只读常量（如 `var _LE = 0;`）— 安全，复用不影响结果。
  - (b) 可变状态且被后续规则读取 — 需要在复用前重置。
  - (c) 可变状态但只被同一规则的 `detect` 读取 — IIFE 已隔离，安全。
- 对 (b) 类变量，在 runtime 复用前执行重置脚本（如
  `__diec_results = []; __diec_block_list = [];` 已有，需扩展）。
- 审计结果写入 `docs/research/runtime-reuse-state-audit.md`，每次上游规则
  同步后重跑。

### 差分验证

- 在现有 31 基线 + 20 边缘样本语料上，对比"每文件新建 runtime"和"复用
  runtime"的检测结果，要求 0 不匹配。
- 新增 benchmark `scan_corpus_reuse` 对比单文件 runtime 创建 vs 复用的
  吞吐差异。
- 新增 fuzz target 验证复用 runtime 在大量畸形输入下不产生状态累积导致的
  假阳性/假阴性。

### API 影响

- `scan_bytes` 签名不变（无状态函数），内部不享受复用。
- 新增 `Scanner` 有状态对象（或扩展现有结构），持有 per-file_type runtime
  缓存，提供 `scan_file`/`scan_bytes` 方法。CLI `--recursive` 和未来服务
  化层使用 `Scanner`，单次 `scan_bytes` 保持原样供 FFI 和测试使用。
- `Scanner` 不进入 C ABI（FFI 仍用无状态 `scan_bytes`），避免增加 ABI
  复杂度。

## Alternatives considered

### 每文件新建 runtime（当前行为）

最安全，状态完全隔离。代价是批量扫描时重复的 runtime 创建和 framework
加载开销。在服务化场景（ADR 0017）下，这个开销会乘以请求数。

结论：保留为 fallback 和 FFI 路径，但批量路径启用复用。

### 跨 file_type runtime 池化

一个 runtime 池服务所有 file_type，按需切换 framework。

代价：file_type 切换需要重新 load_database + init，等于不复用；且不同
file_type 的 type_init 脚本可能冲突（如 `var File = Binary` vs
`var File = JavaClass`）。收益有限（单文件通常只命中 1-2 个 file_type）。

结论：拒绝。复用粒度限定为同一 file_type。

### 预编译规则为字节码

QuickJS 支持字节码缓存，可将规则源码预编译为字节码避免重复 parse。

代价：字节码与 QuickJS 版本绑定，升级 runtime 需重新生成；字节码加载的
兼容性和安全性需额外验证；上游规则同步后需重新预编译。

结论：保留为未来优化选项，不在此 ADR 范围内。先做 runtime 实例复用。

## Consequences

正面：

- 批量扫描吞吐提升（预期 runtime 创建 + framework 加载开销从 O(N) 降为
  O(file_type 数量)）；
- 为 ADR 0017 服务化方案提供性能基础——常驻进程内 runtime 复用使单请求
  开销接近"仅规则执行"成本；
- `Scanner` 有状态对象为未来并发扫描（per-thread runtime）提供结构基础。

代价：

- 引入 persistent state audit 维护面，每次上游规则同步需重跑；
- `Scanner` 有状态对象增加核心层 API 表面（但保持 `scan_bytes` 无状态路径
  供 FFI）；
- runtime 异常后的重建逻辑需仔细实现，避免复用已损坏的 runtime；
- host API 替换机制需要验证或新增 `update_host` 方法。

## Implementation

### 已实现（2026-08-04）

- **`RquickjsRuntime::reinit()`**（`crates/die-rules/src/backend_rquickjs.rs`）：
  清除上一文件的结果 + 重新执行 type_init 脚本更新 host 别名
  （`var File = PE; var X = PE;`）。
- **`Scanner` 结构**（`crates/die-engine/src/scanner.rs`）：
  - `Scanner::new(Arc<Database>)` — 持有 database，runtime 懒加载
  - `Scanner::scan_bytes()` — 复用 per-file_type runtime，register_host_api
    覆盖旧 host + reinit 更新别名 + evaluate_rule_source
  - `Scanner::scan_file()` — 读取文件后委托 scan_bytes
  - `Scanner::reset()` — 清空缓存，强制重建 runtime
  - BudgetExceeded 时驱逐 runtime，下次扫描重建
- **差分验证测试**（4 个，全部通过）：
  - `scanner_differential_reuse_vs_no_reuse` — 复用 vs 非复用 0 不匹配
  - `scanner_differential_same_file_twice` — 同文件两次扫描结果一致
  - `scanner_differential_multiple_formats_sequence` — 多格式顺序+逆序无交叉污染
  - `scanner_reset_clears_cache` — reset 后缓存清空且能重建
- **限制**：`Scanner` 是 `!Send`（QuickJS context 线程局部），不能跨线程
  共享。服务层（ADR 0017）当前用无状态 `scan_bytes`，runtime 复用留作
  专用 worker 线程后续优化。CLI 批量模式可直接使用 `Scanner`。

## Evidence

- `crates/die-engine/src/scanner.rs:293-405` — 当前 scan_bytes 实现
- `crates/die-rules/src/backend_rquickjs.rs:89-124` — RquickjsRuntime::new
- `crates/die-rules/src/backend_rquickjs.rs:446-482` — load_database
- `crates/die-rules/src/backend_rquickjs.rs:484-504` — init
- `crates/die-rules/src/backend_rquickjs.rs:569-639` — evaluate_rule_source
  IIFE 隔离
- `crates/die-rules/src/backend_rquickjs.rs:550-554` — shutdown
- ADR 0006 — rquickjs runtime 资源与恢复约束
- 待补充：`docs/research/runtime-reuse-state-audit.md`
- 待补充：`scan_corpus_reuse` benchmark 结果

## Decision acceptance

评审确认以下决策方向：

- 同一 file_type 的 runtime 跨文件复用是合理的性能优化方向；
- persistent state audit + 差分验证作为复用安全性的双重保障；
- `Scanner` 有状态对象与 `scan_bytes` 无状态函数并存的 API 策略；
- 复用边界（异常后重建、host 替换、状态重置）的约束合理。

## Implementation exit

以下条件满足后才能视为完整交付：

- 固定 1186 条规则的 persistent state audit 完成，(b) 类变量清单为空或
  已有重置脚本覆盖；
- 31 基线 + 20 边缘样本差分测试在复用模式下 0 不匹配；
- `scan_corpus_reuse` benchmark 证明吞吐提升且无内存累积；
- runtime 异常后重建路径有单元测试覆盖（OOM、未捕获异常、cancel 中断后
  复用）；
- host API 替换机制有测试覆盖（同 runtime 不同 host 的检测结果正确）；
- 新增 fuzz target 在复用模式下无状态累积导致的假阳性/假阴性；
- `Scanner` API 有文档注释和集成测试；
- cargo fmt/clippy/test 全部通过。
