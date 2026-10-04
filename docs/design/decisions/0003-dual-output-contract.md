# ADR 0003：分离上游兼容输出与 canonical 输出

Status: Accepted
Last updated: 2026-07-31
## Context

固定上游 CLI 的单文件 JSON 可作为兼容 oracle，但多目标时会在多个 JSON 对象之间
插入 filename/colon，缺失目标和数据库/脚本错误也写入 stdout，导致结构化输出
无效。普通扫描与 entropy/info 的 formatter 优先级还不同。

diec-rust 同时要求 1:1 可观察兼容、稳定 C/Go/Python 数据面和可靠命令行自动化。
若只提供一种 renderer，要么破坏上游 raw 差分，要么延续无效 JSON 和隐式错误。

## Decision

Proposed：从同一个 immutable `ScanReport` 提供两个明确命名的输出面。

- legacy/compatibility renderer 复现固定上游的格式、排序、prefix、stdout/stderr
  和 exit 行为，用于迁移及 raw differential test。
- canonical renderer 生成带独立 schema version 的有效 UTF-8 JSON，供 Rust、
  C ABI、Go、Python 和现代 CLI 使用。
- 多目标 modern JSON 使用单个 `BatchReport`；另提供 NDJSON。
- legacy formatter flags 与 modern `--output` 冲突时返回 usage error。
- 核心 engine 不包含 formatter 或 CLI 错误吞并策略。

无参数 CLI 最终默认采用 legacy 还是 modern profile，在 Phase 0 评审后决定；测试
不得依赖未冻结默认值，必须显式选择 profile。

## Alternatives considered

### 只复刻上游输出

raw compatibility 最直接，但多目标 JSON/XML/CSV 不是有效文档，错误会污染 stdout，
不适合作为稳定 FFI 数据面。

结论：拒绝作为唯一输出；保留为 legacy profile。

### 只提供修正后的 canonical 输出

接口干净，但无法逐字节验证 CLI 等价，也会让依赖上游文本/JSON 的用户无法迁移。

结论：拒绝作为唯一输出。

### 在一个 JSON schema 中增加 compatibility 开关

会让同一 schema name 对应不同字段、错误流和多目标 framing，consumer 无法仅凭
version 判断语义。

结论：拒绝；renderer/profile 名称明确分离。

### 每个 adapter 自行序列化

开发初期简单，但 CLI、FFI 和语言绑定会产生不同字段、排序与错误处理。

结论：拒绝；canonical bytes 由 `diec-output` 单点生成。

## Consequences

正面：

- raw upstream regression 与可靠 machine-readable API 可以同时成立。
- C ABI 不继承 filename prefix、ANSI 或无效多文档 JSON。
- compatibility waiver 可定位到 renderer/adapter，不污染 engine error model。
- batch、空目录和 partial failure 在 modern schema 中始终可解析。

代价：

- 需要维护两套 golden output 和明确的 flag/profile 文档。
- legacy renderer 包含一些有意“不理想”的行为，必须防止被核心复用。
- 默认 profile 尚需兼容性与易用性评审。
- 新增 output 模式要决定是否属于 canonical schema 或 legacy formatter。

## Evidence

- [`cli-path-behavior.md`](../../research/cli-path-behavior.md)
- [`special-path-behavior.md`](../../research/special-path-behavior.md)
- [`cli-special-modes.md`](../../research/cli-special-modes.md)
- [`database-error-behavior.md`](../../research/database-error-behavior.md)
- [`behavior-baseline.md`](../../research/behavior-baseline.md)
- [`c-abi.md`](../c-abi.md)
- [`api.md`](../api.md)

## Decision acceptance

Phase 0 评审确认以下决策方向：

- legacy raw compatibility 与 modern canonical output 永久分离；
- legacy formatter 不混用 modern `--output`；
- canonical schema 候选已定义 single/batch/empty/partial output。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- 固定 corpus 的 legacy raw exit/stdout/stderr 与上游 oracle 分类一致。
- canonical 单目标、batch、empty 和 partial outputs 都通过 schema validation。
- C ABI、Rust 和 modern CLI 的 canonical bytes 相同。
- CLI 明确拒绝混用 legacy formatter flags 和 modern `--output`。
- 文档与 tests 明确默认 profile，或在冻结前始终显式选择。
