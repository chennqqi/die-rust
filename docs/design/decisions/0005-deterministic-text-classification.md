# ADR 0005：文本分类不复制上游未初始化状态

Status: Accepted
Last updated: 2026-07-31
## Context

固定 XScanEngine
`dfe4a419e4f491bb23688ba03c5a5bf39e34da83` 的
`Binary_Script` 构造器只在识别到 UTF-16 时把
`m_bIsUnicodeText` 写为 `true`；非 UTF-16 路径没有初始化该字段。
`isUnicodeText()` 直接返回该字段，`isText()` 又将它与 plain/UTF-8 标志按位或。

89-case Qt5 oracle 使用 placement new，在构造前分别以合法 `bool` 对象表示
`0x00` 和 `0x01` 填充同一块存储。固定普通二进制输入得到：

- zero prefill：`isUnicodeText=false`、`isText=false`；
- one prefill：`isUnicodeText=true`、`isText=true`。

相同的 UTF-16LE 输入在两种 prefill 下都得到 `true/true`，证明 Unicode 分支会
覆盖字段，而非 Unicode 分支的可观察值取决于对象构造前的存储内容。复制这种
行为需要在 Rust 中引入未初始化读取；它既非确定语义，也违反项目对安全、确定性
输出和不可信输入的约束。

## Decision

Proposed：Rust 文本上下文始终显式初始化所有分类事实，并定义：

```text
isUnicodeText = unicode_type != None
isText = isPlainText || isUTF8Text || isUnicodeText
```

不得用 `unsafe`、未初始化内存、随机值或平台相关填充值模拟固定上游的偶然状态。
原始 Qt5 zero/one prefill 输出都必须保留，作为上游缺陷证据。

这是一项限定到非 Unicode 输入的 `isUnicodeText`/`isText` 安全偏差，而不是允许
扩大到其他文本检测、header decoding 或规则结果的 blanket waiver。Phase 1
差分框架建立后，必须按 ADR 0004 创建绑定以下身份的 machine-readable waiver：

- upstream/XScanEngine commit；
- oracle case ID 和原始 baseline hash；
- 精确输出字段；
- 本 ADR；
- 删除条件：上游初始化字段，或兼容基线升级后行为变为确定。

在 waiver 工具可用前，Phase 0 spike 通过成对 prefill 回归测试同时证明上游分歧
和 Rust 确定值，不宣称这两个非 Unicode 字段与任一上游运行逐位相等。

## Alternatives considered

### 默认取 zero prefill 并称为精确兼容

在常见分配器上可能看似稳定，但没有源码契约保证，也会掩盖 one prefill 已证明的
相反结果。

结论：拒绝。

### 用 `unsafe` 复制未初始化读取

可能更接近某次 C++ 运行，却引入 Rust 未定义行为、非确定输出和潜在优化器差异。

结论：拒绝。

### 将所有非 Unicode 输入都视为文本

可以匹配 one prefill，但会系统性制造 false positive，且同样无法匹配 zero
prefill。

结论：拒绝。

### 暂不提供 `isText`

避免立即决策，但固定规则已实际调用该方法，会留下 Host API fallback 并阻断规则
运行时缺口收口。

结论：拒绝。

## Consequences

正面：

- 所有输入和平台产生确定结果；
- 不需要 `unsafe`；
- 普通二进制不会因分配器残留字节随机变成文本；
- 规则调用不再依赖诊断 fallback。

代价：

- 非 Unicode `isUnicodeText`/`isText` 无法与上游每一次含未初始化读取的运行同时
  一致；
- Phase 1 必须实现并维护精确安全 waiver；
- 上游基线升级时必须重新运行成对 prefill oracle。

## Evidence

- [`signature-oracle-vectors.json`](../../research/data/signature-oracle-vectors.json)：
  `binary_script_nontext_prefill_*` 与 `binary_script_unicode_prefill_*`。
- [`signature-oracle-qt5.json`](../../research/data/signature-oracle-qt5.json)：
  固定 Qt5 原始结构化输出。
- [`signature-language.md`](../../research/signature-language.md)：
  oracle 构建、身份和源码行为说明。
- [`rquickjs-rule-runtime-spike.md`](../../research/rquickjs-rule-runtime-spike.md)：
  Rust native Host API 与 292-rule trace。
- [`0004-evidence-bound-difference-waivers.md`](0004-evidence-bound-difference-waivers.md)。

## Decision acceptance

Phase 0 评审确认以下决策方向：

- deterministic text facts 取代未初始化状态；
- `Binary.isUnicodeText` 和 `Binary.isText` 为 native Host API，不经过 fallback；
- 292-rule 固定 trace 为 292/292 无异常且 fallback 为零。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- 固定 Qt5 probe 对 zero/one 普通二进制的相反结果和 UTF-16 的稳定结果做强断言。
- Rust 测试证明普通二进制稳定返回 `false`，UTF-16 稳定返回 `true`。
- Phase 1 差分框架拒绝范围超出上述字段和 case identity 的 waiver。
