# ADR 0010：静态 include 图和运行时 active stack 必须有界

Status: Accepted
Last updated: 2026-07-31
## 背景

固定上游 `includeScript()` 没有 cycle guard。self-cycle 和 two-node cycle 会
递归 evaluate，直到 QtScript 抛出 stack overflow `RangeError`；固定 Qt5 每个
case 发出 28 条 include messages 和一条 `_init` error，随后继续执行后续规则。
证据见
[`include-lifecycle-behavior.md`](../../research/include-lifecycle-behavior.md)。

复制这一实现会让终止依赖 runtime/native 栈深，无法满足不可信输入不得造成 stack
overflow、hang 或无界资源使用的工程约束。不同 JS runtime 也不会自然得到相同
深度和诊断数量。

## 决策

Proposed：

- database build 为可静态解析的 literal `includeScript()` 构造有向图；发现
  self-edge 或 strongly connected component 时返回带完整 path 的
  `DatabaseError::IncludeCycle`；
- runtime 对所有 include 维护 active include stack；动态名称再次进入 active
  path 时，在 evaluate 前返回 `RuleDiagnostic::IncludeCycle`；
- include depth、总 include evaluations 和 script fuel 同时受 scan budget 限制，
  cycle detection 不能替代 hard cap；
- 初始 modern default 候选为 include depth 16、每个 scan context 累计 include
  evaluations 256；显式 `LegacyHighResource` 候选为 depth 64、evaluations
  4096。固定全库 2,235 个程序文件的最大观察值为 depth 2/evaluations 30；
  modern 候选采用 8× depth headroom，以及 `30 × 8 = 240` 向上取 2 次幂得到
  256。数值在本 ADR Accepted 前仍可评审调整，任何 profile 都不得用 `0`、
  整数最大值或缺省表示无界；
- 实现不得依赖 Rust/native stack overflow、VM 默认 recursion limit 或进程崩溃；
- legacy differential 保留固定上游 28+1 raw diagnostics；Rust 的单一 typed
  cycle error 明确分类为 `SafetyDeviation`，不得规范化成 exact；
- ordinary duplicate include 在退出 active stack 后仍允许再次 evaluate，不能把
  cycle guard 错写成 include-once cache。

静态 cycle 是否让整个 database build 原子失败，按 `api.md` 当前 strict 默认；
未来 permissive profile 必须显式命名并返回不可忽略诊断。

## 考虑过的替代方案

### 依赖 QuickJS recursion limit

实现简单，但深度、错误文本和部分副作用随 runtime/build 改变，也可能先耗尽 native
stack，不能作为安全边界。

### 复制固定 Qt5 的 28 条 diagnostics

表面 raw 相似，但 28 是该 build 的偶然 VM/stack 结果。人为递归固定 28 次会制造
错误语义，也不能覆盖动态深链或其他平台。

### 全局 include-once

能阻止循环，但破坏上游已验证的重复 include 重新求值及 global side effect。

## 后果

- 损坏规则库更早、确定性地失败，资源消耗有界；
- cycle 行为与上游不 exact，需要精确 waiver 和兼容报告；
- database manifest/compiler 必须保存 include edges 和 source locations；
- runtime 即使接收动态 include，也必须执行同一 active-stack/budget 策略。

## 证据

- [`include-lifecycle-behavior.md`](../../research/include-lifecycle-behavior.md)
- [`include-lifecycle-linux-qt5.json`](../../research/data/include-lifecycle-linux-qt5.json)
- [`include-graph-sizing.md`](../../research/include-graph-sizing.md)
- [`include-graph-sizing.json`](../../research/data/include-graph-sizing.json)
- `die_script@5d82316.../die_scriptengine.cpp::includeScriptSlot`

## Decision acceptance

Phase 0 评审确认以下决策方向：

- include cycle 提前有界失败；
- 全库 sizing 已提出 modern 16/256 与 legacy-high 64/4096 两组候选。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- self、two-node、long acyclic chain 和 dynamic cycle 各有 unit/system test；
- `limit-1/exact/+1` 覆盖 include depth 和总 evaluation budget；
- 固定全库 sizing、future/custom database 和 dynamic include cases 证明或调整
  16/256 与 64/4096 两组候选，且 production CPU/peak-memory 有界；
- duplicate include 在非 active 状态继续重新求值；
- cycle diagnostic 含完整稳定 path/source locations；
- Rust/upstream 差分报告保留两侧 raw hashes，并仅用精确 SafetyDeviation waiver；
- fuzz/property test 不能产生 stack overflow、panic、hang 或无界 diagnostics。
