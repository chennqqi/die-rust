# ADR 0004：兼容差异使用证据约束的精确 waiver

Status: Accepted
Last updated: 2026-07-31
## Context

diec-rust 以固定 DIE-engine 为兼容基线，但安全 hard limit、平台路径和已确认的上游
缺陷可能需要有意偏离。普通 allowlist 常以 glob、字符串替换或忽略整段 JSON
隐藏差异；随着输出扩大，旧规则可能继续匹配新的回归。

项目又必须保留原始和规范化输出，且默认把可观察差异视为缺陷。

## Decision

Proposed：所有允许差异使用 versioned、machine-readable、evidence-bound waiver。

每项 waiver 必须固定 case ID、平台、upstream commit、Rust schema、精确字段或
raw diff fingerprint，并记录分类、证据、ADR、owner、期限和移除条件。

v1 采用 JSON registry：一个文件只绑定一个
`(platform, upstream_commit, rust_schema)` identity，每条 record 只绑定一个
case ID 和一个非根 semantic JSON Pointer。日期使用 ISO `YYYY-MM-DD`，审计必须
显式传入 `as_of`；`as_of >= expires` 即过期。只有完成 owner review 的
`status=approved` record 能进入 registry，proposal 不作为可应用 waiver。

- 未匹配差异默认失败。
- wildcard case、root JSON path 和整份 stdout blanket waiver 禁止。
- waiver 只能匹配登记时的 exact fingerprint；差异扩大后失败。
- expired、stale、unmatched waiver 使 CI 失败。
- 安全、panic/crash/hang、data race、unbounded allocation、ABI UB、
  silent unknown rule syntax（静默未知规则语法）不可 waiver。
- `SafetyDeviation` 必须有威胁分析和回归测试。
- `Unsupported` 必须链接 roadmap phase 和可测退出条件。
- 原始输出永不被 waiver 或 normalizer 改写。

## Alternatives considered

### 禁止所有差异

原则最简单，但无法安全处理上游无界递归、平台编码和确定存在的 upstream defect。

结论：作为默认行为保留，但允许严格审批的例外。

### 文本 allowlist/glob

实现容易，但容易匹配范围扩大后的差异，无法关联字段语义、平台和版本。

结论：拒绝。

### 只在文档中记录已知差异

便于解释，但 CI 不能判断差异是否仍精确一致、已经消失或扩大。

结论：拒绝；文档/ADR 与机器记录同时存在。

### 规范化掉所有平台差异

报告简洁，但会丢失路径、排序、encoding 和 line-ending 的真实兼容性证据。

结论：拒绝；仅规范化被证明无语义的最小字段。

## Consequences

正面：

- 新回归不会因旧的宽泛 allowlist 被误放行。
- 每项偏差都有来源、责任人和消除路径。
- upstream/schema/platform 升级会主动使旧 waiver 失配。
- compatibility report 可准确区分 exact、semantic、safety 和 unsupported。

代价：

- waiver schema、validator、fingerprint 和 stale detection 增加维护面。
- 上游升级时需要逐项复审。
- 平台差异较多时记录数量可能增加。
- 精确 raw fingerprint 对输出 framing 变化敏感，但这是期望的审计门禁。

## Evidence

- [`testing.md`](../testing.md)
- [`api.md`](../api.md)
- [`cli-path-behavior.md`](../../research/cli-path-behavior.md)
- [`special-path-behavior.md`](../../research/special-path-behavior.md)
- [`database-error-behavior.md`](../../research/database-error-behavior.md)
- [`nested-scan-behavior.md`](../../research/nested-scan-behavior.md)
- [`difference-waiver-registry-v1.schema.json`](../schemas/difference-waiver-registry-v1.schema.json)
- [`difference-input-report-v1.schema.json`](../schemas/difference-input-report-v1.schema.json)
- [`difference-waiver-audit-v1.schema.json`](../schemas/difference-waiver-audit-v1.schema.json)
- [`semantic-case-audit-v1.schema.json`](../schemas/semantic-case-audit-v1.schema.json)
- [`validate_difference_waivers.py`](../../../tools/compat/validate_difference_waivers.py)
- [`audit_semantic_case.py`](../../../tools/compat/audit_semantic_case.py)
- [`run_compatibility_suite.py`](../../../tools/compat/run_compatibility_suite.py)
- [`test_validate_difference_waivers.py`](../../../tools/tests/test_validate_difference_waivers.py)
- [`test_audit_semantic_case.py`](../../../tools/tests/test_audit_semantic_case.py)
- [`test_run_compatibility_suite.py`](../../../tools/tests/test_run_compatibility_suite.py)

## Implementation status

Phase 0 reference implementation已经具备：

- 单一 platform/upstream/Rust schema registry identity；
- 单 case、单非根 JSON Pointer、双 raw hash 和 canonical diff fingerprint；
- exact match、expiration、stale、unmatched case/difference 和 identity drift；
- `SafetyDeviation` threat/regression、`Unsupported` phase/exit condition 门禁；
- 对 crash、memory safety、data race、panic、hang、unbounded allocation、
  silent unknown syntax 和 ABI UB 的结构性拒绝；
- 严格 JSON duplicate-key/non-finite 拒绝、输入文件 SHA-256 和只读审计；
- deterministic `--as-of`、`pass`/`fail`/`infrastructure_error` exit contract。

ADR 仍保持 Proposed：独立 verifier 已能重新读取并校验 content-addressed raw
artifact 本体；单 case comparator 也已从两侧 raw execution 按
verification/framing/semantic projection/optional normalization/comparison 顺序
重建证据，并直接产生 fingerprint 已复算的 waiver input。projection failure 或
差异超过固定上限时写入不可被 validator 接受的 blocked marker，避免复用旧报告。
顶层 single-case auditor 已按固定顺序调用 comparator 与 waiver validator，
冻结并复核 registry/中间产物，且将 blocked comparison 传播为不可通过的
infrastructure audit。独立 comparator 仍是可单测的低层工具。多 case/full
report runner 已使用 hash-bound expected matrix 聚合 typed legacy case，并对
platform/capability/classification/waiver 做确定性汇总。engine-only/modern
variant 和 release approval/signing 尚未接入；synthetic owner 字段同样不能
替代真实 compatibility owner review 流程。

## Decision acceptance

Phase 0 评审确认以下决策方向：

- 默认拒绝且 evidence-bound 的精确 waiver 机制；
- waiver 必须绑定 upstream commit、case identity 和差异字段；
- SafetyDeviation 不得在 normalizer 中隐藏。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- waiver schema 和 validator 拒绝 wildcard、缺失 identity、expired 和 stale 记录。
- 测试证明 diff 扩大、缩小、消失或换平台/commit 时旧 waiver 不会静默通过。
- report 同时列出 applied、unmatched 和 stale waivers。
- raw artifacts 在 waiver 前后 hash 相同。
- compatibility owner review 是 waiver 增改的必需检查。
