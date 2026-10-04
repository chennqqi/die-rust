# ADR 0009：现代 API 取消不返回上游部分检测结果

Status: Accepted
Last updated: 2026-07-31
## 背景

固定上游实验证明 callback 返回 false、规则 `_breakScan()` 和调用前已停止不会让
扫描 API 返回类型化错误。运行中停止保留当前规则产生的 detection；最后一条才
停止时甚至保留完整 detection 集但仍报告 canceled；调用前停止仍可能追加
`Unknown`。同步外部线程在 callback checkpoint 设置 stop 会保留当前规则，同一
engine 换 fresh state 后恢复。`PDSTRUCT` stop flag 是 plain `bool`，未同步跨线程
访问属于数据竞争而非可移植契约。证据见
[`engine-contract-behavior.md`](../../research/engine-contract-behavior.md)。

这会让非空结果同时表示完整成功、部分取消和未开始扫描。现代 Rust API 若原样返回
`ScanReport`，调用方容易遗漏 completion 检查；完全丢弃部分结果又不是上游 exact。

## 决策

Proposed：

- modern Rust/JSON/C ABI 中，外部取消或 deadline 返回类型化 termination，不把
  上游式部分 detection 作为成功 report；
- cancellation error 可以携带 stage、来源和资源计数，但不携带 detections；
- legacy compatibility 测试保留上游原始部分结果和 `PDSTRUCT` 状态，不用 modern
  normalizer 把两者声明为 exact；
- 规则 `_breakScan()` 映射为 cancellation 还是规则控制流的 partial completion，
  在完成更多真实调用点调查前保持开放。

本 ADR Accepted 前，API 文档中的该行为是候选契约，不是稳定承诺。

## 理由

- 类型系统强制调用方处理取消，不把截断结果误当完整结果；
- 不暴露依赖具体 checkpoint 的不稳定 detection 前缀；
- legacy 证据仍完整保存，差异可审计。

## 代价

- modern API 与固定上游停止行为不是 semantic exact；
- 需要单独的差异分类、waiver 和回归测试；
- 若未来需要部分结果，必须设计显式 `Partial`，不能悄悄改变 `Cancelled` 内容。

## 考虑过的替代方案

### 完全复制上游

返回部分 detections，并要求调用方同时检查 stopped 状态。兼容最直接，但现代 API
很容易被误用，且部分前缀依赖取消检查点。

### 显式返回 `Partial`

保留 detections 并用 completion 标明取消。表达力更强，但尚未证明调用方需求，
也没有冻结跨 runtime/checkpoint 的稳定前缀；保留为 ADR 复审选项。

## 证据

- [`engine-contract-behavior.md`](../../research/engine-contract-behavior.md)
- [`engine-contract-linux-qt5.json`](../../research/data/engine-contract-linux-qt5.json)

## Decision acceptance

Phase 0 评审确认以下决策方向：

- modern cancel 不返回 partial detections，completion 标明终止原因；
- legacy 与 modern 永久分离，legacy 部分结果用 ADR 0004 waiver 处理。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- callback 在首/中/末 false、同步外部 stop、`_breakScan()`、调用前取消和
  fresh-state 恢复分别有 upstream raw baseline；
- modern Rust、JSON 和 C ABI 对三类 case 返回一致 termination；
- legacy 差分验证部分 record、Unknown 和 stop/success 状态；
- waiver 精确绑定 upstream commit、case 和差异字段；
- cancel/deadline 竞争及清理后 context/scanner 恢复通过测试。
