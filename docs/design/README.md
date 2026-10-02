# 设计文档

本目录保存由调研证据支持的 diec-rust 设计。尚未完成上游调研的部分应明确标记为待定。

- [`schemas/`](schemas/)：raw execution/framing、legacy CLI semantic result、
  normalization、双侧 semantic comparison、差分输入、精确 waiver registry 和
  audit 的版本化 machine-readable schema 与 synthetic examples。

Phase 0 计划形成：

- [`architecture.md`](architecture.md)：workspace、模块边界、依赖方向和数据流（In Review）。
- [`api.md`](api.md)：Rust API、CLI 契约、结果及错误模型（In Review）。
- [`c-abi.md`](c-abi.md)：C ABI、所有权、线程安全和静态链接（In Review）。
- [`testing.md`](testing.md)：语料、oracle、差分、fuzz、benchmark 和 CI（In Review）。
- [`risks.md`](risks.md)：Phase 0 风险、触发条件、缓解和关闭证据（In Review）。
- [`resource-limit-policy.md`](resource-limit-policy.md)：统一 scan/traversal 候选
  profile、完整但未准入的预算集和准入条件（In Review，尚未冻结）。
- [`data/traversal-attempt-budget-candidate.json`](data/traversal-attempt-budget-candidate.json)：
  metadata/open attempt 单位、结构推导、跨平台上游证据边界和准入条件。
- [`data/diagnostic-budget-candidate.json`](data/diagnostic-budget-candidate.json)：
  typed diagnostic fact 上限、overflow completion 和 scan profile 字段闭包。
- [`data/input-budget-candidate.json`](data/input-budget-candidate.json)：
  root logical length 单位、1 GiB/8 GiB 候选及与读取/分配 counter 的边界。
- [`data/allocation-budget-candidate.json`](data/allocation-budget-candidate.json)：
  scan-owned capacity 的单调累计语义、1 GiB/8 GiB 候选及 RSS 范围边界。
- [`data/script-runtime-budget-candidate.json`](data/script-runtime-budget-candidate.json)：
  script heap、JS VM stack、fuel、deadline 联合候选及 runtime 证据边界。
- [`phase-0-gate-review.md`](phase-0-gate-review.md)：Phase 0 退出条件、阻塞项及
  关闭证据的审计总账（In Review）。
- [`design-review-readiness.md`](design-review-readiness.md)：五份必需设计从
  Draft 进入 In Review 的结构证据、开放阻塞项和防误报约束（In Review）。
- [`adr-review-readiness.md`](adr-review-readiness.md)：十四个有效 Proposed ADR 的
  评审问题、剩余 acceptance evidence 和防止自动接受的机器清单（In Review）。
- [`upstream-sync.md`](upstream-sync.md)：DIE-engine subtree 和组件锁定策略（Accepted）。
- [`phase8-gui.md`](phase8-gui.md)：Phase 8 GUI 设计文档，Tauri v2 实现
  功能对齐上游 `die` 完整 GUI 的 `die-gui` 程序，含 IPC 架构、功能规格
  （7A 核心 + 7B 高级 + 7C 扩展）、测试策略和实现顺序（Accepted）。
- [`phase11-gui-parity.md`](phase11-gui-parity.md)：Phase 11 GUI 深度对齐
  设计，FileInfo 完整头部解析与 PE/ELF/Mach-O 专用视图（Complete）。
- [`phase13-cli-parity.md`](phase13-cli-parity.md)：Phase 13 diec CLI
  100% 上游对齐设计（In Progress 对应实现）。
- [`phase17-gui-parity.md`](phase17-gui-parity.md)：Phase 17 GUI 差距 v4
  补齐设计，demangle 20 模式、归档列表复用引擎接口、哈希算法扩展、
  DEX 深视图、交互细节与 NFD/Unpacker/InfoDB ADR 决策项（Implemented）。
- [`phase18-deferred-parity.md`](phase18-deferred-parity.md)：Phase 18+
  遗留差距路线规划 — demangle 剩余 8 模式、CAB/ISO9660、模糊哈希/
  裸压缩流/反汇编架构评估，以及 InfoDB/静态脱壳/NFD 的 Gate 条件
  （Draft）。
- [`decisions/`](decisions/)：重大决策的 ADR。

设计文档必须链接所依据的 `docs/research/` 文档。被后续设计取代时保留历史内容并将状态改为 `Superseded`，同时链接替代文档或 ADR。
