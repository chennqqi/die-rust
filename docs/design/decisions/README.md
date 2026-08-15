# Architecture Decision Records

使用顺序编号，例如 `0001-rule-runtime-strategy.md`。每份 ADR 至少包含：

- Status
- Context
- Decision
- Alternatives considered
- Consequences
- Evidence

已接受的 ADR 不直接改写历史；需要改变决策时新增 ADR，并将旧 ADR 标记为 `Superseded`。

当前 ADR：

- [`0001-c-abi-opaque-ownership.md`](0001-c-abi-opaque-ownership.md)：
  C ABI 不透明句柄、配对释放、one-shot 与 reusable scanner（Proposed）。
- [`0002-layered-workspace.md`](0002-layered-workspace.md)：
  向内依赖 workspace、ports/adapters 与有界嵌套队列（Proposed）。
- [`0003-dual-output-contract.md`](0003-dual-output-contract.md)：
  分离上游兼容输出与 canonical API/CLI 输出（Proposed）。
- [`0004-evidence-bound-difference-waivers.md`](0004-evidence-bound-difference-waivers.md)：
  默认拒绝、精确 fingerprint 且有期限的兼容差异 waiver（Proposed）。
- [`0005-deterministic-text-classification.md`](0005-deterministic-text-classification.md)：
  显式初始化文本事实，不复制 `Binary_Script` 的未初始化状态（Proposed）。
- [`0006-rquickjs-rule-runtime.md`](0006-rquickjs-rule-runtime.md)：
  以私有 rquickjs/QuickJS-NG backend 作为首个规则运行时，保留严格兼容层、
  资源和 static-link 门禁（Proposed）。
- [`0007-rust-toolchain-baseline.md`](0007-rust-toolchain-baseline.md)：
  历史上固定 Rust 1.88 作为默认工具链与显式 MSRV；默认工具链部分已被 ADR
  0011 取代，MSRV 仍为 1.88（Superseded）。
- [`0008-pinned-rule-order-manifest.md`](0008-pinned-rule-order-manifest.md)：
  不在 Rust runtime 复刻非传递 comparator，以 source/target/oracle 绑定的显式
  顺序清单驱动 legacy 规则执行（Proposed）。
- [`0009-cancellation-result-contract.md`](0009-cancellation-result-contract.md)：
  modern API 用类型化取消代替上游部分成功结果，legacy 保留原始证据（Proposed）。
- [`0010-bounded-include-graph.md`](0010-bounded-include-graph.md)：
  静态 include 图与运行时 active stack 有界，循环作为安全偏差提前失败（Proposed）。
- [`0011-rust-1.97.1-default-toolchain.md`](0011-rust-1.97.1-default-toolchain.md)：
  默认/发布工具链固定升级到 Rust 1.97.1，同时保持 MSRV 1.88 和双版本 CI
  （Proposed）。
- [`0012-bounded-nested-scan-budget.md`](0012-bounded-nested-scan-budget.md)：
  嵌套扫描共享有限 depth/entry/read/expanded/node/deadline 预算；legacy 高资源
  profile 仍不允许无界（Proposed）。
- [`0013-fail-closed-incomplete-input.md`](0013-fail-closed-incomplete-input.md)：
  short read、I/O/seek 失败与非法 subdevice 范围必须类型化失败，不复制上游
  未初始化尾部或 slice 外读取（Proposed）。
- [`0014-bounded-path-expansion.md`](0014-bounded-path-expansion.md)：
  safe canonical 不跟随枚举 link；legacy alias 仍受 cycle、TOCTOU recheck 与
  hard budget 约束（Proposed）。
- [`0015-benchmark-cache-state-model.md`](0015-benchmark-cache-state-model.md)：
  显式区分 warm、file-content-nonresident-metadata-warm 与 dedicated
  system-cold，永久禁止含混的 cold 标签（Proposed）。
- [`0016-runtime-reuse-across-files.md`](0016-runtime-reuse-across-files.md)：
  同一 file_type 的规则运行时跨文件复用，以 persistent state audit 和
  差分验证约束复用安全性（Accepted, 2026-08-04）。
- [`0017-scan-service-layer.md`](0017-scan-service-layer.md)：
  died (diec-server crate) HTTP/JSON 扫描服务层，支持本地路径和远程内容双模式，
  常驻进程避免重复 database load（Accepted, 2026-08-04）。
- [`0018-tauri-gui-framework.md`](0018-tauri-gui-framework.md)：
  Tauri v2 作为 diec-rust GUI 框架，新增 `die-gui` crate 作为薄适配层，
  Web 前端 + Rust 后端直接调用 `diec-engine`（Accepted, 2026-08-05）。
- [`0019-defer-gui-auto-update.md`](0019-defer-gui-auto-update.md)：
  将 tauri-plugin-updater 自动更新功能 deferred 到 Phase 8 之后，
  理由：属于发布基础设施而非核心 GUI 功能，需签名密钥管理（Accepted, 2026-08-06）。
- [`0027-result-deduplication.md`](0027-result-deduplication.md)：
  `--alltypes` 模式默认结果层去重，去重键排除 `file_type`，
  `--no-dedup` / `DIEC_SCAN_FLAG_NO_DEDUP=0x40` 可关闭以匹配上游行为
  （Accepted, 2026-08-08）。
- [`0028-r-semantic-alignment.md`](0028-r-semantic-alignment.md)：
  `-r`/`--recursivescan` 语义对齐上游（文件内部 resource/overlay 递归），
  目录递归迁移到新选项 `--recursive-dir`/`-R`，破坏性变更
  （Accepted, 2026-08-15）。
- [`0029-rars-rar-library.md`](0029-rars-rar-library.md)：
  选用 `rars`（WTFPL）纯 Rust RAR 解包库，避免上游 XArchive UnRAR 源码
  翻译的许可证问题，WTFPL 兼容 MIT（Accepted, 2026-08-15）。
- [`0030-archive-extraction-safety-bounds.md`](0030-archive-extraction-safety-bounds.md)：
  archive 成员解包安全边界：单成员 128 MiB、总解压 512 MiB、压缩比 100:1、
  成员数 20/100000、递归深度 32，比上游更严格的安全改进
  （Accepted, 2026-08-15）。
