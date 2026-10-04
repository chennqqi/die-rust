# ADR 0006：以 rquickjs/QuickJS-NG 作为首个规则运行时后端

Status: Accepted
Last updated: 2026-07-31
## Context

固定规则集包含 2235 个 `.sg`/无扩展名程序，依赖 sloppy JavaScript、共享
global/type 生命周期、跨规则状态、include、Qt QObject 参数转换和大量格式宿主
API。规则必须保持原始字节；不能通过手工修改上游数据库来适配现代 ECMAScript
引擎。

Boa 0.21.1 与 rquickjs 0.12.1 都拒绝 Qt 5 接受的 Nintendo legacy 规则，也都
不能未经适配就等价替代 Qt Script。两者的工程能力存在决定性差别：

- Boa 的公开接口未提供 heap byte limit 或外部 token 驱动的 VM interrupt；
- rquickjs 已验证 interrupt、heap/stack limit 后同 context 恢复、跨线程
  cancel、VM/native deadline、合作式 native HostApi 取消，以及 native callback
  panic 在 C ABI 内捕获并于 Rust eval 边界恢复；
- 候选 custom allocator 已在 Windows 完整 Binary 语料上执行 live-heap 硬限制、
  瞬时 high-water 观测和 runtime drop 后归零；
- rquickjs 的精确、等长、source-pinned compatibility overlay 与 per-rule
  lexical wrapper 已让固定 292 条 Binary 顶层规则全部加载；
- 固定生命周期下 14 个生成 Binary header 样本已分别调用全部 292 个
  `detect`，合计 4088/4088 无异常、0 fallback，按固定 XScanEngine 结果优先级
  排序后的 type/name/version 与 Qt 5 达到 14/14；这些结果仍不是每条规则在其
  有效输入上的兼容率；
- rquickjs 使用 vendored QuickJS-NG C，而 Boa 为纯 Rust；native 边界增加构建、
  sanitizer 和安全审计成本。

新增 static-link spike 又证明 rquickjs/QuickJS-NG 可以进入 Rust `staticlib`，
并由 Windows MSVC `/MD`、MSVC `/MT` 和 Linux GNU 的真实 C11 消费者链接运行。
固定 lockfile 的保守许可证清单为 18 个 Cargo 包、当前 build tree 为 10 个，
rquickjs 与 vendored QuickJS-NG 均为 MIT。

需要在“等待不存在的零差异通用 JS 引擎”与“选定一个有明确兼容层和拒绝门禁的
后端”之间做出工程决策。选型不等于宣布规则兼容完成。

## Decision

Proposed：首个生产规则后端采用固定 `rquickjs@0.12.1`、
`default-features = false`、feature `std`，使用其 vendored
`rquickjs-sys@0.12.1` / QuickJS-NG。正式 lockfile 和供应链策略在 Phase 1
workspace 建立时重新生成并审计，不允许浮动到其他 minor/patch 后继续沿用本 ADR
的兼容结论。

后端边界：

- `die-rules` 暴露项目自有 `RuleRuntime`、`HostApi`、context facts 和 typed
  error；任何 rquickjs/QuickJS 类型不得进入 core、formats、engine、output、
  CLI、FFI 或公共 C ABI。
- native C/`unsafe` 只存在于 backend 私有模块及依赖内部；所有项目自写
  `unsafe` 都需逐处安全不变量、边界测试和 sanitizer。
- 每次 scan 使用与上游生命周期一致的共享 runtime/context，由一个确定 owner
  worker 使用；跨线程只传 cancel/deadline token，不移动 live JS handle。
- global init、type init、signature、普通规则和 include 的顺序来自固定 database
  snapshot，不按文件系统偶然顺序执行；上游非传递 comparator 的隔离与
  target-pinned order manifest 由 ADR 0008 约束。

兼容层：

- 上游规则文件保持 byte-identical，原始 path/commit/hash 永远是事实来源。
- 兼容 overlay 只能是 exact path/hash/length guarded、长度保持、位置固定的
  构建时转换；原始、转换后 hash 和 applied diagnostic 进入 database metadata。
- per-rule lexical wrapper 用于模拟固定 Qt evaluate 行为，但每次上游同步都必须
  重跑 persistent var/function dependency audit。发现任何 wrapper-loss candidate
  时拒绝数据库，而不是静默改变状态语义。
- 不允许用返回 `0`、空字符串或代理 detection 的 HostApi fallback 维持执行。
  未实现 receiver/method/arity 必须产生 typed incompatibility，并计入能力失败。
- Qt 5/Qt 6 已确认不同且影响可观察行为的转换必须由明确 compatibility profile
  或精确 waiver 表达，不能依赖 QuickJS 默认转换。

资源与恢复：

- 启用 VM interrupt、可观测且可执行 hard limit 的 heap allocator、stack limit
  和 wall-clock deadline；
- 所有 signature、parser bridge、decompression 及 native HostApi 长循环合作检查
  同一 cancel/deadline/budget；
- runtime exception、OOM/limit、panic 和 native fault 分开分类；只有 Rust
  unwind panic 可由 ABI 边界最后防护，native crash 不伪装成普通脚本错误；
- context 在 interrupt/exception 后只有通过明确恢复测试才能复用。
- script 资源使用同一个全 scan `ScriptBudget`，初始评审候选为：

  | Counter | Modern | LegacyHighResource |
  | --- | ---: | ---: |
  | live VM heap | 32 MiB | 256 MiB |
  | JS VM stack | 512 KiB | 2 MiB |
  | VM/native fuel quanta | 131,072 | 1,048,576 |
  | cumulative script deadline | 10 s | 60 s |

  heap 由固定 2,902,881-byte 全库程序集按 8×/64× 后向上取二次幂；stack
  相对 pinned QuickJS 256 KiB default 取 2×/8×；modern fuel 是固定 14-sample
  Binary corpus 的 20,947 个 detect/compare/search/include operation anchor
  乘 4 后向上取二次幂，legacy-high 再取 8×；deadline 分别是 30 s/120 s
  scan deadline 的 1/3 与 1/2。三轮 Windows MSVC full Binary corpus 每轮正常
  runtime 共观察 28 次 interrupt callback 和 16,439 次 Binary signature
  native checkpoint（compare 16,285、search 154），稳定投影相同；4095/4096
  候选边界与单次长搜索中断已有回归。4,130 个 lifecycle memory checkpoint
  最大观察 `malloc_size=654,562`、
  `memory_used_size=623,012`。operation anchor 不等于 VM instruction，也不能从
  单一 Binary corpus 的 poll/checkpoint count 推导跨格式 fuel；signature
  checkpoint 也不代表所有 HostApi 已覆盖，默认 allocator 的 memory checkpoint
  不是 eval 内瞬时 heap high-water。候选 `TrackingLimitAllocator` 已在相同
  14-sample/4088-detect oracle 上连续三轮记录 4,478,992-byte 最大瞬时
  high-water，32 MiB limit 下 0 次拒绝，42/42 runtime drop 后归零；稳定投影
  SHA-256 为
  `c455f6932322ff8161a4f6c9288710b5ed792ff5486b4459e11ef27e794e45c4`。
  计费单位是 pinned `RustAllocator` 的实际 `Layout` bytes（对齐 payload 加
  internal header），不是只计 `usable_size()`。
  固定 `db`/`db_extra` 的全部 2,235 个程序文件又在同一 custom-allocator
  runtime 内完成三轮隔离顶层 parse/eval，稳定 high-water 为 3,486,384 bytes、
  0 次拒绝且 drop 后归零；该实验没有调用 `detect` 或复刻各 file type
  lifecycle。逐规则独立 runtime 复验又固定 p50/p95/p99
  118,752/127,776/153,648 bytes，最大 3,489,576 bytes 来自
  `Binary/audio.1.sg`，全部 2,235 个 runtime 零拒绝并在 drop 后归零。
  30-scope shared-runtime 顶层 lifecycle 又动态验证 2,205 个 scoped programs、
  151 次 include 和最大 depth 2；scope heap 最大 4,468,192 bytes，全部零拒绝
  并释放归零。该实验使用显式诊断规则序，不作为上游顺序或 `detect` 证明。
  这仍只是 Windows 候选 allocator 证据，不是 production backend 或跨平台证明。
  另有 PE/ELF/Mach-O/DEX/APK/Archive/PDF 七条代表性规则的
  25-case 矩阵连续三轮固定为每轮 25 次 poll、75 个 lifecycle memory
  checkpoint，最大 `malloc_size=124,485`；同一矩阵的 custom allocator
  三轮最大瞬时 high-water 为 134,792 bytes，0 次拒绝且 75/75 runtime drop
  后归零。但这不是所有格式/规则的 scaling，因此这些数字仍保持
  `review_candidate_not_admitted`。
- fuel quantum 是 pinned backend 的 VM interrupt poll 或 native cooperative
  checkpoint，共享单调 counter，rule/include/child 不重置；runtime 升级必须
  重新定标。script deadline 是首次 runtime work 起算的 absolute deadline，并
  与 scan deadline 取较早者。rquickjs 的 `set_memory_limit()` 在 custom
  allocator 下是 no-op；若采用候选 `TrackingLimitAllocator`，hard limit 必须
  由 wrapper 自身执行，并在 sanitizer、Windows/Linux/macOS 与 production
  lifecycle acceptance 完成前保持未准入。

构建与发布：

- Windows 至少保留匹配的 `/MD` 与 `+crt-static`/`/MT` matrix；
- Unix `.a` 必须随发布记录 rustc `native-static-libs` 和最终动态依赖，不宣称
  fully-static；
- rquickjs 与 QuickJS-NG 许可证、Cargo 闭包、vendored source identity、
  advisory 和 SBOM 每次升级重新审计；
- macOS、Linux musl 和 arm64 未验证前不能升级为受支持 runtime target。

## Alternatives considered

### Boa 0.21.1

优点是纯 Rust。代价是当前 Windows 闭包和最小二进制显著更大，且缺少 runtime
决策所需的外部 interrupt 与 heap byte limit；同样存在 Nintendo 和 shared
lexical 不兼容。

结论：不作为首个后端。保留未来重新评估的可能，但不为抽象上的“双后端”同时
承担实现成本。

### 继续使用上游 Qt Script/QJSEngine

最接近上游语义，但保留 Qt/C++ 大型依赖、跨版本差异、native ABI 和静态链接
负担，违背重写目标。

结论：只作为固定 oracle，不进入产品 runtime。

### 自行实现 JavaScript 子集或把规则翻译成 Rust

可以控制资源和类型，却需要复制完整 sloppy/Qt 语义、动态 include、共享状态及
宿主转换；生成实现也很难证明与原始规则同步。

结论：拒绝。原样规则加受审计 runtime adapter 的证据链更清晰。

### 同时正式支持 Boa 和 rquickjs

看似降低供应商锁定，但会把每个规则、HostApi、取消、错误和平台矩阵翻倍，且两个
后端当前都不兼容，不能通过取交集得到正确语义。

结论：拒绝首版双后端。保留项目自有 port，使未来替换不污染公共层。

### 动态加载 QuickJS/plugin ABI

可单独更新 runtime，但扩大 ABI、安全、部署和许可证面，也破坏静态库优先目标。

结论：拒绝；backend 静态编译且为 crate 私有实现。

## Consequences

正面：

- Phase 1 可以按一个具体 runtime 的线程、资源和构建模型建立 workspace；
- interrupt、heap/stack limit、deadline 和 native callback panic recovery
  已有可执行原型，不必设计不可实现的资源契约；
- Windows/Linux C static-link 可行性和系统依赖有真实证据；
- 公共架构仍通过项目自有 port 隔离 native backend。

代价：

- 正式构建需要 C compiler，跨平台 CI 必须覆盖 vendored native code；
- QuickJS-NG 的 unsafe/native fault 需要 sanitizer、fuzz 和供应链审计；
- compatibility overlay 与 lexical wrapper 是长期维护面；
- staticlib 产物和最终 C executable 明显大于不含 JS runtime 的通用 ABI spike；
- 其他格式/file-part 的完整 HostApi 和逐规则有效分支 differential 未完成前，
  不能声称规则兼容。

## Evidence

- [`rule-runtime-spike.md`](../../research/rule-runtime-spike.md)
- [`rquickjs-rule-runtime-spike.md`](../../research/rquickjs-rule-runtime-spike.md)
- [`rquickjs-static-link.md`](../../research/rquickjs-static-link.md)
- [`rquickjs-static-link.json`](../../research/data/rquickjs-static-link.json)
- [`rule-compatibility.md`](../../research/rule-compatibility.md)
- [`binary-rule-lifecycle.md`](../../research/binary-rule-lifecycle.md)
- [`script-scope-semantics.md`](../../research/script-scope-semantics.md)
- [`script-state-semantics.md`](../../research/script-state-semantics.md)
- [`host-api-inventory.md`](../../research/host-api-inventory.md)
- [`global-host-api-runtime-differential.md`](../../research/global-host-api-runtime-differential.md)
- [`format-host-api-runtime-differential.md`](../../research/format-host-api-runtime-differential.md)
- [`signature-language.md`](../../research/signature-language.md)
- [`pe-rule-runtime-differential.md`](../../research/pe-rule-runtime-differential.md)
- [`elf-rule-runtime-differential.md`](../../research/elf-rule-runtime-differential.md)
- [`macho-rule-runtime-differential.md`](../../research/macho-rule-runtime-differential.md)
- [`dex-rule-runtime-differential.md`](../../research/dex-rule-runtime-differential.md)
- [`apk-rule-runtime-differential.md`](../../research/apk-rule-runtime-differential.md)
- [`archive-rule-runtime-differential.md`](../../research/archive-rule-runtime-differential.md)
- [`pdf-rule-runtime-differential.md`](../../research/pdf-rule-runtime-differential.md)
- [`c-static-link-spike.md`](../../research/c-static-link-spike.md)
- [`script-runtime-budget-candidate.json`](../data/script-runtime-budget-candidate.json)
- [`test_script_runtime_budget.py`](../../../tools/tests/test_script_runtime_budget.py)

## Decision acceptance

Phase 0 评审确认以下决策方向：

- rquickjs/QuickJS-NG 作为首个私有 backend；
- heap/JS stack/fuel/deadline 已有联合候选；
- Binary VM poll/signature checkpoint 与七类 25-case 代表性格式矩阵均已三轮计量；
- 4095/4096 边界、单次中断已测。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- 固定 main/extra/custom 目标规则 100% discovered，并按真实 file type/layer/order
  load；所有 overlay 精确绑定 source identity，未知规则拒绝；
- 固定规则实际可达的 receiver/method/arity 100% 有 native adapter 或明确
  incompatibility，不存在 silent fallback；
- global/type init、include、跨规则 persistent state 和 error propagation 的
  Qt 5 oracle 差分通过；
- 代表性 PE、ELF、Mach-O、DEX/APK、Archive、PDF、Binary 规则各有
  positive/negative/truncated differential；剩余差异只有 ADR 0004 waiver；
- VM interrupt、native cooperative cancel、heap/stack/deadline、panic recovery
  和 context reuse 在正式 backend 测试通过；
- Windows x64、Linux x64 和 macOS 目标完成 static archive、C link/run、
  native dependency 与 sanitizer smoke；未承诺的平台明确标为 unsupported；
- runtime、vendored QuickJS-NG 和完整 feature-resolved 闭包通过发布许可证、
  SBOM 和安全审计。
