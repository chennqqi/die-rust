# ADR 0002：采用向内依赖的分层 workspace

Status: Accepted
Last updated: 2026-07-31
## Context

diec-rust 需要同时承载不可信二进制解析、上游规则 runtime、嵌套扫描、CLI 和稳定
C ABI。上游实现的模块关系、Qt/C++ 依赖和全局状态不适合直接翻译；同时，规则需要
查询格式事实，容易形成 `rules <-> formats` 循环。嵌套对象若直接递归调用扫描入口，
也难以统一限制深度、累计解压、取消和确定性顺序。

证据与完整边界见 [`architecture.md`](../architecture.md)。

## Decision

Proposed：采用 `diec-core`、`diec-formats`、`diec-rules`、`diec-engine`、
`diec-output`、`diec-cli` 和 `diec-ffi` 的向内依赖 workspace。

- core 提供 checked input、基础模型、预算、取消和结果 arena。
- formats 与 rules 仅依赖 core，彼此不依赖。
- rules 定义 `RuleRuntime`/`HostApi` ports；engine 使用格式事实实现 host adapter。
- engine 是唯一扫描编排层，并用显式、有界 work queue 处理嵌套对象。
- output 只依赖 core model；CLI/FFI 是 engine/output 的薄适配层。
- xtask、oracle、corpus 和上游树不进入 runtime dependency graph。
- native/unsafe runtime 仅允许存在于选定 backend 的最小私有边界。

依赖方向和禁止边必须由 CI 机器验证。反转边、跨层调用检测逻辑或让 adapter 拥有
独立扫描实现均视为架构变更。

## Alternatives considered

### 单一 crate

初期文件少，但第三方 runtime、parser、CLI 和 C pointer 边界会共享可见性，难以
阻止格式解析调用输出或 FFI 类型泄漏到核心。模糊边界也降低 fuzz 和替换 runtime
的能力。

结论：拒绝。

### 每种格式一个 crate

隔离最强，但在格式边界尚未稳定时产生大量 crate、feature 和版本管理成本，也可能
迫使共享解析工具上移到错误层级。

结论：初始不采用；有独立依赖或编译证据时再拆分。

### 按上游 C++/Qt 类层次直接翻译

可机械对应源码，但会继承重依赖、共享状态和展示/检测耦合，不能达到可移植静态库
目标。

结论：拒绝；兼容可观察行为而非内部结构。

### rules 直接依赖 formats

实现 host API 简单，但 rules 会绑定具体 parser，engine 也需要 rules，从而形成
循环或迫使编排逻辑下沉。

结论：拒绝；由 rules 定义 port、engine 实现 adapter。

### runtime/plugin-first 动态架构

动态加载便于替换引擎或格式插件，但会提前冻结 plugin ABI、扩大不可信边界，并使
static link、许可证和部署更复杂。

结论：当前范围拒绝；runtime 是 crate 内 backend，不是公共插件。

### 调用栈递归处理嵌套对象

代码直观且接近部分上游路径，但难以实施全局累计预算、取消、公平调度和确定性并行，
恶意输入还可耗尽栈。

结论：拒绝；使用显式 work queue。

## Consequences

正面：

- CLI、FFI 和未来 GUI 共享单一检测实现与结果。
- 格式 parser、规则 runtime 和编排可以独立 fuzz、mock 和替换。
- checked input、全局预算和结果确定性成为横跨能力的统一约束。
- native/unsafe 依赖不会污染纯 Rust 核心或公共 ABI。
- 显式 queue 支持有界嵌套、取消及未来确定性并行。

代价：

- 需要设计 ports 和 adapter，早期代码量高于单 crate。
- `diec-core` 的准入需要持续评审，防止成为公共杂物箱。
- rule host adapter 可能产生一定转换成本，需要 benchmark 后优化。
- workspace 的版本、feature 和依赖策略需要 CI 工具维护。
- 在 `api.md` 冻结结果模型前，core 与 output 的边界仍可能调整。

## Evidence

- [`source-analysis.md`](../../research/source-analysis.md)
- [`rule-compatibility.md`](../../research/rule-compatibility.md)
- [`nested-scan-behavior.md`](../../research/nested-scan-behavior.md)
- [`rule-runtime-spike.md`](../../research/rule-runtime-spike.md)
- [`rquickjs-rule-runtime-spike.md`](../../research/rquickjs-rule-runtime-spike.md)
- [`c-static-link-spike.md`](../../research/c-static-link-spike.md)
- [`c-abi.md`](../c-abi.md)

## Decision acceptance

Phase 0 评审确认以下决策方向：

- 向内依赖 workspace、ports/adapters 和统一 engine/result 路径；
- CLI 和 FFI 是核心库的薄适配层，核心层不依赖它们或 GUI 框架；
- architecture.md 已定义 Cargo workspace、模块职责、依赖方向和数据流。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- CI 能从 Cargo metadata 验证允许依赖和禁止边。
- 最小纵切片证明 CLI/FFI 共用 engine/result/output。
- nested queue spike 覆盖累计预算、取消、深度和稳定 merge。
- 独立 ADR 选定规则 runtime，并通过完整规则、host API 和 static-link 门禁。
- 没有 workspace 循环、生产依赖指向 xtask/tests/upstream tree，或公共类型泄漏第三方
  runtime。
