# ADR 0008：用固定顺序清单隔离上游非传递规则排序

Status: Accepted
Last updated: 2026-07-31
## Context

上游分别对 main、extra、custom 每层调用 `std::sort`，比较器
`sort_signature_prio()` 只有在比较双方文件名都包含至少两个点时才比较字符串
priority，否则比较完整名称。固定规则已经存在多个比较环；type `_init` 本身也能
与普通 priority 文件构成：

```text
DS.deep.2.sg < _init < z_normal.1.sg < DS.deep.2.sg
```

因此比较器不满足 strict weak ordering，C++ `std::sort` 的前置条件被破坏。Rust
不能安全、可移植地“复刻”这项未定义行为。无条件改成 `(priority, name)` 虽然
确定，却会改变固定 Linux oracle 的真实执行顺序；规则共享 runtime 状态、会覆盖
`detect` 并产生跨规则副作用，顺序差异可以改变 detection。

项目生成的隔离 fixture 证明：

- 不含 type `_init` 的列表按字符串 priority `1 → 2 → 4`，优先于文件名字典序；
- 加入真实 init 布局后，固定 qmake/CMake Linux Qt5 executable subsequence
  偏离纯 priority，但两个构建彼此一致；
- main、extra、custom 分别排序后 append，extra/custom 的 priority `"0"` 仍在
  main priority `"4"` 之后；
- 完整固定 Binary 规则的两个 Linux Qt5 oracle 又得到相同 292-rule 顺序。

Windows MSVC 与 macOS libc++ 尚无相同顺序证据，不能从 Linux 外推。

## Decision

Proposed：产品 runtime 不实现或调用上游非传递 comparator。规则同步/数据库构建
阶段生成带版本的 order manifest，immutable database snapshot 只消费已验证的
显式 execution ordinal。

每条 order entry 至少绑定：

- upstream DIE-engine commit；
- rules/database commit 与 database layer；
- file type、原始相对路径、basename 和原始字节 SHA-256；
- compatibility profile、target OS/architecture，以及产生顺序的 oracle identity；
- layer-local ordinal 和最终 main→extra→custom execution ordinal；
- global/type init 与 include 的首选记录身份。

加载规则时：

1. 原始规则字节保持不变，order manifest 是派生元数据，不改名、不格式化规则；
2. inventory 必须与 manifest 路径/hash 一一相等，缺失、重复、额外或 hash 漂移
   全部拒绝；
3. 同步 validator 对每个 layer/file type 构造比较关系并检测 strict-weak-order
   违反；发现环时记录最小 witness；
4. legacy compatibility profile 若存在比较环，必须选择与 upstream/rules/target
   精确匹配的 oracle order；没有清单时数据库状态为 incompatible，不回退到
   文件系统顺序、Rust stable sort 或 `(priority, name)`；
5. 无环列表仍由 validator 比较源码 comparator 的确定结果和 order manifest，
   防止生成器/Qt 字符串语义漂移；
6. runtime 只按 ordinal 遍历，并继续独立应用 file type、signature/path、
   deep/heuristic、database enable 和 cancel filters；
7. raw oracle order、规范化 order、source identity 和 comparator-cycle witness
   都进入兼容报告。

如果 Windows/macOS order 与 Linux 不同，初始 legacy profile 使用 target-specific
manifest；不得用一个“多数平台顺序”冒充逐平台兼容。是否另设跨平台统一 canonical
规则顺序，需要在检测差分和产品需求明确后新增 ADR，不能由 output renderer
重排结果来掩盖。

## Alternatives considered

### 直接翻译 C++ comparator 并调用 Rust sort

Rust 排序 API 同样要求一致的比较关系；非传递 comparator 可能 panic、产生版本
相关结果或在算法改变后漂移。即便某次恰好匹配 GCC，也不能证明 MSVC/libc++。

结论：拒绝。

### 修正为 `(file_type, priority, name)`

得到清晰总序，但固定 Linux fixture 已证明它与上游 init 布局的真实顺序不同。
规则执行有共享状态，不能把差异降级为表示层排序。

结论：不能用于 legacy compatibility；未来 canonical 模式需单独决策。

### 固定 Linux 顺序并用于所有平台

可重复，但在没有 Windows/macOS oracle 前属于无证据外推；若上游平台顺序不同，
就不满足逐平台可观察兼容。

结论：拒绝 blanket manifest。

### 运行时动态调用一个 C++ compatibility sorter

保留 native 依赖和未定义行为，结果仍随 STL/编译器变化，也违背纯 Rust核心与
可审计数据库 snapshot 方向。

结论：拒绝。

### 忽略执行顺序，只比较 detection 集合

上游规则共享 global/init/include 状态，已有跨规则隐式全局依赖；集合比较会隐藏
真实版本、info、错误和副作用差异。

结论：拒绝。

## Consequences

正面：

- runtime 遍历完全确定，不依赖 HashMap、目录枚举或排序算法；
- 上游非传递行为被限制在离线、可审计的 oracle 证据中；
- 上游规则仍保持 byte-identical；
- 同步时任何新增环、顺序或 source drift 都会显式失败；
- 差分报告可以把顺序差异定位到具体 layer/file type/path/hash。

代价：

- 每个受支持 target/profile 都需要可重复 upstream oracle；
- 上游同步必须重采 order manifest，不能只更新规则 hash；
- target-specific order 可能使相同输入在不同平台保持上游差异；
- 完整规则 order 清单增加发布物、SBOM/归属和 review 工作；
- 当前没有 Windows/macOS 证据，因此本 ADR 不能接受，也不能据此宣称三平台兼容。

## Evidence

- [`rule-orchestration.md`](../../research/rule-orchestration.md)
- [`rule-orchestration-linux-qt5.json`](../../research/data/rule-orchestration-linux-qt5.json)
- [`binary-rule-lifecycle.md`](../../research/binary-rule-lifecycle.md)
- [`binary-rule-order-linux-qt5.json`](../../research/data/binary-rule-order-linux-qt5.json)
- [`script-state-semantics.md`](../../research/script-state-semantics.md)
- [`rule-compatibility.md`](../../research/rule-compatibility.md)

## Decision acceptance

Phase 0 评审确认以下决策方向：

- 固定 order manifest 取代非传递 comparator；
- sync validator 从固定 source inventory 生成 comparator relation、cycle witness
  和 content-addressed order manifest；
- priority-only、type-init cycle、main/extra/custom append fixture 都有 golden。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- 完整目标规则按 file type/layer 100% 进入 manifest，无 missing/duplicate/hash
  mismatch；
- Windows x64 MSVC、Linux x64 GNU 和 macOS 目标分别采集固定 upstream order；
- 若平台顺序不同，target selection 和 unsupported behavior 有 system test；
- runtime/database snapshot 不包含上游 comparator，不依赖 filesystem iteration；
- 规则执行、init/include 和错误顺序的差分默认有序比较；
- `architecture.md`、`testing.md`、同步设计和发布兼容报告与本 ADR 一致。
