# 测试、差分与发布验证设计

Status: Accepted

Last updated: 2026-07-31

## 1. 状态与证据

本文定义 Phase 0 的测试设计评审稿，不表示当前兼容性已经得到证明。正式实现开始后，
测试工具和 manifest 可以演进，但不得削弱原始证据保存、默认拒绝差异、语料溯源、
资源安全和跨平台门禁。

依据：

- [`upstream-baseline.md`](../research/upstream-baseline.md) 与
  [`upstream-build-baseline.md`](../research/upstream-build-baseline.md)：
  固定上游、构建环境和 binary 证据；
- [`upstream-cmake-differential.md`](../research/upstream-cmake-differential.md)：
  qmake/CMake 双 oracle；
- [`behavior-baseline.md`](../research/behavior-baseline.md)：
  生成语料、原始输出哈希和扫描矩阵；
- [`cli-path-behavior.md`](../research/cli-path-behavior.md)、
  [`special-path-behavior.md`](../research/special-path-behavior.md)、
  [`path-filesystem-behavior.md`](../research/path-filesystem-behavior.md)、
  [`large-directory-behavior.md`](../research/large-directory-behavior.md)、
  [`path-toctou-behavior.md`](../research/path-toctou-behavior.md)、
  [`path-locale-filesystem-behavior.md`](../research/path-locale-filesystem-behavior.md)、
  [`cli-special-modes.md`](../research/cli-special-modes.md) 与
  [`database-error-behavior.md`](../research/database-error-behavior.md)：
  CLI、特殊模式和失败行为；
- [`nested-scan-behavior.md`](../research/nested-scan-behavior.md)：
  resource/overlay/archive harness；
- [`rule-orchestration.md`](../research/rule-orchestration.md)：
  priority/init/layer/mode/file-type/Unknown 编排基线；
- [`rule-compatibility.md`](../research/rule-compatibility.md)：
  规则语法、host API 和结果要求；
- [`c-static-link-spike.md`](../research/c-static-link-spike.md)：
  C static linking、生命周期和 panic 验证；
- [`architecture.md`](architecture.md)、[`api.md`](api.md) 和
  [`c-abi.md`](c-abi.md)：被验证的架构及契约。

已存在的 `tools/corpus/`、`tools/upstream/`、`tools/tests/` 和
`docs/research/data/*.json|toml` 是 Phase 0 基础设施，不等于完整测试覆盖。

## 2. 质量目标

测试必须分别证明：

1. **能力完整性**：能力矩阵中的每个承诺都有至少一个 positive 和必要的 negative
   case。
2. **上游兼容性**：固定输入、规则、选项和平台下，可观察结果达到声明的兼容级别。
3. **规则完整性**：固定规则集全部被发现、解析、加载和执行；unknown syntax 不会
   静默消失。
4. **内存与资源安全**：畸形输入不 panic、越界、无限循环或无界分配。
5. **确定性**：相同 case 重复执行和并行执行产生相同 canonical bytes。
6. **ABI 正确性**：layout、ownership、线程、panic 和语言绑定符合 C ABI。
7. **可移植性**：目标平台上构建、测试及可观察平台差异均有证据。
8. **性能可解释性**：优化和回归由稳定 benchmark/profiling 证明。

测试通过不能只表示“进程退出 0”。测试必须检查与该能力相关的结构、顺序、错误、
资源使用和 provenance。

## 3. 测试层级

| 层级 | 主要对象 | 典型断言 |
| --- | --- | --- |
| Unit | checked input、parser helper、budget、arena、排序 | 边界值、错误类型、不变量 |
| Property | offset/length、round-trip、排序、预算 | 任意输入满足代数/安全性质 |
| Format integration | 单个格式 module + fixture | probe、字段、截断、unsupported |
| Rule conformance | parser/runtime/HostApi | 全库覆盖、生命周期、函数与异常 |
| Engine integration | scan pipeline/work queue | tree、顺序、partial、取消、limits |
| Output golden | canonical/legacy renderer | schema、逐字节、escaping、稳定顺序 |
| CLI system | binary + database + filesystem | args、路径、stdout/stderr、exit |
| Differential | Rust 与固定 upstream oracle | raw 与 semantic report |
| FFI/language | staticlib + C/Go/Python | layout、ownership、thread、panic |
| Fuzz | parser/runtime host/engine/FFI | no crash、no hang、bounded allocation |
| Performance | database/scan/output/end-to-end | latency、throughput、peak RSS、size |

低层 fake 不能代替高层真实规则和真实 parser 的 system test。每个缺陷修复先增加能
失败的最小回归用例，再修复并将用例保留。

规则数据库/engine integration 必须保留
[`rule-orchestration-fixture.json`](../research/data/rule-orchestration-fixture.json)
的排序和编排关系：无 type init 的 `1 → 2 → 4` priority、同 priority 文件名
回退、字符串 priority `10 → 2`、缺失/空 priority 段回退、含 `_init` 的非传递
实际顺序、main→extra→custom layer append、main global/type/include 首选、
DS/EP/HEUR mode filter、PE decoy 排除和空数据库 Unknown。legacy 测试比较
execution order 与 detection 数组原顺序；只允许规范化 profiling elapsed，
不得按名称排序后比较。order manifest 的 source path/hash/target/oracle 任一漂移
都必须是 database incompatibility。

另用
[`database-layer-fixture.json`](../research/data/database-layer-fixture.json)
验证三层同名 `shared.5.sg` 不覆盖/不去重、3/6/6/9 materialized counts、
main→extra→custom record blocks，以及全量加载后四组 runtime gate。测试必须同时
比较 record provenance 和 detection 原顺序，不能只比较名称 multiset。

嵌套 engine integration 必须覆盖 context 传播而不只计数 child：项目生成的
RT_MANIFEST resource 在 recursive+aggressive 下应形成 offset 608、size 20、
`Binary / Resource` child，把 scan ID `"24"` 交给原样规则并得到
`format / Manifest / "" / Resources`；其他三种模式不得产生该 child。测试同时
保存 raw upstream stdout 与规范化树。另设负门禁保证 legacy-compatible 普通
扫描不因 PE parser 能枚举 debug-data 就自动调度它。

## 4. 能力追踪

能力矩阵为每个条目分配稳定 `CAP-*` 标识，例如：

```text
CAP-CLI-INPUT-SINGLE
CAP-CLI-PATH-DIRECTORY
CAP-FORMAT-PE32
CAP-RULE-HOST-READ-U32
CAP-NESTED-RESOURCE
CAP-ABI-C-LIFETIME
```

测试 case manifest 的 `capabilities` 是非空数组。CI 生成 traceability report：

- capability -> source evidence；
- capability -> Rust tests；
- capability -> oracle/differential cases；
- capability -> 支持平台；
- capability -> unresolved gaps/waivers。

`Observed` 能力没有 Rust case、或已承诺能力只在 mock 中覆盖时，Phase 对应门禁失败。
新增能力必须先更新矩阵和 case，再宣称支持。

Phase 0 的
[`capability-coverage.json`](../research/data/capability-coverage.json)
把 68 个能力投影到四个平台的 272 个 cell，并显式区分 runtime、source-only、
corpus-missing 与 platform-missing。其未分类行/cell 均为 0，但 coverage complete
仍为 false；测试不得把“清单闭合”解释为“行为闭合”。

## 5. Case 身份与 manifest

每个可重复 case 使用稳定 ID，不依赖测试函数名：

```json
{
  "schema": 1,
  "id": "cli.scan.minimal-pdf.json.default",
  "capabilities": ["CAP-CLI-INPUT-SINGLE", "CAP-FORMAT-PDF"],
  "input": {
    "manifest": "baseline-corpus.json",
    "entry": "minimal.pdf",
    "sha256": "..."
  },
  "database": {
    "component": "Detect-It-Easy",
    "commit": "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
  },
  "upstream": {
    "commit": "74eaf505c250ab47e709024e9dc41657cd8f2254",
    "oracle": "cmake-qt5"
  },
  "args": ["--json", "{input}"],
  "environment": {"LC_ALL": "C", "TZ": "UTC"},
  "expected_profile": "Exact"
}
```

manifest 规则：

- ID 全局唯一且一旦发布不复用；语义变化创建新 ID/version。
- input、database、binary、container/Dockerfile 和 generator 都用 SHA-256 或
  commit 标识。
- argv 是数组，不保存 shell command string。
- cwd、locale、timezone、platform、architecture 和 path mapping 显式记录。
- 未列入 allowlist 的环境变量不传入 oracle。
- case 不引用开发者绝对路径、当前时间或“latest”。
- manifest schema 有 JSON Schema 和拒绝未知字段的 validator。

测试开始前验证全部 identity；不匹配时是 infrastructure failure，不能运行后再把
新输出当作 baseline。

## 6. 语料分类与来源

语料分为：

### Tier A：项目生成

首选。生成器只用代码内常量或已验证 Tier A 输入，写出 deterministic manifest。
现有 baseline、path、path-filesystem、large-path、path-toctou、database 和
nested generators 属于该层。测试要求：

- 两次生成逐字节相同；
- 目录无额外文件、symlink 或 path escape；
- 每个文件 size/SHA-256 与版本化 manifest 一致；
- generator 自身 hash/version 进入运行报告。

### Tier B：可公开再分发的良性语料

只在生成器无法表达真实格式边界时使用。每个样本记录来源 URL、下载日期、上游
版本、许可证、归属、原始/仓库 hash 和最小化过程。导入前完成许可证评审。

### Tier C：隔离/受限语料

恶意、客户、来源不明或不可再分发样本不提交到 Git。隔离系统只保存 hash inventory
和访问策略，CI 使用受控 runner，artifact 禁止上传原始 bytes。测试报告用 opaque
sample ID 和 hash，不含客户/本机路径。

任意 fuzz crash 如含第三方字节，先最小化并完成来源审查；不能合法提交时保存
生成 recipe 或受限 hash。

## 7. 上游 oracle

primary oracle 固定为官方 CMake 路径构建的 upstream CLI；qmake oracle 用于发现
构建系统/Qt 差异。两者都必须固定：

- DIE-engine commit 和全部 gitlinks；
- Detect-It-Easy rules commit；
- base image digest、Dockerfile hash、工具链/包 inventory；
- binary hash、link metadata 和启动命令。

“官方 CMake”仍不足以唯一标识 oracle：固定 Qt 5/Qt 6 初始差分已证明同一
upstream/rules/platform/input 可产生 runtime-specific `ReferenceError` 文本，
Qt 6 还可额外写 stderr。identity 因此必须另含 Qt major/minor、script runtime
backend 和构建 profile。当前 Linux Qt 5 CMake profile 是 primary，Qt 6 CMake
作为独立 conformance profile；不得把两者合并成一个可互换的 expected namespace。
证据见
[`../research/upstream-qt6-differential.md`](../research/upstream-qt6-differential.md)。

global HostApi differential 还必须比较函数 surface、缺参 error、signal/副作用和
返回值。固定 harness 已证明 Qt 5 的 `"undefined"` 宽松转换与 Qt 6 的
`Insufficient arguments` 严格拒绝不同，不能由“参数类型相同”或最终 detection
相同替代。见
[`../research/global-host-api-runtime-differential.md`](../research/global-host-api-runtime-differential.md)。

现有 `compare_cli_oracles.py` 在 Phase 1 扩展为可比较 upstream 与 Rust binary，
但不得让 Rust 进程参与生成 upstream expected 值。archive-only engine 能力继续
使用固定 harness；harness 源码/binary hash 是 case identity 的组成部分，并与发布
CLI 做无 archive flag 的等价自检。

oracle image 只读挂载语料，禁用网络，设置 CPU/memory/pid/time limits。每个 case
在独立临时目录执行；timeout 后终止整个 process tree。oracle crash、timeout 或
identity mismatch 是 `ORACLE_ERROR`，不是 Rust pass。

规则 signature 使用组件级 XBinary oracle，不能只看最终 CLI detection。每个向量
同时固定 source pattern、规范化结果、parse validity、record sequence、输入 bytes、
初始 offset、file type/memory map、返回值/最终 offset 或错误。至少覆盖 literal、
quoted Latin-1、wildcard、五类 byte predicate、bounded find、relative offset、
absolute address、奇数 token、未闭合 quote、无效后缀和所有 bounds。header
signature fast path 与通用 matcher 分开跑同一向量，覆盖严格边界、负 offset
的 Qt 5 `QString::mid` clamp 和无效后缀；差异不得被规范化隐藏。未知语法诊断
只适用于实际进入 generic parser 的路径，不能覆盖 header string matcher 的
上游 false 结果。`findSignature`、`fSig` 和 `isSignaturePresent` 还需共享同一
搜索向量，比较超长范围裁剪、`size == -1`、未找到 offset 与布尔投影，防止三个
adapter 漂移。overlay context 向量必须正交组合当前 file-part 与当前 parser
内部 nested overlay，分别比较 `isOverlay`、offset、size 和 presence，禁止用
单一 `has_overlay` 标志代替。动态
317-pattern 清单只证明一个固定样本的已执行路径，不替代全调用点 inventory。
`compareSignature` 与 `find_signature` 必须作为两个 operation 比较；固定 oracle
已证明 record/SigByte class table 和 search anchor 会产生不同结果，禁止用一侧
结果推断另一侧。
合成 memory-map 向量用于隔离 matcher 的地址、端序和 file-type 分支；另用项目
生成的最小真实格式文件验证各 parser 的 `getMemoryMap`，两层证据不能互相替代。

升级上游时创建新的 baseline namespace；旧 baseline 不就地覆盖。先运行
upstream-old vs upstream-new 报告，再决定 Rust compatibility target。

## 8. 原始执行记录

每次 system/differential 执行保存：

- run/case/schema version；
- source、rules、binary、container 和 generator identities；
- platform、architecture、toolchain、locale/timezone；
- argv、受控 environment 和逻辑 cwd；
- exit reason/code、signal/exception、timeout 和 wall duration；
- stdout/stderr 原始 bytes 的 SHA-256、length 和 artifact reference；
- parsed output 或 parse failure；
- peak RSS/commit、CPU time 和预算计数（可获得时）；
- harness/tool version。

stdout/stderr 是 byte stream，不先 decode；小型基线可以直接保存，较大内容使用
content-addressed artifact。报告时间戳不参与 equality。任何 sanitizer/runtime
日志都作为独立 stream，不能混入程序 stdout。

Phase 0 v1 以
[`raw-execution-v1.schema.json`](schemas/raw-execution-v1.schema.json)
冻结最小 execution evidence，并由
[`verify_raw_execution.py`](../../tools/compat/verify_raw_execution.py)
按
[`raw-execution-verification-v1.schema.json`](schemas/raw-execution-verification-v1.schema.json)
产生审计。manifest 固定 side/platform/profile/producer revision/case manifest/
executable、argv/environment/logical cwd、四类 termination、wall time，以及
显式 nullable CPU/peak-memory、命名 budget counters，及 stdout/stderr（必需）
和 runtime log（可选）的 digest/size。环境变量名保留平台原始拼写，只拒绝 NUL/
`=`。artifact path 不进入 manifest，而由显式 root 下的 `sha256/<digest>` 唯一派生。

验证器在解析 artifact 前先检查总 declared bytes，随后有界流式读取；拒绝
symlink/reparse/non-regular、缺失、size/hash mismatch 和读取期间身份变化，并在
输出前重新有界读取 manifest。manifest、raw bytes 和 audit 的 SHA-256 均保留；
audit 只表示该单份 execution evidence 通过，不等于 differential pass。

固定上游证据同时存在 profiling/messages 位于 JSON 前，以及 rule error 位于 JSON
后的两类 framing。Phase 0 v1
[`project_raw_framing.py`](../../tools/compat/project_raw_framing.py)
先执行上述全 execution rehash，再二次稳定读取 stdout，并按
[`raw-framing-projection-v1.schema.json`](schemas/raw-framing-projection-v1.schema.json)
投影为覆盖全部 bytes 的连续有序 ranges。只把 stream/LF 行首的完整 object/array、
严格 UTF-8、无 duplicate key/非有限数的候选标为 `json_document`；prefix、
separator、invalid candidate 和 trailing diagnostic 都保留为 `raw` range。
每段保留 offset/size/raw hash，JSON 另保留 parsed value/canonical hash，整个
segment sequence 再取 hash。`documents_found`/`no_json_document` 仅描述 framing，
不得当作 differential pass/empty success。证据见
[`../research/cli-option-behavior.md`](../research/cli-option-behavior.md) 和
[`../research/database-error-behavior.md`](../research/database-error-behavior.md)。
扫描位置只能单调前进：balanced-invalid 整段保留 raw、mismatch 从冲突后继续、
unterminated 消费至 EOF，不得从嵌套 opener 重试形成二次复杂度。
单 document 最大 8 MiB、JSON document 最多 4096、nesting 最大 256；触发时未投影
部分仍归入 raw range，并输出 `projection_limit_reached` 与有序原因，不得继续解析
成部分 semantic success。

CI 失败报告默认显示结构化 diff 和有限上下文，不把受限语料、全部二进制或巨量
输出写入日志。

## 9. 差分算法

差分按固定顺序执行：

1. 验证 case、输入、数据库和 oracle identity。
2. 在等价隔离环境运行 upstream，保存 raw record。
3. 运行 Rust，保存 raw record。
4. 比较 termination：exit/signal/timeout。
5. 对 legacy profile 逐字节比较 stdout 和 stderr。
6. 独立解析两侧已声明格式及 framing；parse failure 和 trailing records 本身是结果。
7. 投影为 versioned semantic model。
8. 按字段、数组顺序和 tree relation 比较，先生成完整有序差异。
9. 应用精确 waiver，生成 applied/unmatched/stale 清单。
10. 输出 machine-readable report，保留两侧 raw hashes。

semantic model 至少比较：

- 根类型、format candidates 和 all-types 顺序；
- detection 的 type/name/version/info/display、heuristic/unknown；
- rule identity/priority（上游能观察时）；
- parent/child、file-part、offset、size 和 child order；
- script/parser/database errors 的类型、位置、规则和顺序；
- handlers/debug/profiling（启用相应模式时）；
- entropy/info/struct 的字段、数值和顺序；
- CLI path expansion、filename prefix、stdout/stderr 与 exit；
- stdout 中首个结构化 document 的边界、前后诊断记录及其顺序；
- completion/limit/cancel metadata。

数组默认有序比较。只有源码或实验明确证明集合语义的字段才可先按冻结 key 排序。
不能用“排序后相同”隐藏上游优先级差异。

## 10. 规范化

原始记录永不修改；规范化产生新的派生 artifact，并记录 normalizer 名称、版本和
输入/输出 hash。

允许候选仅包括：

- 已证明无语义的固定临时根目录替换为 token；
- 明确标为 non-canonical 的 wall-clock/profile timing；
- 平台 oracle 已证明不同但等价的 path separator/line ending；
- 上游生成且无业务语义的地址或随机标识；当前只批准 format HostApi semantic
  harness 的 QObject error message，把精确匹配
  `ClassName(0x[0-9a-fA-F]+)` 的地址替换为 `ClassName(<address>)`，raw
  execution 仍必须保留。

禁止规范化：

- detection/tree/array 顺序；
- rule 字符串、拼写、大小写或空白；
- offset、size、file-part、parent relation；
- unknown、error、exit code 或 missing field；
- 浮点精度，除非专项实验冻结 tolerance；
- 把 crash、timeout、invalid JSON 或 unsupported 转成空成功。
- 丢弃完整 JSON document 前后的 stdout records，或只比较已解析 JSON。

normalizer 的每条变换有 unit/golden test。新增变换按兼容策略变更评审。

Phase 0 已实现严格的最小可执行子流水线
[`normalize_semantic_projection.py`](../../tools/compat/normalize_semantic_projection.py)，
对应版本化
[`semantic-projection-v1.schema.json`](schemas/semantic-projection-v1.schema.json)、
[`semantic-normalization-policy-v1.schema.json`](schemas/semantic-normalization-policy-v1.schema.json)
和
[`semantic-normalization-output-v1.schema.json`](schemas/semantic-normalization-output-v1.schema.json)。
policy 整体绑定精确 platform/oracle profile/upstream commit/semantic schema/case，
每条规则绑定相对 `semantic` 的单一 JSON Pointer、封闭 transform、精确替换次数、
规范化后的完整字符串以及 research/contract 文件。v1 只实现已有证据的
`qobject_address_v1` 和 `profiling_elapsed_ms_v1`；目标缺失、非字符串、身份漂移、
未知字段/transform、替换次数或周边文本变化全部按 infrastructure error 拒绝。
派生输出记录原始 input/policy bytes hash、canonical input/policy hash、每个目标的
前后 hash 和完整 normalized projection hash，并拒绝覆盖或运行中变化的输入。

`semantic-projection-v1` 只定义规范化 envelope，单独使用仍不等于完整 semantic model。
固定上游 CLI 的有类型 payload
由 [`semantic-result-v1.schema.json`](schemas/semantic-result-v1.schema.json)
定义，证据 inventory 见
[`cli-json-schema-inventory.md`](../research/cli-json-schema-inventory.md)。
完整 envelope 由
[`semantic-result-projection-v1.schema.json`](schemas/semantic-result-projection-v1.schema.json)
把该 payload 约束到 normalizer-compatible projection。
[`semantic-projection-contract-v1.schema.json`](schemas/semantic-projection-contract-v1.schema.json)
把一个 case 的 platform、oracle profile、目标 upstream commit、case manifest
hash、semantic schema、输出种类和预期 JSON document 数量冻结在投影之前。
这避免从 argv/JSON shape 猜 mode，也避免把 Rust producer commit 错当成双方共享的
upstream compatibility target。

Phase 0 reference projector
[`project_semantic_result.py`](../../tools/compat/project_semantic_result.py)
先重新验证 execution 的全部 content-addressed artifacts，再从同一 stdout 重建
lossless framing。v1 对 normal scan、递归 child node/detection、entropy、
info/struct 和 normal scan open-error 建立封闭 union；unknown field/shape、
document count mismatch 和 framing limit 都输出 `projection_failure`，不静默
忽略。raw stdout segments、stderr 和 runtime log 拆为有序 line records；
`comparison` 保存精确 UTF-8/base64 body 和 `none`/`lf`/`crlf`，关联的
`evidence.raw_streams` 保存绝对 offset/size/hash。这样 profiling/message 可由
normalizer 定点处理且仍可重建原 bytes。
comparison segment/record 与 evidence source-map 使用相同数组 ordinal；数量、
kind、range 连续性和 hash 由 projector 回归测试强制一致。
termination 和 producer identity 也进入 semantic payload。normal scan
同时保留 offset/size 的上游 decimal string 与严格 u64，Info/Struct object 转为
有序 entries，不能由 canonical object key 排序隐藏 formatter 顺序。
只有 `semantic.comparison` 的 output/termination/streams 进入两侧 semantic
equality；producer revision/executable 与 verification/framing/contract hashes
是同一 artifact 内的 provenance，不得因两侧来源天然不同而报告检测差异。

该 v1 闭合的是已观测 legacy CLI JSON/output surface，不等于 modern canonical
`ScanReport` 或全部 engine-only harness schema。rule identity/priority、
handlers/debug 等仅 engine 可观察字段仍须补 inventory 和 typed variant；未知
harness JSON 当前明确失败并保留 value。

Phase 0 reference comparator
[`compare_semantic_results.py`](../../tools/compat/compare_semantic_results.py)
已经闭合单 case 的 execution → framing → semantic projection → optional
normalization → comparison。它从两侧 raw manifest 重新构造全部派生 artifact，
不接受调用方提供的投影作为可信输入；只比较 `semantic.comparison`，但在报告中
保留两侧 producer/evidence/contract/policy hash。object key 按稳定顺序遍历，
array 保序，missing 与 JSON null 分离，bool 不等同数字，只有数值相等的有限
integer/float 表示视为相同。每项差异使用 `/comparison` 起始的 RFC 6901 pointer、
显式 presence/value、双 raw-observation hash 和 validator 可复算 fingerprint。

结果区分 `exact`、`semantic_equal`、`different`、`projection_failure` 和
`comparison_limit_reached`；contract 可要求 exact 或 semantic。完整差异硬上限为
10,000，超限不发布部分 report。projection/limit 失败会覆盖输出为不可 waiver 的
versioned blocked marker，配置过 policy 的 projection failure 也不会继续运行
normalizer。`audit_semantic_case.py` 已继续执行 exact waiver audit；
`run_compatibility_suite.py` 使用 hash-bound expected matrix 顺序运行所有
typed legacy case，并聚合统一顶层 report。尚未闭合的是 engine-only/modern
typed variant、真实跨平台矩阵和 release approval/signing。

format HostApi 的 argument conformance case 必须同时断言语义返回、异常四元组
（name/message/line/backtrace）和 stderr。特别覆盖 Qt 5/Qt 6 对 extra arguments、
缺少必需参数、C++ 默认参数，以及 `qint64` 的 string/boolean/null/undefined
转换；不能因返回值相同而忽略 Qt 6 的 extra-argument diagnostics。整数读取还要
按宽度/端序/别名覆盖 unsigned 24-bit；`quint64` 位移分别覆盖 0、合法最大边界、
负数/fraction/safe-integer 外转换，并把 shift >= 64 的上游 C++ 未定义范围作为
显式 safety-deviation 决策，不能从单机结果冻结契约。

## 11. 差异分类与 waiver

未匹配差异默认失败。分类采用 `Exact`、`Semantic`、`SafetyDeviation` 和
`Unsupported`，含义与 [`api.md`](api.md) 一致。

waiver 是精确、有期限的审计记录，不是宽泛 allowlist。v1 registry 整体绑定一个
platform/upstream commit/Rust schema；每条 record 只绑定一个 case 和一个非根
JSON Pointer，不使用数组或 glob 扩大匹配面。格式为：

```json
{
  "schema_version": 1,
  "registry_identity": {
    "platform": "linux-x86_64",
    "upstream_commit": "74eaf505c250ab47e709024e9dc41657cd8f2254",
    "rust_schema": 1
  },
  "waivers": [{
    "id": "DIFF-0001",
    "status": "approved",
    "case_id": "cli.path.symlink-cycle",
    "json_pointer": "/items/0/error/code",
    "classification": "SafetyDeviation",
    "failure_kind": "safety_limit",
    "left_raw_sha256": "<sha256>",
    "right_raw_sha256": "<sha256>",
    "diff_fingerprint": "<sha256>",
    "evidence": "docs/research/...",
    "decision": "docs/design/decisions/0014-bounded-path-expansion.md",
    "owner": "compatibility",
    "reviewed_by": "compatibility-owner",
    "reviewed_on": "2026-07-27",
    "expires": "2027-07-27",
    "removal_condition": "...",
    "threat_analysis": "docs/design/risks.md",
    "regression_test": "tools/tests/test_....py"
  }]
}
```

约束：

- 不允许 `*` case、全部平台、整份 stdout 或根 JSON path 的 blanket waiver。
- 必须固定 upstream/schema/platform 和精确 case/field。
- 必须包含原始两侧 hash/diff fingerprint，防止差异扩大后仍匹配。
- `SafetyDeviation` 必须链接 ADR、威胁和回归测试。
- `Unsupported` 必须有 roadmap phase 和实现退出条件。
- crash、memory safety、data race、panic、hang、unbounded allocation、silent
  unknown syntax 和 ABI UB 永远不可 waiver。
- expired、unmatched 或意外不再需要的 waiver 都使 CI 失败。
- waiver 增改要求 compatibility owner review。

该策略由 [`ADR 0004`](decisions/0004-evidence-bound-difference-waivers.md) 记录。
v1 schemas 位于 [`schemas/`](schemas/)，reference validator 为
[`validate_difference_waivers.py`](../../tools/compat/validate_difference_waivers.py)。
validator 使用严格 JSON（拒绝 duplicate key、`NaN`/`Infinity` 和未知字段），
重新计算 canonical diff fingerprint，并以显式 `--as-of` 产生 applied、
unmatched、expired 和 stale audit。当前 v1 只处理 semantic JSON Pointer；
raw-only byte-range waiver 默认 unmatched。

## 12. Unit、property 与 integration

最低测试要求：

- checked input：`0`、边界、`u64::MAX`、checked add/mul、short read、32-bit
  `usize` 转换和 allocation failure；
- parsers：每个字段的最小合法、截断、冲突长度、重叠、极大计数和 unsupported；
- budget：`limit-1/limit/limit+1`、子任务累计、diagnostic cap 和 queue cap；
- arena：parent/child 一致、stable ID、无 cycle 和 deterministic finalize；
- rules：发现/排序/init/include、全部语法节点、host API 类型/边界及异常；
- include graph：self/two-node/dynamic cycle、长无环链、重复非 active include，
  depth/evaluation budget 的 `limit-1/exact/+1`；不得依赖 VM/native stack
  overflow，SafetyDeviation 必须保留 upstream raw 诊断；
- engine：candidate 顺序、all-types、unknown、heuristic、嵌套、partial 和 cancel；
- engine contract：精确 signature name（含大小写/deep gate）、record sort 开关、
  callback 在首条/中间/末条 false、同步跨线程 stop、规则 `_breakScan()`、预停止、
  fresh-state engine 恢复，以及 file/memory/device/subdevice 等价；另固定
  chunked/EOF/read/seek/sequential、初始 position、合法/非法 subdevice range；
  legacy 保留部分 record/Unknown 和上游 slice overread 证据，Rust checked view
  断言父 source 不越界读取；modern 按 ADR 0009 验证类型化取消、按 ADR 0013
  对不完整读取 fail closed；
- output：UTF-8 escaping、整数、float、optional/null、key/array order；
- special modes：理论 entropy `6.484375/6.5/6.515625` 对应固定运行时
  double/status/text，struct 大小写、空/未知/超深 section、空 option 分派，
  PE/ELF/Mach-O/DEX 11 个格式方法及两目标 filename-prefix/多文档 framing；
- profiling：无 messages 时与默认输出逐字节相同；有 messages 时保留 292 条
  signature 名称/顺序/数量，只允许对 elapsed milliseconds 做具名规范化；
- database：三层顺序、空/缺失/损坏、duplicate、hash mismatch 和事务失败；
- database cache：cold miss/hit、保持 count/size/mtime 的内容替换、bad
  magic/version/engine、每个 record 字段截断、超大 count/text、写失败和并发
  writer；decode 失败不得发布部分 record，取消前/中/后不得提交 cache，未取消的
  后续加载不得复用 canceled/partial state。

property test 的随机 seed、case count 和 shrink result 进入失败输出；修复后的最小
case 晋升为命名 regression，不只依赖随机重现。

## 13. Rule conformance

规则门禁针对 manifest 中每一个固定上游规则，而不是少量代表文件：

- inventory 数、相对路径和 hash 与 upstream manifest 完全相同；
- parser 对每个文件返回 success 或明确 unsupported/error；
- zero silently skipped files/statements/functions；
- init/include/detect 生命周期和 priority/filter 顺序有 instrumentation；
- 每个 host function 有参数类型、边界、错误、返回值和副作用测试；
- Boa/QuickJS/最终 backend 使用同一 conformance cases；
- runtime heap/stack/fuel/deadline/cancel 都有硬失败测试；
- runtime exception 不污染下一规则、下一 node 或下一次 scanner 调用。

全库“可解析”不等于行为兼容。必须同时通过代表性输入 differential 和 host call
trace；选定 runtime 前保留失败规则清单及最小重现。

外部取消 fixture 使用确定性握手：worker 只能在 runtime interrupt handler 已被
观察后设置 token；handler 另有独立硬上限，防止测试自身永久挂起。断言必须包括
取消来源、typed/interrupted error、硬上限未触发，以及清除 token 后同一 context
恢复。不得固定受 OS 调度影响的 handler callback 次数。另设 native HostApi
长循环合作取消用例，因为 VM interrupt 不能抢占正在执行的 Rust/native 调用。
rquickjs spike 已用项目生成的 cooperative loop 验证可行性；正式实现仍须让真实
signature/search/decompression 循环分别覆盖取消前、精确 checkpoint 和硬上限，
并测试不可分割阻塞调用不会被误报为可取消。

wall-clock fixture 的 VM 计时从首次 interrupt callback 开始，native 计时使用调用
前配置的绝对 monotonic deadline；两者另设硬上限并验证同 context 恢复。测试固定
到期/终止/恢复，不固定 callback 数、checkpoint 数或产品默认时长。正式 timeout
测试必须注入 clock 验证 cancel/deadline 竞争顺序，并在真实时钟 system test 中
只设置有依据的最大延迟上界。

## 14. Fuzz 设计

初始 fuzz targets：

- `ByteView` subview/read/LE-BE integer；
- 每个 format probe/parser；
- database archive/manifest/rule parser；
- rule host API argument conversion；
- canonical/legacy serializer；
- nested archive/resource extractor 与 work queue；
- engine single input with synthetic bounded database；
- C ABI bytes/options/lifecycle state machine。

### 已实现 fuzz targets（2026-08-01）

| Target | 覆盖层 | 不变量 |
|--------|--------|--------|
| `fuzz_byte_source` | die-core | 无 panic、无越界 |
| `fuzz_byte_view_subview` | die-core | 无 panic、无越界 |
| `fuzz_format_probe` | die-formats | 无 panic、无 None strength、无 Io error |
| `fuzz_scan_engine` | die-engine | 无 panic、无 hang、detection 字段非空 |
| `fuzz_output_render` | die-output | 无 panic、JSON 可解析、所有渲染器不崩溃 |
| `fuzz_scan_ffi` | die-ffi | 无跨边界 panic、状态码合法、double-free 安全 |

每个 target 设置输入大小、总 allocation、depth、instruction 和 wall timeout。
fuzz invariant：

- 无 panic/abort/native crash、越界、UB、leak 和 data race；
- 超限在规定时间内返回 typed limit；
- 相同输入 deterministic；
- parser 不接受相互矛盾的 range；
- result arena 和 JSON schema 始终自洽。

PR 运行小型固定 seed smoke；nightly 持续更长时间；release 前运行累计 corpus。
使用 `cargo-fuzz`/libFuzzer，纯 Rust unsafe 边界补 Miri；native/FFI 在可用平台使用
ASan/UBSan/LSan，Windows 使用对应 sanitizer/Verifier。并发 scheduler 若引入共享
状态，增加 Loom 或等价模型测试。

crash triage 保存 target、toolchain、seed/input hash、stack、limit 和首次发现 commit。
修复 SLA 在项目治理文档冻结前为开放项，但 release blocker 不得 quarantine。

## 15. FFI 与语言集成

C header 与 Rust 导出通过生成/校验脚本保持一致：

- symbol inventory、calling convention、visibility；
- `sizeof/alignof/offsetof`、enum/status/flag 数值；
- null、zero length、invalid UTF-8、reserved/struct_size；
- builder/scanner/result/error/cancel 状态机；
- free null/idempotent、double-free misuse、borrow-after-free contract；
- 1000+ lifecycle loop、allocation failure 和 panic containment；
- wrong-thread、busy、cancel race 和 scanner-per-worker；
- static `.a`/`.lib` 的最终 undefined/system libraries。

平台至少运行 C 编译/链接/执行。Go 运行 cgo one-shot、locked OS-thread reusable、
cancel 和 race detector。Python 测试 CPython extension/static link、bytes copy、
exception mapping 和 repeated import/use/free；不声称 `.a` 可被 `ctypes` 直接加载。

debug 与 release、Windows `/MD`/`/MT` 支持矩阵按 [`c-abi.md`](c-abi.md) 执行。

## 16. 性能与资源 benchmark

性能比较固定：

- hardware/VM、CPU model/core、RAM、OS/kernel、filesystem；
- Rust/upstream commit、rules/database hash、toolchain/profile/features；
- power governor、worker count、CPU affinity（可控制时）；
- corpus manifest、每个输入 size 和运行顺序；
- warm/cold cache 条件、预热次数、样本次数和统计方法。

分开测量：

1. database load/validate 与 runtime/session creation；
2. borrowed bytes 单文件 scan；
3. path I/O + scan；
4. nested/decompression；
5. canonical serialization；
6. batch single-thread 与 bounded parallel；
7. staticlib C call overhead；
8. peak RSS/commit、allocation count/bytes、output size。

报告 median、p95、MAD/置信区间、throughput 和 peak memory，不只报告最好一次。
upstream 与 Rust 使用相同 bytes/options/database；无法等价的 case 不用于“更快”
结论。冷 cache 如果不能可靠清除，明确标为 uncontrolled。

Phase 0 已提供
[`run_process_benchmark.py`](../../tools/benchmark/run_process_benchmark.py)
和对应的[调研记录](../research/process-benchmark-runner.md)，固定 strict plan、
输入/可执行文件 hash、bounded stdout/stderr、direct-process wall time/peak RSS
及机器报告。固定 Linux Qt5 的五层 warm-process 描述性基线、cgroup 和 noise
calibration 见
[`upstream-performance-baseline.md`](../research/upstream-performance-baseline.md)。
单 WSL2/Linux vCPU affinity 首轮复验、`cpuset.cpus.effective=0` 证明和短
control 的 partial-RSS 审计边界见
[`upstream-performance-affinity.md`](../research/upstream-performance-affinity.md)。
同一固定 affinity suite 的三次独立 invocation、51 warmup/270 measured 与
跨 session median/p95/RSS 漂移见
[`upstream-performance-repeated-sessions.md`](../research/upstream-performance-repeated-sessions.md)；
archive median max/min 1.7704 和 batch p95 max/min 1.6848 证明单 session
不能冻结阈值。
同五个 case 的双次 Linux x86_64 ptrace 已固定 2,283-file/
73,560,058-byte successful regular-file union，并证明 database path 成功打开
2,235 个 `.sg`、未打开 33 个非脚本资产，见
[`upstream-benchmark-file-access.md`](../research/upstream-benchmark-file-access.md)。
静态 controller 随后对每个 case 双次证明所有候选页完整 resident、fadvise 后
逐文件 0 resident、post-run vector 相同，且不保留受 controller 污染的 timing，
见
[`upstream-benchmark-page-cache.md`](../research/upstream-benchmark-page-cache.md)。
process runner plan/report schema v2 随后通过 preflight/exec/finalize 链接入
同一静态 controller、clock 与 `wait4` direct-child RSS 口径，对每个 case
采集 10 组 ABBA warm/file-content 配对，共 100 个 measured child；每个 run
都绑定 plan/controller/manifest identity、before-run 页状态和未变输出，见
[`upstream-benchmark-file-content-performance.md`](../research/upstream-benchmark-file-content-performance.md)。
该证据仍只是单次 WSL2 session。
failed lookup、目录、dentry/inode、overlayfs/host isolation 仍未闭合，因此不得
把它标成 cold；若采用 metadata-warm/file-content-nonresident 层，名称和比较组
必须与完整 cold 分开。
固定容器的只读环境 probe 又证明根是 overlayfs、`/proc/sys` ro、无
`CAP_SYS_ADMIN`、`drop_caches` write-open 返回 `EROFS`，且不存在 page-cache
namespace；见
[`upstream-benchmark-cache-environment.md`](../research/upstream-benchmark-cache-environment.md)。
因此 cache state 采用 ADR 0015 的三个互斥名称：`warm`、
`file-content-nonresident-metadata-warm`、`system-cold`；通用 `cold` 永久
拒绝。前两层和 system-cold 必须分别建立 baseline/trend/threshold，不能合并。
原生 Windows build 26100/NTFS 的双次只读观察进一步证明：当前 token 没有
`SeIncreaseQuotaPrivilege`，`SetSystemFileCacheSize` 是全局特权操作，
`FILE_FLAG_NO_BUFFERING` 会改变被测 handle 的 I/O 契约，
`EmptyWorkingSet` 只作用于进程 working set。因此 Windows 只复用 `warm`；
第二层保持 unsupported，system-cold 等待 dedicated Windows infrastructure，
见
[`windows-benchmark-cache-state.md`](../research/windows-benchmark-cache-state.md)。
macOS 又固定 Apple XNU `fcntl` flag 语义，并将
`msync(MS_SYNC|MS_INVALIDATE)` + per-page `mincore=0` 定义为第二层的
runtime candidate；候选只操作 unlink 后的 16 MiB temporary fixture，双轮
Darwin 报告及 benchmark closure 尚未执行，因此仍不 admission，见
[`macos-benchmark-cache-state.md`](../research/macos-benchmark-cache-state.md)。
固定 Linux Qt5 的 ELF、realpath 去重动态依赖闭包和 2,268 个规则资产 size
口径见
[`upstream-deployment-size.md`](../research/upstream-deployment-size.md)；
同时保留 binary+rules 与 full-closure+rules，禁止只用动态链接 ELF 本体比较。
这些证据尚无 Rust 成对数据、dedicated system-cold、macOS runtime candidate
与 fixed-closure integration、可证明 topology 的 physical-core 或跨
reboot/日期长期 session，
也无跨平台发行包，且未冻结阈值或默认限制。现有 scan/traversal 数值、上游临界值、
QuickJS spike-only 限额、include sizing 及 script runtime 等各类候选已由
[`resource-limit-policy.md`](resource-limit-policy.md) 和
[`data/resource-limit-policy-candidate.json`](data/resource-limit-policy-candidate.json)
统一为 0 个 unresolved、`admitted=false` 的完整评审候选；这减少配置漂移，
但不替代 production limit benchmark 或评审结论。

回归阈值在首个 Rust vertical slice 形成同 bytes/options 成对报告后冻结。小于
50 ms median 的 direct-process case 当前不具备 regression eligibility；阈值必须
同时约束 latency、throughput 和 peak memory，不能用速度提升掩盖内存失控。显著
变化先保存 profiler/trace，再优化；benchmark 不是普通 CI 的 correctness oracle。

## 17. CI 矩阵

### Pull request

- formatting、clippy `-D warnings`、unit/property smoke、doc contract；
- Linux/Windows/macOS 固定 default Rust 1.97.1 的 workspace tests，并以显式
  MSRV 1.88 job 防止最低版本漂移；浮动 stable 只作非阻塞前瞻信号；
- corpus/manifest/upstream lock verifier；
- generated corpus reproducibility；
- 快速 canonical/legacy golden 和最小 differential（oracle 可用 runner）；
- C static-link smoke；依赖/license/unsafe policy；
- 固定 seed fuzz smoke。

### Nightly/scheduled

- 全 capability differential matrix；
- full rules conformance；
- 长时间 fuzz、sanitizers、Miri 和并发模型测试；
- Go/Python integrations 与 race checks；
- x86_64 + aarch64、必要的 32-bit checked-input build/test；
- deterministic repeat/parallel stress；
- benchmark trend 和 artifact retention。

### Release

- clean checkout 重建所有发布产物；
- 三大桌面平台目标架构 static-link system tests；
- 完整 differential、waiver audit、schema/header/symbol audit；
- rules/source/license/SBOM/provenance；
- component license inventory：58 个 gitlink commit、root LICENSE path/hash、
  nested `.gitmodules` 和 bundled license candidate diff；候选文件名清单不得
  代替实际 object/link/file-header license closure；
- bundled build closure：由固定 link line 和 `.o.d` 反推实际 compile
  source/header/archive，固定 path/hash/license marker，并拒绝对象数或链接关系
  静默漂移；默认构建但未进入主二进制的 target 仍计入 source/build
  distribution 审计，不能只按最终 link closure 删除；
- embedded source provenance：固定官方 remote/commit/license/generator/input，
  以去注释 token 精确比较或长 shingle coverage 证明来源；覆盖率不得代替未匹配
  区域分类；无内联声明的 vendored 文件必须沿固定 blob/history 链恢复原
  LICENSE/NOTICE；
- native compiler diagnostics：保存规范化 warning path/line/option 和原始输出
  hash；新增、消失或分类变化均需评审，不能把 warning 静默视为通过；
- artifact content closure：对每个平台和发布格式固定安装/解包后的 path、
  type、mode、bytes、content hash、来源和 LICENSE/NOTICE/SBOM 覆盖；拒绝
  CLI-only artifact 混入 GUI/lite/不可达数据、同一规则多份复制、manifest
  重复覆盖或未分类文件。固定上游 Linux Qt5 CMake staging 基线见
  [`linux-cmake-install-tree.md`](../research/linux-cmake-install-tree.md)，但
  不得把它外推为 AppImage/portable/压缩包；上游 AppImage pre-linuxdeploy 与
  portable post-build 反例见
  [`linux-release-trees.md`](../research/linux-release-trees.md)；
- archive reproducibility：固定 path order、mtime、mode、owner/group、压缩器
  与 `SOURCE_DATE_EPOCH`；两次隔离 clean build 必须同时得到相同解包 tree hash
  和 archive hash。普通 `tar -czf` 成功退出不能作为可重复发布证据；固定上游
  的两次 post-build replay 已实际观察到相同 tree/成员语义却因八个 mtime
  差异产生不同 tar 与 tar.gz；对同一 tree 固定排序、mtime、owner/group、
  GNU format 和 gzip header 后，两份 17,463,573-byte control archive
  逐字节相同。该 control 验证机制但不替代 Rust clean build 与获批 manifest，见
  [`linux-release-trees.md`](../research/linux-release-trees.md)；
- fuzz corpus replay、零未分类 crash；
- benchmark 与 size/resource gate；
- release binary/library hash、依赖和签名清单。

最低平台表：

| OS | Architecture | Rust | C link | Differential | Go/Python |
| --- | --- | --- | --- | --- | --- |
| Linux | x86_64 | fixed default + MSRV | required | required | required |
| Windows | x86_64 MSVC | fixed default + MSRV | required | required when oracle fixed | required |
| macOS | x86_64 | fixed default + MSRV | required | required when oracle fixed | required |
| macOS | aarch64 | fixed default + MSRV | required | required when oracle fixed | required |

Linux aarch64、Windows aarch64 和 32-bit 是扩展门禁；宣称支持前必须升为 required。
不得用 Linux oracle 证明 Windows/macOS CLI 路径和编码完全兼容。

## 18. Flake、失败与 quarantine

- correctness/differential test 不自动 retry 后转绿；可重跑用于诊断，但保留首次失败。
- flaky case 有 issue、owner、首次/最近失败、seed 和解除条件。
- security、ABI、规则静默跳过和 release differential 不可 quarantine。
- infrastructure failure 与 product failure 分开，二者都不能算 pass。
- 同一 case 在 clean runner 三次不同输出立即视为 determinism defect。
- 更新 golden 必须展示 old/new semantic diff，禁止无审查批量重录。

## 19. Artifact 与保留

提交到 Git：

- 小型文本 manifest/schema；
- 项目生成器和合法的小型 golden；
- normalizer/validator；
- 非敏感最小 regression。

不提交：

- build target、完整 Docker layer、临时扫描输出；
- 未知/恶意/客户样本；
- 本机绝对路径、credential、环境 dump；
- 无界 stdout/stderr 或 profiler data。

CI artifact 使用 content hash、访问控制和保留期。release compatibility report 长期
保留 manifest、summary、waiver 和 raw hash；受限 raw bytes 留在隔离存储。

## 20. 机器可读报告

完整差分报告最终至少包含：

```text
report_schema
run_identity
case_identity
oracle_execution
rust_execution
raw_comparison
semantic_comparison
normalizations_applied
waivers_applied
unmatched_differences
result
```

`result` 只能是 `pass`、`fail` 或 `infrastructure_error`。没有“warning 即 pass”
的隐式状态。summary 按 capability、platform、classification 和 waiver 聚合，并
链接精确 case，不只提供总百分比。

Phase 0 已先冻结并实现 waiver 子流水线的三个 v1 schema：

- [`difference-input-report-v1.schema.json`](schemas/difference-input-report-v1.schema.json)；
- [`difference-waiver-registry-v1.schema.json`](schemas/difference-waiver-registry-v1.schema.json)；
- [`difference-waiver-audit-v1.schema.json`](schemas/difference-waiver-audit-v1.schema.json)。

规范化子流水线同时冻结并实现三个 v1 schema：

- [`semantic-projection-v1.schema.json`](schemas/semantic-projection-v1.schema.json)；
- [`semantic-normalization-policy-v1.schema.json`](schemas/semantic-normalization-policy-v1.schema.json)；
- [`semantic-normalization-output-v1.schema.json`](schemas/semantic-normalization-output-v1.schema.json)。

raw execution evidence 子流水线冻结并实现两个 v1 schema：

- [`raw-execution-v1.schema.json`](schemas/raw-execution-v1.schema.json)；
- [`raw-execution-verification-v1.schema.json`](schemas/raw-execution-verification-v1.schema.json)。

lossless framing 子流水线冻结并实现：

- [`raw-framing-projection-v1.schema.json`](schemas/raw-framing-projection-v1.schema.json)。

typed legacy semantic projection 子流水线冻结并实现：

- [`semantic-projection-contract-v1.schema.json`](schemas/semantic-projection-contract-v1.schema.json)；
- [`semantic-result-v1.schema.json`](schemas/semantic-result-v1.schema.json)；
- [`semantic-result-projection-v1.schema.json`](schemas/semantic-result-projection-v1.schema.json)。

单 case 双侧比较子流水线冻结并实现：

- [`semantic-comparison-contract-v1.schema.json`](schemas/semantic-comparison-contract-v1.schema.json)；
- [`semantic-comparison-v1.schema.json`](schemas/semantic-comparison-v1.schema.json)；
- [`semantic-difference-blocked-v1.schema.json`](schemas/semantic-difference-blocked-v1.schema.json)。

单 case 顶层比较/waiver 决策冻结并实现：

- [`semantic-case-audit-v1.schema.json`](schemas/semantic-case-audit-v1.schema.json)；
- [`audit_semantic_case.py`](../../tools/compat/audit_semantic_case.py)。

typed legacy 多 case 执行与顶层报告冻结并实现：

- [`compatibility-suite-plan-v1.schema.json`](schemas/compatibility-suite-plan-v1.schema.json)；
- [`compatibility-suite-report-v1.schema.json`](schemas/compatibility-suite-report-v1.schema.json)；
- [`run_compatibility_suite.py`](../../tools/compat/run_compatibility_suite.py)。

这些子 schema 不冒充完整 differential report：waiver input 只携带 executed case、
精确 semantic difference、两侧 raw stream hash 和 canonical fingerprint；
normalization input 只是任意 semantic value 的版本化 envelope，不等于完整
semantic model；raw verifier/framing 只证明一侧 execution bytes 身份与 stdout
无损分段；case audit 证明一个 typed legacy case 的完整 comparison/waiver
决策；suite report 证明 version-controlled plan 中预期 case 矩阵全部执行并按
platform/capability/classification/waiver 汇总。engine-only/modern variants、
真实 Windows/macOS 矩阵和 release approval/signing 仍需接入。

## 21. Phase 门禁

### Phase 1

- workspace CI、manifest validator 和依赖 DAG 检查存在；
- 最小 corpus 可重复生成；
- 规则 source/order manifest validator 能检测 path/hash 漂移与 comparator cycle；
- Rust placeholder/vertical slice 能被 differential harness 调用并产生可审计失败；
- C smoke 和 canonical schema golden 基础设施存在。

### Phase 2

- 每个实现格式有 positive/truncated/malformed/fuzz/differential cases；
- 范围内能力矩阵 100% traceable；
- 零 panic、hang、unbounded allocation 和未解释 semantic diff。

### Phase 3

- 固定规则 inventory 100% discovered/parsed/loaded；
- 每个支持 target 的 cyclic rule set 有精确 oracle order manifest，runtime 不
  调用非传递 comparator；
- zero silent unsupported syntax；
- host API/lifecycle conformance 完整；
- 代表语料规则结果达到批准阈值，剩余差异都有精确 waiver。

### Phase 4

- legacy CLI raw matrix 和 modern schema matrix通过；
- path/special/database/nested/error/exit 全覆盖；
- 三平台差异已分类，无无效 structured modern output。

### Phase 5

- C/Go/Python ownership、thread、cancel、panic 和 static-link matrix 通过；
- header/symbol/layout 与 canonical bytes 一致；
- sanitizer/race 生命周期测试无问题。

### Phase 6/release

- 全范围 capability traceability 无 missing；
- 全 differential 无 unmatched/expired/stale waiver；
- fuzz/security、performance、license/SBOM 和跨平台 release gates 全通过；
- compatibility report 随版本发布。

“100% traceable”不等于“100% compatible”；report 必须分别展示 implemented、
tested、exact、semantic、waived 和 unsupported 数量。

## 22. 风险与开放门禁

- Windows/macOS upstream oracle 尚未固定，不能声称跨平台 exact。
- capability coverage report 已覆盖全部 68 行和 272 个平台 cell 的分类；当前
  Linux Qt5 的 68 项均为 runtime-observed，source-only 与 corpus-gap 均为 0；
  三个缺失平台仍不足以满足 capability matrix；source-only 空闭集见
  [`source-only-closure.json`](../research/data/source-only-closure.json)。
- ADR 0006 已提议 rquickjs/QuickJS-NG，但 acceptance conditions 和全库
  execution conformance 未通过。
- waiver v1、最小 semantic-normalizer v1、raw execution/artifact rehash、
  lossless raw framing v1、固定 legacy CLI typed semantic result v1 和单 case
  双侧 comparator + exact waiver audit v1、hash-bound typed legacy multi-case
  report 已实现；完整 semantic model 仍缺 engine-only/modern canonical
  variants，真实跨平台/release integration 尚未实现。
- process benchmark runner 已有 contract test；upstream 基线、noise、阈值、
  默认资源 limits 和 release integration 尚未冻结。
- archive/decompression sanitizer 与恶意语料隔离设施尚未建立。
- CI provider、artifact retention 和 restricted corpus 权限尚未决定。

这些项目关闭前本文不得标记为 Accepted。`In Review` 只表示测试层级、证据契约、
开放门禁和验收条件已经完整列出。

## 23. 测试设计验收条件

- case、execution、semantic report、normalizer 和 waiver 都有 versioned schema。
- 固定 upstream/rules/binary/corpus identity 失败时拒绝运行或报告
  `infrastructure_error`。
- raw stdout/stderr 与规范化结果同时保留且 hash 可追溯。
- 差分默认失败；waiver 精确、有证据、有到期/移除条件。
- capability matrix 可机器追踪到 tests/platform/result。
- fuzz、FFI、性能和三平台 CI 有可执行 target 与明确门禁。
- `testing.md`、ADR 0004 和风险清单完成评审后才能满足 Phase 0 测试方案门禁。
