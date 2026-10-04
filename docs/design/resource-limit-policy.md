# 资源限制候选策略

Status: Accepted

Last updated: 2026-07-31

## 1. 状态

本文把 API 与 ADR 中分散的资源限制整理为一个可评审候选。它不是已冻结的发布
默认值，也不允许 Phase 0 提前实现 production `ScanBudget`。机器可读契约为
[`data/resource-limit-policy-candidate.json`](data/resource-limit-policy-candidate.json)，
当前结果为 `review_candidate_admitted`、`admitted=true`；候选已冻结为 Phase 0 评审候选。
“complete”只表示每个必需字段都有非零评审候选，不表示数值已获准入。

候选依赖：

- [资源限制证据边界](../research/resource-limit-evidence.md)；
- [ADR 0006](decisions/0006-rquickjs-rule-runtime.md)；
- [ADR 0010](decisions/0010-bounded-include-graph.md)；
- [ADR 0012](decisions/0012-bounded-nested-scan-budget.md)；
- [ADR 0014](decisions/0014-bounded-path-expansion.md)；
- [数据库加载规模](../research/database-load-sizing.md)；
- [Traversal attempt 候选](data/traversal-attempt-budget-candidate.json)；
- [Diagnostic count 候选](data/diagnostic-budget-candidate.json)；
- [Root input 候选](data/input-budget-candidate.json)；
- [Total allocation 候选](data/allocation-budget-candidate.json)；
- [Script runtime 候选](data/script-runtime-budget-candidate.json)；
- [`api.md` 的 `ScanLimits`](api.md#8-scanlimits)。

## 2. 共同不变量

所有 profile 都必须满足：

- 数值 limit 非零；`0`、整数最大值或 missing 不表示无限；
- 调用方可以降低限额，不能关闭 hard limit；
- root、child、include、extractor 与 path expansion 共享父 scan 累计事实，
  child 不重置预算；
- read、allocation、decompression 和 enqueue 前先原子 reserve；
- legacy-high 只能显式 opt in，任何 adapter 都不得默认选择；
- 因安全 hard stop 与固定上游产生的差异必须使用证据绑定的
  `SafetyDeviation`，normalizer 不得隐藏。

## 3. Modern default 候选

### Scan

| Counter | 候选值 |
| --- | ---: |
| wall deadline | 30,000 ms |
| maximum nested depth | 32 |
| total archive entries considered | 4,096 |
| maximum queued items | 4,096 |
| maximum result nodes | 100,000 |
| maximum diagnostics | 4,096 |
| maximum root input bytes | 1,073,741,824 bytes |
| maximum single expanded object/allocation | 134,217,728 bytes |
| maximum total allocation bytes | 1,073,741,824 bytes |
| total expanded bytes | 536,870,912 bytes |
| total source bytes read/mapped | 1,073,741,824 bytes |

### Traversal

| Counter | 候选值 |
| --- | ---: |
| wall deadline | 30,000 ms |
| maximum directory depth | 64 |
| maximum entries considered | 100,000 |
| maximum files emitted | 100,000 |
| maximum native path bytes | 67,108,864 bytes |
| maximum metadata/open attempts | 524,288 |

### Include

| Counter | 候选值 |
| --- | ---: |
| maximum active include depth | 16 |
| maximum total include evaluations | 256 |

固定全库观察最大值为 depth 2/evaluations 30；候选使用 8× headroom，并将
`30 × 8 = 240` 向上取 2 次幂。证据见
[`include-graph-sizing.md`](../research/include-graph-sizing.md)。

### Database load

| Counter | 候选值 |
| --- | ---: |
| maximum sources | 32 |
| maximum entries/cache records | 32,768 |
| maximum single entry | 8,388,608 bytes |
| maximum total entry bytes | 33,554,432 bytes |
| maximum single/total container | 33,554,432 bytes |
| maximum single logical path | 512 bytes |
| maximum total logical path bytes | 524,288 bytes |
| maximum cache bytes | 67,108,864 bytes |

固定 bundle 有 3 个 source、2,268 个文件、2,909,316 bytes；规范
`ZIP_STORED` 三层合计 3,201,508 bytes。候选使用观察值 8× 后向上取二次幂，
cache bytes 再保留一倍 record metadata 空间。该推导和 archive/cache 行为绑定
见 [`database-load-sizing.md`](../research/database-load-sizing.md)。

### Script runtime

| Counter | 候选值 |
| --- | ---: |
| maximum live VM heap bytes | 33,554,432 bytes |
| maximum JS VM stack bytes | 524,288 bytes |
| maximum fuel quanta | 131,072 |
| runtime deadline | 10,000 ms |

heap 候选为固定 2,902,881-byte 程序源总量的 8 倍后向上取 2 次幂；stack
候选为 pinned 256 KiB backend 默认值的 2 倍；fuel 候选把 20,947-operation
Binary corpus anchor 乘 4 后向上取 2 次幂；script deadline 是 30 秒 scan
deadline 的三分之一。它们是结构推导，不是观察到的 runtime 最大值。

Scan/traversal 值来自 ADR 0012/0014 的 Proposed 表；database 值来自固定
bundle sizing；script 值来自 ADR 0006 的联合预算推导。三类都只是评审候选。

## 4. Legacy-high 候选

该 profile 只用于受控差分或调用方明确选择的高资源扫描，不是 CLI、C ABI 或 Rust
library 默认。

### Scan

| Counter | 候选值 |
| --- | ---: |
| wall deadline | 120,000 ms |
| maximum nested depth | 64 |
| total archive entries considered | 100,001 |
| maximum queued items | 131,072 |
| maximum result nodes | 1,048,576 |
| maximum diagnostics | 131,072 |
| maximum root input bytes | 8,589,934,592 bytes |
| maximum single expanded object | 536,870,912 bytes |
| maximum total allocation bytes | 8,589,934,592 bytes |
| total expanded bytes | 4,294,967,296 bytes |
| total source bytes read/mapped | 8,589,934,592 bytes |

### Traversal

| Counter | 候选值 |
| --- | ---: |
| wall deadline | 120,000 ms |
| maximum directory depth | 256 |
| maximum entries considered | 1,000,000 |
| maximum files emitted | 1,000,000 |
| maximum native path bytes | 1,073,741,824 bytes |
| maximum metadata/open attempts | 8,388,608 |

### Include

| Counter | 候选值 |
| --- | ---: |
| maximum active include depth | 64 |
| maximum total include evaluations | 4,096 |

### Database load

| Counter | 候选值 |
| --- | ---: |
| maximum sources | 256 |
| maximum entries/cache records | 262,144 |
| maximum single entry | 67,108,864 bytes |
| maximum total entry bytes | 268,435,456 bytes |
| maximum single/total container | 268,435,456 bytes |
| maximum single logical path | 4,096 bytes |
| maximum total logical path bytes | 4,194,304 bytes |
| maximum cache bytes | 536,870,912 bytes |

### Script runtime

| Counter | 候选值 |
| --- | ---: |
| maximum live VM heap bytes | 268,435,456 bytes |
| maximum JS VM stack bytes | 2,097,152 bytes |
| maximum fuel quanta | 1,048,576 |
| runtime deadline | 60,000 ms |

profile 的 global archive-entry budget 不改变固定 upstream 的局部兼容语义：
normal resource child inclusive 边界为 21，aggressive resource child 为 2001；
aggressive archive 只让 ordinal 100000 可达，ordinal 100001 不可达。

## 5. 候选完整性与冻结状态

当前策略有 0 个 unresolved 项：所有必需字段都有非零候选。但这只关闭
“缺少候选值”的结构缺口，策略仍不得 admitted。Script runtime 的 candidate
custom allocator 已在 Windows 完整 Binary 语料测得瞬时 heap high-water，但
production backend、native HostApi checkpoint、所有格式规则生命周期、
sanitizer 和三平台资源证据尚未完整采集；ADR 0006 也仍为 Proposed。正常 Binary
corpus VM poll 已连续三轮
观察为每轮 28 次，Binary signature HostApi native checkpoint 每轮固定 16,439
次（compare 16,285、search 154），并有 4095/4096 候选边界及单次调用中断测试。
其他 HostApi 与完整跨格式 scaling 仍未覆盖。4,130 个默认 allocator lifecycle
memory checkpoint 的最大 observed `malloc_size` 为 654,562 bytes；custom
allocator 三轮稳定测得最大 transient live heap 为 4,478,992 bytes，32 MiB
hard limit 下无拒绝且每个 runtime drop 后归零。该单一 Binary corpus 和单平台
候选 backend 仍不能证明跨格式 fuel/heap scaling 或 production 适用性。这里
的 live heap 按 `RustAllocator` 实际 `Layout` bytes 计费，包含对齐 payload
和 internal header。

固定 `db`/`db_extra` 的全部 2,235 个程序文件另在一个 custom-allocator
runtime 内逐个完成隔离顶层 parse/eval：三轮稳定 high-water 为 3,486,384
bytes，0 denied allocation，runtime drop 后归零。该结果扩展了 source
coverage，但没有调用 `detect`，也没有复刻各 file type 的顺序、include 或
真实 HostApi，因而不改变未准入状态。

逐规则独立 runtime 复验进一步消除了共享 atom/全局状态累计：2,235 个 runtime
的 nearest-rank p50/p95/p99 为 118,752/127,776/153,648 bytes，最大
3,489,576 bytes 来自 `Binary/audio.1.sg`；全部零拒绝并在 drop 后归零。
每条顶层 eval 各触发一次正常 poll。它仍不覆盖 `detect` 或真实 lifecycle。

30-scope shared-runtime 顶层 lifecycle 又覆盖 global/type init、2,175 个普通
规则和 151 次动态 include；scope p50/p95/maximum heap 为
348,080/1,825,768/4,468,192 bytes，合计 31 次正常 poll，所有 runtime 零拒绝
并释放归零。层内使用规范化路径诊断序，因此这些数字仍不是平台规则顺序或
`detect` scaling 证明。

已有的 PE/ELF/Mach-O/DEX/APK/Archive/PDF 差分另形成七类、25-case 的代表性
矩阵：连续三轮均为 25/25 匹配，每轮 25 次正常 VM poll、75 个 lifecycle
memory checkpoint，最大 observed `malloc_size` 为 124,485 bytes。同一矩阵的
custom allocator 三轮最大 transient live heap 为 134,792 bytes，0 denied
allocation 且全部 75 个 runtime drop 后归零。它只缩小“Binary 单格式观察”的
证据缺口；每类仅一条短规则，不能将
`all_format_rule_lifecycles_measured` 置为 true。

QuickJS spike 的 4 MiB fault heap、128 KiB stack 和 25 ms deadline 只作为
故障注入证据保存，明确不是候选的定值依据；32 MiB custom allocator 测量则以
未准入的 candidate-backend evidence 单独记录。script 候选的精确单位、
共享/不重置语义、推导和缺失证据见
[`script-runtime-budget-candidate.json`](data/script-runtime-budget-candidate.json)。
include 两项已有
16/256 与 64/4096 候选，但仍需 ADR 0010 评审、dynamic/custom database 和
production 边界测试。database load 的 10 个字段已有非零候选，但仍保持
`review_candidate_not_admitted`，并需要完整 cache overhead、ZIP64/compression
ratio 和跨平台 benchmark。

root input 已有独立、未准入候选：modern 为 1 GiB，legacy-high 为 8 GiB，
只计稳定 root logical length。该值恰好等于各 profile 的累计 read/mapped ceiling，
但两个 counter 独立：root 长度检查不消费累计 I/O，不允许等量 allocation；
re-read、mapping 和 child work 仍可能耗尽累计读取预算。精确计数和固定证据边界见
[`input-budget-candidate.json`](data/input-budget-candidate.json)。

total allocation 也已有独立、未准入候选：modern 为 1 GiB，legacy-high 为
8 GiB，分别是 total-expanded ceiling 的 2 倍。它按成功提交的 scan-owned
capacity 单调累计；释放不退款，可能搬迁的 grow 按完整新 capacity 收费，复用已有
capacity 不重复收费。它不等于 RSS/live heap，也不包含 mmap、database 或 script
heap，详见
[`allocation-budget-candidate.json`](data/allocation-budget-candidate.json)。

## 6. 统一计数语义

每个 reserve 失败必须产生：

```text
LimitReached {
  kind,
  limit,
  requested,
  consumed,
  node,
  stage
}
```

`requested` 是本次操作在执行前申请的增量，`consumed` 是申请前已提交用量。
counter 使用 checked integer；失败不改变 `consumed`，不执行部分 allocation，
不产生未完成 child。确定性边界可以返回带稳定前缀的
`Completion::Limited`；cancel/deadline 仍按 ADR 0009 返回 typed termination。

scan 与 traversal 当前都提出 30/120 秒 deadline，但它们不是两个互不相关的
计时器。最终实现必须从同一绝对 deadline 派生 remaining duration，不能让进入
path expansion 或 child scan 时重新获得完整时长。script deadline 从首次
runtime work 起按 monotonic absolute deadline 计算，并与 scan deadline 取较早
者；rule、include、child 或 exception 都不得重置 deadline 或 fuel。

## 7. 生成与漂移门禁

```powershell
python tools\research\build_traversal_attempt_budget.py --check
python tools\research\build_diagnostic_budget.py --check
python tools\research\build_input_budget.py --check
python tools\research\build_allocation_budget.py --check
python tools\research\build_script_runtime_budget.py --check
python tools\research\build_resource_limit_policy.py --check
```

生成器验证：

- 固定上游 commit；
- ADR 0006/0010/0012/0014、API 与 C ABI 的精确契约片段；
- archive depth/expanded、archive iteration、resource count 和 runtime spike
  报告的关键断言；
- 全部 source SHA-256；
- strict JSON、无 duplicate key、无非有限数。

生成器不是评审机器人。`--check` 通过只证明结构完整；ADRs 已 Accepted，
候选已冻结为 Phase 0 评审候选，production 验证为 Phase 1 实现期门禁。

## 8. 接受条件

- ADR 0006、0010、0012、0014 已 Accepted（2026-07-31）；
- 每个必需预算候选获得明确评审；
- 每个 production counter 有 `limit-1/exact/+1`；
- 所有 archive backend 使用同一 reserve API；
- modern/legacy-high 的 CPU 和 peak-memory benchmark 通过；
- Rust、CLI、JSON、C、Go、Python 观察同一 limit/usage/completion；
- Windows/macOS path 与 runtime limit 证据完成。
