# ADR 0014：路径展开采用有界、句柄校验的双策略

Status: Accepted
Last updated: 2026-07-31
## 背景

固定 Linux Qt5 上游通过 `XBinary::findFiles()` 无条件递归目录。9-case 双 Oracle
已经确认：

- 显式文件 symlink、目录 symlink 和枚举中发现的 file/directory symlink 都会被
  跟随；
- 真实路径和 symlink alias 不按 inode 或 canonical path 去重，输出保留 alias
  路径；
- dangling symlink 输出 `Cannot find:`，不可读目录则静默变成成功的空结果；
- 64 层目录仍到达 leaf；
- `loop -> .` 没有 visited set，最终依赖 Linux symlink resolution 上限，在
  depth 40→0 的路径上把同一 PDF 扫描 41 次。

该行为是固定平台的兼容证据，却不是可移植安全边界。静态库会嵌入
C/Go/Python 进程，不能依赖 container、内核链接上限、调用方 watchdog 或本机
权限模型阻止循环、目录逃逸、TOCTOU 和无界枚举。

## 决策

Proposed：

1. 目录展开属于独立 `TargetExpander`，不进入 parser/rule engine。它输出有序的
   `ExpandedTarget` 或类型化 `TraversalDiagnostic`；CLI、JSON 和 FFI 不得各自
   重新枚举目录。
2. API 提供两个显式命名的策略，不以布尔参数混合：
   - `LegacyCompatible`：跟随显式及枚举发现的 file/directory link，保留 alias
     logical path、参数顺序、平台枚举顺序及非循环 alias 重复；
   - `SafeCanonical`：作为 modern API/CLI 候选默认；显式传入的 file symlink
     可以打开，但目录枚举默认跳过所有发现的 symlink/junction/reparse point，
     不跨 root。
3. `LegacyCompatible` 也不得无界。展开器维护当前 ancestry 的 stable file
   identity，只拒绝 cycle，不把全局已见 identity 当作去重集合；因此正常
   symlink tree 仍扫描四项，而 self-cycle 在首次回边产生
   `CycleDetected`，不会复刻 41 次依赖内核上限的扫描。
4. stable identity 在 Unix 使用打开句柄的 device/inode，在 Windows 使用
   volume/file ID；不得把 `canonicalize()` 后的展示字符串当作安全 identity。
   请求跟随目录 link 却无法取得 stable identity 时必须类型化失败，不能退回
   “继续直到 OS 报错”。
5. 每次展开共享 checked `TraversalBudget`，至少计数：
   `max_directory_depth`、`max_entries_considered`、
   `max_files_emitted`、`max_total_path_bytes`、metadata/open attempts、
   deadline 和 cancellation。每个 entry 在 metadata、分配 path 或入队前 reserve；
   child 不重置额度。一次 metadata/open attempt 是 adapter 对 filesystem 发起的
   一次 metadata/type/identity/read-link 查询，或一次 file/directory/reparse
   handle acquire/reacquire；失败调用也计数，内部重试必须再次 reserve。已经随
   handle 保存的事实若未刷新不重复计数。
6. 初始 `SafeCanonical` 候选值为 depth 64、considered/emitted files 各
   100,000、累计 native path encoding 64 MiB、metadata/open attempts
   524,288、deadline 30 s。
   `LegacyHighResource` 需要显式构造，候选 hard ceiling 为 depth 256、
   considered/emitted files 各 1,000,000、累计 path encoding 1 GiB、
   metadata/open attempts 8,388,608、deadline 120 s。attempt 候选按
   `4 + 4*entries_considered + files_emitted` 建立普通 entry 的 metadata/open/
   post-open verification 与 emitted-file handoff allowance，再向上取二次幂。
   复杂 link/reparse 或失败可更快耗尽该独立预算，不保证总能同时达到所有 counter
   最大值。数值在本 ADR Accepted 前可经 benchmark 评审调整，但任何 profile
   都不得用 `0`、整数最大值或缺省表示无界。
7. `SafeCanonical` 在支持的平台使用 directory handle 相对枚举/open，并在打开后
   以 `fstat`/handle identity 复验 type、root confinement 和枚举时 identity。
   identity/type/parent 发生变化时返回 `ChangedDuringTraversal`，不扫描替换后的
   target。平台缺少所需 primitive 时返回
   `UnsupportedSafetyGuarantee`，不得悄悄降级为字符串前缀检查。
8. permission denied、dangling link、cycle、limit、取消和 TOCTOU 都是结构化 item
   diagnostic，必须能与合法 empty directory 区分。policy 明确决定继续或停止，
   但不得丢失已发生的 diagnostic。
9. `LegacyCompatible` renderer 可以复现固定上游的 `Cannot find:`、静默权限
   错误和 alias prefix；核心 report 仍保留 typed fact。因 cycle/预算/TOCTOU
   hard stop 产生的差异分类为 `SafetyDeviation`，按 ADR 0004 绑定精确 case、
   limit、平台与本 ADR，normalizer 不得隐藏。
10. canonical 顺序基于完整无损 native name key，排序前不做 Unicode
    normalization 或 lossy UTF-8 转换。legacy 顺序按固定 Oracle 平台分别验证，
    不从 Linux 推断 Windows/macOS。

## 考虑过的替代方案

### 完全复制上游递归

最接近固定 Linux 小样本，但 cycle 终止依赖 OS，权限错误与 empty directory
不可区分，也没有全局 entry/path/time 上限。

结论：拒绝。

### 默认跟随目录 link，只增加最大深度

能阻止部分无限递归，却仍允许 root 逃逸、alias 扇出、TOCTOU 和平台相关重复；
达到深度时也无法区分真实深目录与 cycle。

结论：拒绝。

### 全局按 canonical path 或 inode 去重

可避免循环，但会错误删除上游正常 alias 重复，并且字符串 canonicalization
不能可靠处理权限、rename、mount、非 UTF-8 或 Windows reparse point。

结论：只使用 ancestry identity 检测 cycle，不做全局去重。

### 只依赖调用方 timeout 或 subprocess

静态库调用方可能没有隔离进程；timeout 也不能阻止 timeout 前的无界分配或目录
逃逸。

结论：进程隔离可以是第二层防线，不能替代 library budget 与句柄校验。

## 后果

- modern 默认不会因枚举目录而跨 symlink/junction 离开 root，权限、循环与空目录
  具有可区分结果。
- legacy 对普通 symlink alias 保持可观察顺序与重复，但恶意 cycle、超大目录和
  TOCTOU 输入会有明确安全偏差。
- Unix/Windows adapter 需要实现稳定 identity 和 handle-relative traversal；
  macOS 需要验证 volume normalization/case 行为。
- `TraversalPolicy`、budget usage 和 diagnostics 成为 Rust/CLI/JSON/C 的共享
  契约，增加跨平台 system/property tests。
- 候选默认值在性能和平台证据完成前不能宣称已冻结。

## 证据

- [`path-filesystem-behavior.md`](../../research/path-filesystem-behavior.md)
- [`path-filesystem-engine-qt5.json`](../../research/data/path-filesystem-engine-qt5.json)
- [`path-filesystem-fixture.json`](../../research/data/path-filesystem-fixture.json)
- [`large-directory-behavior.md`](../../research/large-directory-behavior.md)
- [`large-path-engine-qt5.json`](../../research/data/large-path-engine-qt5.json)
- [`large-path-fixture.json`](../../research/data/large-path-fixture.json)
- [`path-toctou-behavior.md`](../../research/path-toctou-behavior.md)
- [`path-toctou-engine-qt5.json`](../../research/data/path-toctou-engine-qt5.json)
- [`path-toctou-fixture.json`](../../research/data/path-toctou-fixture.json)
- [`path-locale-filesystem-behavior.md`](../../research/path-locale-filesystem-behavior.md)
- [`path-locale-filesystem-engine-qt5.json`](../../research/data/path-locale-filesystem-engine-qt5.json)
- [`path-locale-fixture.json`](../../research/data/path-locale-fixture.json)
- [`traversal-attempt-budget-candidate.json`](../data/traversal-attempt-budget-candidate.json)
- [`special-path-behavior.md`](../../research/special-path-behavior.md)
- [`cli-path-behavior.md`](../../research/cli-path-behavior.md)
- [`test_probe_path_filesystem_behavior.py`](../../../tools/tests/test_probe_path_filesystem_behavior.py)
- [`test_generate_path_filesystem_fixture.py`](../../../tools/tests/test_generate_path_filesystem_fixture.py)
- [`test_probe_large_path_behavior.py`](../../../tools/tests/test_probe_large_path_behavior.py)
- [`test_generate_large_path_fixture.py`](../../../tools/tests/test_generate_large_path_fixture.py)
- [`test_probe_path_toctou_behavior.py`](../../../tools/tests/test_probe_path_toctou_behavior.py)
- [`test_generate_path_toctou_fixture.py`](../../../tools/tests/test_generate_path_toctou_fixture.py)
- [`test_probe_path_locale_filesystem_behavior.py`](../../../tools/tests/test_probe_path_locale_filesystem_behavior.py)
- [`test_generate_path_locale_fixture.py`](../../../tools/tests/test_generate_path_locale_fixture.py)
- [`test_traversal_attempt_budget.py`](../../../tools/tests/test_traversal_attempt_budget.py)
- `Formats@1151e725.../xbinary.cpp::findFiles`
- [`api.md` §14](../api.md#14-batch-与目录枚举)
- [`risks.md` R-019](../risks.md#r-019路径枚举和编码安全)
- [`0004-evidence-bound-difference-waivers.md`](0004-evidence-bound-difference-waivers.md)

## Decision acceptance

Phase 0 评审确认以下决策方向：

- safe canonical 不跟随枚举 link；legacy alias 仍受 cycle/TOCTOU/budget hard stop；
- traversal 候选已机器统一但 metadata/open 次数未定。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- production `TargetExpander` 与 parser/rule engine 保持单向边界，所有 adapter
  消费同一 `ExpandedTarget`/diagnostic model；
- 固定 Linux fixture 对 direct/file-link/dir-link/alias tree/dangling/permission/
  depth-64/self-cycle 的 legacy 与 canonical 预期均有 system tests；
- 每个 traversal limit 有 `limit-1/exact/+1` unit/property tests，取消/deadline
  在大目录中有有界响应并保留稳定前缀与 usage；
- metadata/open 的成功、失败、retry、link/reparse 和 TOCTOU revalidation
  都逐 attempt reserve；mock adapter 证明 exact/+1 不发生越界调用；
- Unix stable identity、Windows junction/reparse point、macOS case/normalization
  及三平台排序都有固定 upstream/Rust differential；
- handle-relative open 的 rename/link/target-swap adversarial tests 证明 root
  confinement，identity/type 改变均 fail closed；
- permission、empty、dangling、cycle、limit 和 TOCTOU 在 Rust、canonical JSON、
  CLI、C、Go、Python 中映射为同一 typed fact；
- legacy 的 alias 重复/顺序保持 exact；所有 hard-stop 差异具有 ADR 0004
  machine-readable SafetyDeviation waiver；
- benchmark 评审确认或调整两个 profile 的
  depth/entry/path-byte/metadata-open/deadline 数值。
