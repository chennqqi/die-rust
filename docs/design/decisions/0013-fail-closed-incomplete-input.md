# ADR 0013：不完整输入读取必须 fail closed

Status: Accepted
Last updated: 2026-07-31
## 背景

固定 `XScanEngine@dfe4a419e4f491bb23688ba03c5a5bf39e34da83` 对不超过
16 MiB 的输入先分配 `new char[nSize]`，调用
`XBinary::read_array_process()`，随后无条件用声明的 `nSize` 构造 `QBuffer`。
返回的实际读取字节数没有被检查；`safeReadData()` 遇到提前 EOF、`read()=-1`
或 seek 失败只停止循环，不写 `PDSTRUCT::sErrorString`。因此未读满时，扫描器会把
未初始化的 buffer 尾部当作输入继续处理。

固定 Linux Qt5 的 37-case engine oracle 进一步观察到：

- 3-byte chunked direct device 会循环至完整 35 bytes；
- 提前 EOF 只返回 5/35 bytes，`read()=-1` 返回 0/35 bytes，seek 失败和
  sequential device 完全不读取；这些 case 仍得到 `pd_success=true`、空 scan
  error 和正常 Binary detection；
- 相同现象也发生在合法 subdevice；
- Qt 的父设备缓冲在 35-byte subdevice 的 3-byte chunk case 实际读取 36 bytes，
  即触碰 slice 末端后一字节；
- 负 offset、非正 size、offset 等于末尾和越过末尾的 subdevice 范围直接返回
  全零 `SCAN_RESULT`，不读设备也不产生诊断；精确最后一字节范围有效。

复制这些行为需要读取未初始化内存、允许 slice 外读取，或把真实 I/O 失败伪装成
成功。这违反不可信输入、确定性、无 `unsafe` 默认和显式错误模型约束。

## 决策

Proposed：

1. 核心扫描只接受具有稳定长度和受控随机访问语义的 `ByteSource`。每次读取返回
   `Result<usize, IoError>`；需要固定长度的读取必须使用 checked `read_exact_at`。
2. 在声明范围结束前遇到 EOF，返回
   `IoError::ShortRead { offset, expected, actual }`；底层 read/seek 错误保留
   source kind。不得继续格式探测、规则执行或生成成功 detection。
3. 不分配或读取未初始化字节。buffer 必须初始化，并且只有在完整读取成功后才能
   发布为 scan view；zero-fill 后继续扫描也被禁止。
4. subdevice 使用 checked `offset + size`，要求 `size > 0`、`offset < source_len`
   且 `end <= source_len`；精确末字节有效。负 C/FFI 参数在转换为无符号类型前返回
   `INVALID_ARGUMENT`，溢出返回 typed range error。
5. view 的底层读取请求不得越过自身 `[offset, end)`。不得复制 Qt 父设备为满足
  内部缓冲而多读 slice 后一字节的行为。
6. 不满足随机访问契约的 sequential/non-seekable source 在扫描前返回 typed
   `IoError::NotSeekable`。未来若增加 streaming scanner，必须是独立能力和 ADR，
   不能静默进入现有随机访问 parser。
7. modern API 对非法 subdevice 范围返回 `InvalidRequest`，不返回看似成功的全零
   report。legacy 差分仍保存上游零结果，但不得把它作为 core success。
8. 上述 short-read、seek、slice-overread 和 invalid-range 差异均分类为
   `SafetyDeviation`，按 ADR 0004 绑定 upstream commit、case、字段、原始 artifact
   hash 和本 ADR；normalizer 不得隐藏。
9. 输入错误分类在 Rust、canonical JSON、CLI 和 C ABI 中来自同一核心事实。adapter
   不得把 I/O error 降级为 Unknown detection 或空成功结果。

## 考虑过的替代方案

### 完全复制上游未初始化尾部

可能匹配某次分配器状态，但引入未定义行为、信息泄漏、随机 detection 和跨平台
漂移。

结论：拒绝。

### 未读部分补零后继续扫描

避免未初始化内存，却把不存在的零字节伪造成输入，可能改变 magic、offset 和规则
结果，也会隐藏真实介质或并发修改错误。

结论：拒绝。

### 对所有 short read 无限重试

合法 chunked reader 需要有限循环，但 EOF、永久错误或恶意 source 会导致 hang。
实现只在有正进展时继续；零或错误立即终止。

结论：拒绝。

### 自动把 sequential source 全部缓存

未知长度可能导致无界读取和分配，且无法满足 parser 的稳定长度/随机访问假设。
未来可在显式总字节预算下提供独立导入步骤，但不作为 scan 的隐式行为。

结论：拒绝。

## 后果

- 输入截断、介质错误和不可 seek source 会确定性失败，不再产生依赖 heap 残留的
  detection。
- Rust 不会越过 subdevice 边界读取父 source。
- modern API 的 short-read/invalid-range 结果与固定上游不同，必须保留精确
  SafetyDeviation 证据。
- `ByteSource`、parser、嵌套 view、FFI callback 和 CLI 文件 adapter 必须共享
  checked range 与 exact-read 实现，增加了一组跨层 contract tests。
- 合法的分块读取仍被支持，只要每次有正进展并最终满足请求。

## 证据

- [`engine-contract-behavior.md`](../../research/engine-contract-behavior.md)
- [`engine-contract-linux-qt5.json`](../../research/data/engine-contract-linux-qt5.json)
- [`test_probe_engine_contract.py`](../../../tools/tests/test_probe_engine_contract.py)
- `XScanEngine@dfe4a419.../xscanengine.cpp::scanProcess`
- `XScanEngine@dfe4a419.../xscanengine.cpp::scanSubdevice`
- `Formats@1151e725.../xbinary.cpp::safeReadData`
- `Formats@1151e725.../subdevice.cpp::SubDevice`
- [`api.md` §12](../api.md#12-错误模型)
- [`testing.md` §12](../testing.md#12-unitproperty-与-integration)
- [`0004-evidence-bound-difference-waivers.md`](0004-evidence-bound-difference-waivers.md)

## Decision acceptance

Phase 0 评审确认以下决策方向：

- short read/I/O/seek/range fail closed，不复制未初始化尾部；
- modern API 的 short-read/invalid-range 结果与固定上游不同，必须保留精确
  SafetyDeviation 证据。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- 固定 Qt5 probe 对 chunked、EOF、read error、seek error、sequential、初始 position、
  direct/subdevice 和全部范围边界作强断言，且报告绑定 harness/source/image hash。
- production `ByteSource::read_exact_at` 对正进展分块、EOF、错误、零进展和超范围读取
  有 unit/property tests。
- subdevice 对 `0`、末字节、末尾、越界、checked-add overflow 和 FFI 负值有
  `limit-1/exact/+1` 回归测试，底层 mock 证明从不读取 view 之外。
- Rust、CLI、JSON、C、Go 和 Python 对同一不完整输入返回一致的 typed I/O/range
  error，legacy 差异用 ADR 0004 SafetyDeviation waiver。
- fuzz/sanitizer 不能产生 panic、heap 残留读取或未定义行为。
