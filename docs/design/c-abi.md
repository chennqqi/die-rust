# C ABI 设计

Status: Accepted

Last updated: 2026-07-31

## 依据与状态

本设计依赖：

- [`../research/c-static-link-spike.md`](../research/c-static-link-spike.md)：
  Windows/Linux staticlib、CRT、所有权和 panic 实验。
- [`../research/source-analysis.md`](../research/source-analysis.md)：上游扫描调用链、
  结果树和运行时生命周期。
- [`../research/capability-matrix.md`](../research/capability-matrix.md)：扫描选项、
  文件/内存入口和可观察能力。
- [`../research/database-error-behavior.md`](../research/database-error-behavior.md)：
  上游数据库错误的不一致语义。
- [`../research/nested-scan-behavior.md`](../research/nested-scan-behavior.md)：
  递归、container entry 和资源限制风险。

不透明句柄和配对释放的长期边界选择记录在
[`decisions/0001-c-abi-opaque-ownership.md`](decisions/0001-c-abi-opaque-ownership.md)。

本文是 Phase 0 评审稿。符号名、状态码和 options layout 在进入 `Accepted` 前仍可
调整；它们不是当前仓库已经发布的 ABI。正式实现不得直接复制 spike 的
`die_spike_*` 名称或占位 JSON。

## 目标

- 提供可静态链接的 C ABI，作为 C、Go/cgo、CPython extension 和 cffi 的共同
  最低层。
- ABI adapter 只负责参数验证、所有权转换和序列化，不复制扫描逻辑。
- 支持低开销 reusable scanner，也支持不要求调用方管理线程亲和性的 one-shot
  scan。
- 所有跨边界类型、版本、所有权、编码、线程安全和错误行为都有明确契约。
- panic、脚本异常、取消、超时、资源限制和数据库错误均不能变成未定义返回值。
- 同一内部结果模型生成 CLI、JSON 和 FFI 数据，保持确定性。

## 非目标

- 不复刻 Qt/C++ 类、signals/slots、容器或对象继承关系。
- v1 初始版本不暴露 Rust struct、enum、trait object、`String`、`Vec`、future
  或 allocator。
- 不把上游 CLI 的格式化文本当成 C API 数据模型。
- 不在 v1 提供异步 callback、progress callback 或可重入扫描。
- 不承诺 `.a`/`.lib` 会让最终程序完全没有 libc/CRT/操作系统动态依赖。
- 不在结果模型冻结前发布庞大的逐字段 C struct graph。

## 产物与命名

计划发布：

```text
include/die.h
lib/libdiec.a            Unix-like
lib/diec.lib             Windows MSVC
lib/diec_static_crt.lib  可选 Windows static-CRT variant
share/diec/...           固定规则与来源 manifest
```

公共符号以 `diec_` 开头。除版本协商外，首个 major 的功能符号使用
`die_v1_` 前缀，使未来不兼容 major 可以与 v1 同时链接。

静态库文件名不编码 Rust crate 结构。内部 workspace 中 FFI crate 的名称和拆分
不属于 ABI。

## 三种独立版本

以下版本不得混用：

1. **ABI version**：函数、状态码、所有权和 options layout。
2. **Result schema version**：canonical JSON 字段和语义。
3. **Engine/database version**：diec-rust 版本、固定 DIE-engine SHA、规则 SHA、
   规则 manifest hash 和 runtime implementation。

建议编码：

```c
#define DIE_ABI_VERSION_ENCODE(major, minor) \
    ((((uint32_t)(major)) << 16) | ((uint32_t)(minor)))
#define DIE_ABI_V1_0 DIE_ABI_VERSION_ENCODE(1, 0)
```

只保留少量无 major 前缀的协商符号：

```c
uint32_t die_abi_version(void);
uint32_t die_abi_is_compatible(uint32_t requested);
```

状态码解释属于对应 major：

```c
uint32_t die_v1_status_name(uint32_t status,
                             const uint8_t **out_data,
                             uint64_t *out_length);
```

兼容规则：

- `is_compatible(requested)` 仅在 major 相同且 library minor 不小于 requested
  minor 时返回 true；
- major 变化允许破坏 ABI，并增加一套新符号；
- 同 major 的 minor 只允许增加符号、状态码或可选 options 尾字段；
- 不改变既有函数签名、状态数值、字段偏移或所有权；
- patch 是实现/修复版本，不编码进 ABI compatibility；
- 未识别的新增状态码对旧调用方仍是失败，不能被当成成功。

## 公共 C 类型

只使用 `<stdint.h>` 中固定宽度整数、C pointer 和 opaque forward declaration：

```c
typedef uint32_t die_status_t;

typedef struct die_v1_database_builder die_v1_database_builder;
typedef struct die_v1_database die_v1_database;
typedef struct die_v1_scanner die_v1_scanner;
typedef struct die_v1_cancel die_v1_cancel;
typedef struct die_v1_result die_v1_result;
typedef struct die_v1_error die_v1_error;
```

不在 ABI 中使用 C `enum`、bitfield、`long`、`wchar_t`、`size_t`、`bool` 或
compiler-specific packed layout。布尔值使用 `uint32_t` 的 0/1，长度使用
`uint64_t`，转换到 Rust `usize` 前必须检查。

### Scan options

扫描 options 是 v1 唯一计划按值公开的 layout；其字段只包含标量，便于 C/cgo/
cffi 创建并避免每次 scan 的 setter 调用：

```c
typedef struct die_v1_scan_options {
    uint32_t struct_size;
    uint32_t flags;
    uint64_t max_input_bytes;
    uint64_t max_unpacked_bytes;
    uint64_t max_container_entries;
    uint64_t timeout_ms;
    uint32_t max_recursion_depth;
    uint32_t reserved_0;
    uint64_t max_total_allocation_bytes;
    uint64_t script_heap_bytes;
    uint64_t script_stack_bytes;
    uint64_t script_fuel_quanta;
    uint64_t script_deadline_ms;
} die_v1_scan_options;
```

拟定 layout：

| Field | Offset x64 | 语义 |
| --- | ---: | --- |
| `struct_size` | 0 | 调用方实际可读结构长度 |
| `flags` | 4 | deep/heuristic/all-types/递归类别 |
| `max_input_bytes` | 8 | 0 表示项目安全默认值，不表示无限 |
| `max_unpacked_bytes` | 16 | 整次扫描累计解包预算 |
| `max_container_entries` | 24 | 整次扫描累计 entry 预算 |
| `timeout_ms` | 32 | 0 表示默认 timeout |
| `max_recursion_depth` | 40 | 0 表示默认深度 |
| `reserved_0` | 44 | 必须为 0 |
| `max_total_allocation_bytes` | 48 | 0 表示项目安全默认值；全 scan 单调累计 allocation capacity，不表示无限 |
| `script_heap_bytes` | 56 | 0 表示安全默认；per-scan live VM heap |
| `script_stack_bytes` | 64 | 0 表示安全默认；JS VM stack，不含 native stack |
| `script_fuel_quanta` | 72 | 0 表示安全默认；全 scan VM/native cooperative fuel |
| `script_deadline_ms` | 80 | 0 表示安全默认；累计 absolute script deadline |

预期 x64 size 为 88 bytes；32 位和 arm64 必须用 C/Rust 双侧 `sizeof`,
`alignof` 和 `offsetof` 测试确认，不能从 x64 外推。

初始化：

```c
die_status_t die_v1_scan_options_init(
    die_v1_scan_options *options,
    uint32_t options_size);
```

规则：

- 调用方可传 `NULL` 表示全部安全默认值；
- 非 null options 必须先调用 init；
- library 只读取 `min(struct_size, 当前结构大小)`；
- 缺失尾字段使用默认值；
- 大于当前大小的未知尾部必须由调用方置 0；
- unknown flags、非零 reserved 或小于 v1 最小 prefix 返回
  `INVALID_ARGUMENT`；
- 任何 `0 = default` 字段都不能暗中解释成 unlimited；
- unlimited 若未来允许，使用单独 flag/常量并受 policy 控制。
- aggressive compatibility mode 只能在全局 hard cap 内提高预算，不能关闭
  depth、bytes、entry、time 或 allocation 防护。

flag 数值在 `api.md` 完成后冻结，至少区分：

- deep scan；
- heuristic scan；
- all-types scan；
- resource recursion；
- overlay recursion；
- archive recursion；
- aggressive compatibility mode。

目录递归属于 CLI/input enumeration，不与文件内部递归 flag 混为一项。

## 状态码

拟定 v1 固定数值：

| Value | Name | 含义 |
| ---: | --- | --- |
| 0 | `DIE_STATUS_OK` | 成功 |
| 1 | `DIE_STATUS_INVALID_ARGUMENT` | pointer、长度、flag 或状态非法 |
| 2 | `DIE_STATUS_ABI_MISMATCH` | 调用方请求不兼容 ABI |
| 3 | `DIE_STATUS_INVALID_UTF8` | 要求 UTF-8 的输入非法 |
| 4 | `DIE_STATUS_IO` | 文件/目录读取失败 |
| 5 | `DIE_STATUS_DATABASE` | 规则数据库加载或校验失败 |
| 6 | `DIE_STATUS_UNSUPPORTED` | 明确不支持的格式/语法/功能 |
| 7 | `DIE_STATUS_LIMIT_EXCEEDED` | byte/entry/depth/memory 预算 |
| 8 | `DIE_STATUS_CANCELLED` | cancel token 被请求 |
| 9 | `DIE_STATUS_TIMEOUT` | deadline 到期 |
| 10 | `DIE_STATUS_SCRIPT` | 规则 parse/runtime 错误 |
| 11 | `DIE_STATUS_WRONG_THREAD` | thread-affine handle 在错误线程使用 |
| 12 | `DIE_STATUS_BUSY` | scanner 重入或并发调用 |
| 13 | `DIE_STATUS_PANIC` | unwind panic 被边界捕获 |
| 14 | `DIE_STATUS_INTERNAL` | 不满足内部不变量 |
| 15 | `DIE_STATUS_ALLOCATION_FAILED` | 可恢复的 `try_reserve` 等失败 |

状态码只表达稳定类别；不得把 OS error、规则路径或详细诊断编码进整数。
`ALLOCATION_FAILED` 不承诺捕获全局 allocator OOM abort。

## Error handle

每个 fallible API 的最后一个参数统一为可选 `die_v1_error **out_error`：

- 调用前 library 将非 null `*out_error` 清为 null；
- 成功时不产生 error；
- 失败时尽力返回 owned immutable error；
- error allocation 本身失败时仍返回原始 status，允许 error 为 null；
- error message 是诊断文本，不作为程序分支依据。

访问器：

```c
die_status_t die_v1_error_status(const die_v1_error *error,
                                   uint32_t *out_status);
die_status_t die_v1_error_message(const die_v1_error *error,
                                    const uint8_t **out_data,
                                    uint64_t *out_length);
die_status_t die_v1_error_details_json(const die_v1_error *error,
                                         const uint8_t **out_data,
                                         uint64_t *out_length);
die_status_t die_v1_error_free(die_v1_error **in_out_error);
```

message/details 是 UTF-8、非 NUL 结尾、借用到 error free。details schema 单独
版本化，可包含 path、rule、offset、OS code、cause chain 和 script diagnostic。

不使用 global/TLS `last_error`，因为它在 callback、并发、Go goroutine 和 Python
线程间容易被覆盖。

## Database API

数据库加载是昂贵且可失败的独立阶段，不能在每次 scan 隐式执行。

拟定 builder API：

```c
die_status_t die_v1_database_builder_new(
    die_v1_database_builder **out_builder,
    die_v1_error **out_error);

die_status_t die_v1_database_builder_add_path_utf8(
    die_v1_database_builder *builder,
    uint32_t database_kind,
    const uint8_t *path,
    uint64_t path_length,
    uint32_t source_flags,
    die_v1_error **out_error);

die_status_t die_v1_database_builder_build(
    const die_v1_database_builder *builder,
    die_v1_database **out_database,
    die_v1_error **out_error);

die_status_t die_v1_database_builder_free(
    die_v1_database_builder **in_out_builder);

die_status_t die_v1_database_metadata_json(
    const die_v1_database *database,
    const uint8_t **out_data,
    uint64_t *out_length);

die_status_t die_v1_database_free(
    die_v1_database **in_out_database);
```

`database_kind` 明确区分 main、extra、custom；不会复制上游“main 返回值影响调用方、
extra/custom 失败被忽略”的不一致。任一启用来源失败都返回 DATABASE，详细 error
保留来源类别和路径。若 CLI 需要兼容上游错误行为，由 CLI compatibility 层显式
选择和测试，核心/FFI 不静默忽略。

builder 在 `add_path_utf8` 返回前复制并验证 path，不保留调用方 byte pointer。

规则同步要求：

- load 前验证 source manifest、固定 commit 和文件 hash；
- 未知规则语法产生 SCRIPT/UNSUPPORTED diagnostic；
- metadata JSON 包含 ABI-independent engine version、上游 SHA、规则 SHA、
  manifest hash、source 列表和实际启用类别；
- database build 成功后内容逻辑不可变；
- database 不持有 thread-affine JavaScript context；per-context runtime/cache 只属于
  scanner；
- scanner 内部持有数据库共享所有权，因此创建 scanner 后调用方可释放原
  database handle。

后续可按 additive minor 增加 in-memory archive/manifest source；v1.0 不接受
任意 native plugin 或 callback loader。

## Scanner 与两层调用

### Reusable scanner

```c
die_status_t die_v1_scanner_new(
    const die_v1_database *database,
    die_v1_scanner **out_scanner,
    die_v1_error **out_error);

die_status_t die_v1_scanner_scan_bytes(
    die_v1_scanner *scanner,
    const uint8_t *data,
    uint64_t length,
    const die_v1_scan_options *options,
    const die_v1_cancel *cancel,
    die_v1_result **out_result,
    die_v1_error **out_error);

die_status_t die_v1_scanner_scan_path_utf8(
    die_v1_scanner *scanner,
    const uint8_t *path,
    uint64_t path_length,
    const die_v1_scan_options *options,
    const die_v1_cancel *cancel,
    die_v1_result **out_result,
    die_v1_error **out_error);

die_status_t die_v1_scanner_free(
    die_v1_scanner **in_out_scanner);
```

scanner 复用 rule runtime、host binding 和 per-worker cache，适合 C 或显式固定
worker 的绑定。

### Thread-neutral one-shot

```c
die_status_t die_v1_scan_bytes(
    const die_v1_database *database,
    const uint8_t *data,
    uint64_t length,
    const die_v1_scan_options *options,
    const die_v1_cancel *cancel,
    die_v1_result **out_result,
    die_v1_error **out_error);

die_status_t die_v1_scan_path_utf8(
    const die_v1_database *database,
    const uint8_t *path,
    uint64_t path_length,
    const die_v1_scan_options *options,
    const die_v1_cancel *cancel,
    die_v1_result **out_result,
    die_v1_error **out_error);
```

one-shot 在调用线程创建并销毁内部 scanner，避免 runtime thread-affinity 泄漏给
Go/Python，代价是每次扫描有初始化成本。它必须调用与 reusable scanner 相同的
内部 scan service，不得复制检测逻辑。

path API 只接受 UTF-8 bytes；不依赖 NUL，包含 NUL byte 时返回
`INVALID_ARGUMENT`，允许路径中除 NUL 以外的 Unicode。
Unix 非 UTF-8 native path 不由 v1 path API 表达，调用方可自行打开文件并用
scan-bytes。Windows adapter 使用 checked UTF-8→UTF-16 转换。

scan 是同步调用。输入 bytes 只借用到函数返回；实现不得在返回后保留 pointer。
若未来提供 streaming 或 async，使用新 opaque handle/symbol，不改变这一契约。

## Cancellation

```c
die_status_t die_v1_cancel_new(
    die_v1_cancel **out_cancel,
    die_v1_error **out_error);
die_status_t die_v1_cancel_request(die_v1_cancel *cancel);
die_status_t die_v1_cancel_reset(die_v1_cancel *cancel);
die_status_t die_v1_cancel_free(die_v1_cancel **in_out_cancel);
```

cancel token 是唯一明确可由其他线程调用的 mutable handle，内部使用 atomic
state。scanner 在格式解析、规则执行、container entry 和大循环的受控点检查；
runtime interrupt handler 也映射到同一 token/deadline。

reset 只能在没有 scan 引用 token 时调用。request 可重复且幂等。取消后返回
`CANCELLED`，部分 detection 不作为成功 result 返回；详细 error 可以报告停止阶段。
scan 的 cancel 参数允许为 null，此时仍执行 options 中的 timeout 和其他资源预算。

## Result handle

初始稳定结果面采用 immutable result + canonical JSON：

```c
die_status_t die_v1_result_json(
    const die_v1_result *result,
    const uint8_t **out_data,
    uint64_t *out_length);

die_status_t die_v1_result_free(
    die_v1_result **in_out_result);
```

契约：

- JSON 是 UTF-8、非 NUL 结尾；
- pointer 借用到 result free，不允许调用方释放或写入；
- canonical JSON 在 scan 成功并转移 result 前完成有界生成；accessor 不再分配，
  后续地址和 bytes 不变；
- schema version 是顶层必需字段；
- 保留文件级元数据、完整 detection tree、parent relation、offset/size/file part、
  rule metadata、errors/debug/handlers 和 resource-limit metadata；
- 数组顺序和字段语义由 `api.md` 与 `testing.md` 定义，序列化必须确定；
- 不把 CLI filename prefix、颜色、表格或上游无效多文档 JSON 混入结果。

初始 v1 不发布逐 record flat struct。待内部结果模型和 schema 通过差分评审后，
可以在同 major 增加只读 typed accessors；JSON API 不因此移除。

## 通用 output 规则

所有函数遵守：

- 必需 output pointer 为 null：返回 `INVALID_ARGUMENT`；
- non-null output 在任何后续工作前初始化为 null/0；
- 成功才转移 owned handle；
- 失败不得同时返回可用 result；
- output pointers 不得与输入 handle storage 或彼此非法 alias；
- length 为 0 时 byte pointer 可以为 null；
- view 不保证 NUL terminator，调用方不得调用 `strlen`；
- free 接收 pointer-to-pointer，先置 null 再 drop；
- null handle variable 的 free 成功，null outer pointer 失败；
- stale copy、伪造 pointer、use-after-free 和 invalid readable/writable range 仍是调用方
  UB，ABI 无法通过 null check 使任意 pointer 安全。

## 句柄状态机

```text
database builder: Mutable --build--> Mutable --free--> Dead
database:         Immutable -------------------------> Dead
scanner:          Idle --scan--> Scanning --return--> Idle --free--> Dead
cancel:           Clear --request--> Requested --reset--> Clear --free--> Dead
result/error:     Immutable -------------------------> Dead
```

约束：

- builder 不得在 build 期间修改或并发使用；
- scanner 在 Scanning 状态重入返回 BUSY；
- scanner free 只允许 Idle；
- result/error/database 的 read accessor 可并发读取，但 free 不得与任何 read 竞争；
- successful scanner creation 持有自己的 database reference；
- free 不因业务错误失败；返回 status 只用于非法 outer pointer 或边界 panic。

## 线程模型

规则 runtime 尚未冻结，且 Boa `Context` 与 QuickJS context 的 Send/Sync 模型不同。
v1 采用可由所有候选实现的保守契约：

- database build 后 immutable，可用于并发创建 scanner；调用方不能同时 free；
- reusable scanner 绑定到创建它的 OS thread；
- scanner 的 scan/free 只能在该线程且不可并发/重入；
- 错误线程返回 `WRONG_THREAD`，不接触 runtime state；
- one-shot scan 不绑定跨调用 thread state，推荐给 Go/Python；
- cancel request 是 thread-safe；
- result/error immutable read 可并发，生命周期同步由调用方负责。

Go reusable binding 必须使用专用 goroutine + `runtime.LockOSThread`，或把所有调用
发到 native worker；不能假设 goroutine 固定在线程。Python binding 默认暴露
one-shot；若释放 GIL 扫描，仍要保证 reusable scanner 的创建/调用/销毁在同一
native worker。

若最终 runtime 可安全跨线程移动，只能通过新的 capability/query 和 additive
API 放宽；不能让 v1 调用方依赖未声明行为。

## Panic、异常与 native fault

每个可能 unwind 的导出函数最外层使用 `catch_unwind(AssertUnwindSafe(...))`，
并编译为 `panic = "unwind"`：

- 捕获后返回 PANIC；
- result 清空；
- 尽力生成 error；
- panic payload 不跨 ABI；
- Drop/cleanup 必须保持 handle 状态一致。

这不是完整 crash sandbox：

- `panic=abort`、allocator OOM abort、stack overflow、SIGSEGV/SEH/native C crash
  不保证可恢复；
- 用户或宿主安装的 panic hook 会在 catch 前运行，可能输出、panic 或终止；
- library 不替换进程全局 panic hook；
- runtime/native parser 的 hard fault 需要 sanitizer、fuzz 和可选 process
  isolation 解决。

正式代码以“不 panic”为首要不变量；catch 是边界保险而不是正常 error flow。

## Allocator 策略

v1 不接受 caller allocator callback：

- allocator callback 会引入 alignment、realloc、unwind、thread 和 module CRT
  组合风险；
- static library 可能与宿主使用不同 CRT；
- opaque handle 已避免跨 allocator free。

所有 Rust-owned allocation 通过对应 `die_v1_*_free` 释放。借用 view 无释放函数。
输入驱动的大分配优先使用 checked arithmetic 与 `try_reserve`，可恢复失败映射为
`ALLOCATION_FAILED`；仍不承诺捕获全局 OOM abort。

若未来需要 caller-owned output，优先增加“两次调用获取长度 + caller buffer”
的新函数，而不是替换 v1 ownership。

## 静态链接策略

FFI crate 使用 `crate-type = ["staticlib"]`，核心 crate 不依赖 FFI crate。

每个发布 target 必须附带：

- archive hash 和 Rust/toolchain version；
- `rustc --print native-static-libs` 原始结果；
- C compiler/linker version；
- CRT/libc 模式；
- 最小 C consumer 的完整 link command；
- 最终 executable 的 `dumpbin /dependents`、`ldd`、`otool -L` 或等价报告；
- 许可证与归属清单。

已验证基线：

| Target | Archive | C runtime | 额外要求 |
| --- | --- | --- | --- |
| `x86_64-pc-windows-msvc` | `diec.lib` | `/MD` | VC/UCRT DLL + Windows system libs |
| `x86_64-pc-windows-msvc` | static-CRT variant | Rust `+crt-static`, C `/MT` | Windows system DLL |
| `x86_64-unknown-linux-gnu` | `libdiec.a` | glibc | `libgcc_s`, libc, loader |

未验证 target 不进入支持矩阵。macOS、Windows GNU、Linux musl、arm64 和 32 位
必须分别 smoke test；`.a` 不能被描述为 fully-static，除非最终 consumer 的依赖
审计证明。

公共 release 默认提供动态 CRT MSVC 还是双 variant，将在发布/供应链设计中决定；
不同 CRT variant 必须使用不同文件名，禁止静默覆盖。

## C、Go 与 Python 消费

### C

C 直接包含 `die.h` 并链接 archive。发行包提供：

- 最小 scan/free 示例；
- C11 `-Wall -Wextra -Werror` / MSVC `/W4 /WX` smoke；
- debug/release 和 CRT link command；
- status/error 处理示例。

### Go

Go 使用 cgo 链接 `.a`/`.lib`。binding：

- 默认调用 one-shot；
- 用 `runtime.KeepAlive` 保证借用 input 生命周期；
- 立即复制 result JSON 到 Go memory，再 free result；
- reusable 模式使用 locked OS-thread worker；
- cancel token 可由另一 goroutine request；
- 不让 C pointer 进入长期 Go heap object，遵守 cgo pointer rules。

### Python

Python 不能直接 `import` 或用 `ctypes.CDLL` 加载静态 `.a`/`.lib`。支持方式是：

- CPython limited-API extension；
- 或 cffi out-of-line extension；
- 两者在构建时把 staticlib 链入 `.so`/`.pyd`。

若另行发布 shared library，ctypes 才可直接加载；shared library 不是静态交付目标的
替代。Python wrapper：

- 默认 one-shot；
- 扫描期间可释放 GIL；
- 返回前复制 JSON 到 Python bytes；
- 用 capsule/finalizer 作为异常路径保险，但显式 free 仍需测试；
- exception type 由稳定 status 决定，message 只用于展示。

## Header 与实现同步

初始 ABI 面较小，采用手写 C header；不把 cbindgen 生成结果未经审计直接发布。
CI 必须防止 header/Rust 漂移：

- C 与 C++ 编译 header；
- Rust/C 双侧验证 options `sizeof/alignof/offsetof`；
- symbol inventory 与 allowlist 精确相等；
- 每个 status/flag 数值双侧相等；
- 32/64 位 target 都做 layout test；
- release archive 不意外导出未前缀符号；
- header 变更触发 ABI compatibility diff。

## 安全要求

- 所有长度先转换/相加检查，再创建 slice 或分配。
- path UTF-8 校验后再做平台转换；不使用隐式 locale/codepage。
- 不信任 options `struct_size`、flags、reserved 或 pointer。
- database manifest/hash 在执行规则前验证。
- 资源预算覆盖输入、映射、解包累计 bytes、entry、depth、脚本 heap/stack/
  instruction/deadline。
- 未知规则语法不能静默跳过，返回可定位 diagnostic。
- FFI 层不拥有扫描算法，也不绕过核心安全 reader。
- error/result 序列化必须有 size limit，防止诊断本身无界增长。

## 验收矩阵

正式 ABI 进入 Accepted/稳定发布前至少通过：

| 范围 | 验证 |
| --- | --- |
| Header | C11、C++17、MSVC/GCC/Clang，warnings-as-errors |
| Layout | x86_64/arm64，计划支持 32 位时增加 32 位 |
| Link | Windows `/MD`、`/MT`，Linux GNU/musl，macOS |
| Symbols | exact allowlist、ABI diff、无 Rust mangled public API |
| Ownership | success/error、1000+ loop、null free、failure cleanup |
| Invalid C | null、oversize、alias misuse 的可检测子集 |
| Panic | unwind catch、hook 输出、post-panic continued call |
| Thread | wrong-thread、BUSY、cancel race、read/free synchronization tests |
| Result | canonical JSON schema、确定性、完整树和错误 |
| Differential | 同一固定上游 SHA/规则 SHA 的扫描结果 |
| Go | cgo one-shot、locked reusable、cancel、race detector |
| Python | CPython/cffi extension、GIL、exception、lifetime |
| Sanitizer | ASan/UBSan/LSan；native runtime 适用时启用 |
| Fuzz | raw FFI argument harness + core byte-input fuzz |
| Dependencies | native-static-libs 与最终 binary dependency report |

## 开放问题与冻结门禁

以下问题解决前本文不能改为 Accepted：

- `api.md` 冻结内部 result/error/resource model 和 canonical JSON schema。
- 规则 runtime ADR 决定 scanner 的实际创建成本、thread affinity 和 interrupt。
- 确认 v1 是否需要 path API，还是只保留 bytes/reader bridge。
- 确认 typed result accessor 是否进入 v1.0 或作为 additive v1.1。
- 确认数据库 source builder 的 archive/in-memory 支持范围。
- 确认默认 MSVC CRT variant 与分发文件名。
- 在 Go 与 Python 原型中验证 one-shot 性能是否可接受。
- 完成 macOS、musl、arm64 和 C++ consumer spike。
- 对状态码、flag 数值、options layout 和 symbol inventory 进行设计评审。

## Phase 1/5 实施顺序

1. 先实现内部 result/error/options，不建立公共导出。
2. 建立 private FFI adapter 与 C header drift tests。
3. 实现 database/result/error/cancel 基础句柄。
4. 实现 one-shot bytes scan；以固定 oracle 做端到端差分。
5. 接入选定 runtime 后实现 thread-affine reusable scanner。
6. 完成 C consumer 和 sanitizer。
7. 完成 Go/Python extension 原型。
8. ABI review 后才将 status/layout/symbol 标记稳定。
