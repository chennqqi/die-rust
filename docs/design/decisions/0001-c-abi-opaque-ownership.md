# ADR 0001：C ABI 使用不透明句柄和配对释放

Status: Accepted
Last updated: 2026-07-31
## Context

diec-rust 需要同时供 C、Go 和 Python 使用，并提供 Unix `.a` 与 Windows `.lib`。
内部结果包含 detection tree、错误、debug、handler 和嵌套 file-part，尚未冻结为
公共 Rust model。Rust 与调用方可能使用不同 allocator/CRT；规则 runtime 还可能
带有 thread affinity。

Phase 0
[`C static-link spike`](../../research/c-static-link-spike.md) 已在 Windows MSVC
动态/静态 CRT 和 Linux GNU 中验证：

- opaque result handle；
- 借用 JSON byte view；
- Rust 配对 free；
- pointer-to-pointer 释放并置 null；
- 1000 次生命周期；
- panic containment。

## Decision

Proposed：C ABI 的 owned object 使用 opaque handle，不公开 Rust layout。每类
owned handle 都有配对的 Rust free 函数，free 接收 pointer-to-pointer，先置 null
再销毁。

初始 v1 result/error 通过 immutable handle 提供借用 UTF-8 byte view；调用方不能
用自己的 allocator 释放 view 或 handle。只有经过单独 layout review 的纯标量
options struct 可以按值公开，并使用 `struct_size` 做 additive extension。

初始 v1 同时提供：

- thread-neutral one-shot scan；
- 可复用、不可重入且保守 thread-affine 的 scanner handle。

两层入口调用同一个内部 scan service。

## Alternatives considered

### 暴露完整 C struct graph

优点是 C 可直接遍历字段，少一次 JSON 解析。缺点是当前结果模型未冻结，嵌套数组、
optional/string ownership 会迅速扩大 ABI，且每次字段变化都可能破坏 layout。

结论：v1.0 不采用；未来可添加只读 typed accessors，不移除 JSON。

### 返回 caller 使用 `free()` 释放的字符串

接口表面简单，但 Rust staticlib、宿主和 Windows CRT variant 可能使用不同 heap。
跨 CRT free 会造成未定义行为。

结论：拒绝。

### 接受 caller allocator callback

可统一 allocation ownership，但引入 alignment、realloc、callback panic、并发、
Go pointer rules 和 Python runtime 生命周期风险。

结论：v1 不采用；有真实性能证据后另建 ADR。

### 只提供 canonical JSON，不返回 handle

可以返回 caller buffer 或两次调用长度，但 error/result 缓存、未来 typed accessor
和大结果生命周期受限。

结论：JSON 是初始稳定数据面，但由 opaque result 持有。

### 只提供 reusable scanner

初始化成本低，但 runtime thread affinity 会泄漏给 Go goroutine 和普通 Python
调用方。

结论：同时提供 one-shot。

### 只提供 one-shot

线程模型简单，但规则数据库/runtime 初始化可能成为主要性能成本，C 服务无法建立
worker pool。

结论：同时提供 reusable scanner。

### TLS/global last-error

减少函数参数，但 callback、并发和语言 runtime 会覆盖错误，生命周期也隐式。

结论：使用显式 owned error handle。

## Consequences

正面：

- Rust 内部 layout 和 allocator 不进入 ABI。
- result/error 可以在不破坏 ABI 的情况下增加内部字段。
- pointer-to-pointer free 降低同一变量重复释放风险。
- C、cgo 和 CPython extension 使用同一所有权模型。
- one-shot 与 reusable scanner 覆盖易用性和性能两类调用方。

代价：

- C 调用方必须管理 handle 和配对 free。
- JSON-first 对高频逐字段访问有解析成本。
- stale pointer copy、伪造 pointer 和并发 free 仍无法自动防止。
- thread-affine reusable scanner 需要 Go/Python binding 提供 worker abstraction。
- 每类 handle 增加 symbol 和生命周期测试。

## Evidence

- [`../c-abi.md`](../c-abi.md)
- [`../../research/c-static-link-spike.md`](../../research/c-static-link-spike.md)
- [`../../research/source-analysis.md`](../../research/source-analysis.md)
- `spikes/c-static-link/include/die_spike.h`
- `spikes/c-static-link/c/smoke.c`

## Decision acceptance

Phase 0 评审确认以下决策方向：

- opaque handle、paired pointer-to-pointer free 和 JSON-first v1 result boundary
  作为 C ABI 初始稳定面；
- one-shot 与 reusable scanner 两层入口共用同一内部 scan service；
- spike 已在 Windows MSVC 动态/静态 CRT 和 Linux GNU 验证 opaque handle、
  借用 byte view、配对 free、1000 次生命周期和 panic containment。

评审结论：决策方向 Accepted，实现期门禁如下。

## Implementation exit

以下条件在 Phase 1+ 满足后才能视为完整交付：

- `api.md` 接受 result/error/resource model；
- C/C++/Go/Python consumer 都验证 opaque ownership；
- sanitizer 覆盖 success/error/panic cleanup；
- thread-affinity 与最终规则 runtime 一致；
- 评审确认 JSON-first 足以作为 v1.0 稳定结果面；
- 正式 header 和 symbol inventory 通过 ABI diff。
