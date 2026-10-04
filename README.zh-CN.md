# die-rust

[Detect It Easy](https://github.com/horsicq/DIE-engine) (DIE) 的 Rust 重写。

[English](README.md)

> **v1.0.0** — 首个稳定版本。检测覆盖率与输出格式对齐 pin 住的上游
> 基线，有意偏离项均有 ADR 记录（见 `docs/design/decisions/` 与
> `COMPATIBILITY.md`）。

## 为什么

目标是与上游 DIE 兼容 — 相同的检测能力、相同的规则语义、相同的输出格式 —
加上 Rust 的内存安全和多语言绑定。

## 项目原则

- **AI 开发、AI 测试**：本项目由 AI 开发、AI 测试，不承诺人工测试；
  欢迎反馈 BUG。
- **尽力兼容**：不承诺与上游原版 1:1 行为一致，但会以兼容为主要目标。
- **选择性合并 PR**：不承诺接受所有 PR；默认仅合入与上游功能对齐的
  改动。

## 核心优势

- **DIE 兼容**：通过 rquickjs 运行时原样加载上游规则；PE/ELF/MACH host API
  桥接实现了最常用的方法
- **Rust 安全**：核心层零 `unsafe`，FFI 边界 panic 隔离，畸形输入不崩溃
- **性能**：并行数据库加载（比顺序加载快 3 倍），格式探测亚微秒级
- **多语言绑定**：C ABI + Go/cgo + Python ctypes

## 已知限制

已记录的有意偏离项（各 ADR 见 `docs/design/decisions/`）：

- **NFD/SpecAbstract 引擎为部分实现**：签名匹配核心、dispatch 表与常用
  handler 已实现；version-resource FileDescription 链显式 deferred
  （Phase 21）。
- **反汇编架构**：对齐集合之外的架构支持经复审后 deferred（Phase 30）。
- **SSDeep**：parity 用途已否决（ADR 0039）；TLSH 已实现。
- **归档安全上限**：提取限制有意比上游更严格，且可配置（ADR 0030）。
- **XStyles / InfoDB**：平台主题差异与 JSON sidecar 存储为永久偏离
  （ADR 0037+）。

## 已知差异（非缺陷）

- **规则版本差异**：4 个语料样本的检测结果多于上游 DIE 3.21，因为 vendored
  规则数据库比上游 3.21 自带规则更新。详见 `COMPATIBILITY.md` § Mismatch
  Details。这些不是引擎 bug。
- **结果去重**：`--alltypes` 模式默认对结果去重（上游不去重）。使用
  `--no-dedup` 可匹配上游行为。详见 ADR 0027。
- **RAR 归档解包**：上游 XArchive 的 RAR decoder 是 UnRAR 源码的近逐字翻译
  （94.21% token 覆盖率，跨 17 个 UnRAR 源文件），但标注 MIT 许可证时未保留
  UnRAR license 对修改源码分发要求的 notice 和 acknowledgments。出于许可证
  合规，die-rust **不复制、翻译或改写**上游 RAR decoder。RAR 成员解包改用
  `rars`（WTFPL），一个独立的纯 Rust RAR 实现。由于实现独立，RAR 解包行为
  在边缘场景（如 CAB LZX/Quantum 方法、加密归档、损坏头部）可能与上游有差异。
  详见 `docs/research/rar-decoder-provenance.md`（上游来源审计）和
  ADR 0029（`rars` 选型决策）。

## Benchmark

数据库加载：**160ms**（并行）vs **480ms**（优化前顺序）— **3 倍提升**。
格式探测：**60-407ns** 每文件。

测试方法和原始数据：[tools/benchmark/](tools/benchmark/) ·
[benchmark_results.json](tools/benchmark/results/benchmark_results.json)

复现：
```sh
python tools/benchmark/run_benchmarks.py --quick
```

## 兼容性

**1056 个测试通过**，上游规则加载，28 个基线 + 20 个边缘语料验证 —
无崩溃、无误检、无挂起。

与上游 DIE 3.21 差分测试：
- diec.exe 自身检测：**5/5 完全匹配**（linker、compiler、tool、debug data、C/C++ runtime）
- 6 个大型系统 DLL（0.5-61MB）：**6/6 完全匹配**
- 28 文件语料：17/28 匹配（剩余差异为规则版本差异和 format 类型去重行为差异）

测试方法和原始数据：[tools/benchmark/](tools/benchmark/) ·
[compatibility_results.json](tools/benchmark/results/compatibility_results.json)

复现：
```sh
python tools/benchmark/run_compatibility.py
python tools/compat/compare_upstream.py
```

## 快速开始

```sh
git clone https://github.com/chennqqi/die-rust.git
cd die-rust && cargo build --workspace --release
./target/release/diec --alltypes file.exe
```

Python / Go / C 绑定：见 [README.md](README.md) 或 [bindings/](bindings/)。

## 许可证

MIT — 与上游一致。详见 [NOTICES.md](NOTICES.md)。
