## 2026-10-05 Phase 18 实施分析

18.A：8 个精简解码器走"前缀识别→结构化还原"，修 4 处 bug（GNU v2 的
F 标记撞类名、Go 多字节按字节推、SunPro 长度编码 off-by-one、GNAT
测试期望错误）。18.B：CAB 选 `cab` 0.6（MIT、成熟）；ISO9660 自实现
PVD+目录记录遍历（深度≤8、条目≤65536）避免引入年轻 crate。18.C：
SSDeep 因 libfuzzy GPL-2.0 拒绝；TLSH 纯 Rust 移植 2021 年停更暂缓；
BZ2/XZ/LZMA 用 `bzip2-rs`+`lzma-rs` 实现（xz2/bzip2 native 拒绝，
liblzma 曾有 CVE-2024-3094 供应链事件）。18.D：crates.io 无 PPC
解码器、RISC-V 仅 `rvdasm` 等年轻实现、yaxpeax-mips 停更，capstone
native 是唯一全架构路径——deferred。全量验证 fmt/clippy/test/前端
build 全绿。
