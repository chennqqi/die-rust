# Phase 18+：上游遗留差距补齐路线 — deferred 项分解

Status: Draft（规划，未立项实施）
Last updated: 2026-10-02

## 目标

Phase 17 显式 deferred 的项目按"阻塞原因 × 可落地性"重新分阶段。原则：

1. **纯 Rust 无阻塞的先做**（demangle 剩余模式、CAB/ISO9660）
2. **需要依赖/许可证决策的先评估再立项**（SSDeep/TLSH、BZ2/XZ、capstone）
3. **架构级功能各自独立成 Phase**（InfoDB、静态脱壳、NFD）
4. 每项保留 ADR 链接，立项前必须先满足前置条件（Gate）

## 分层视图

| 项 | 阻塞原因 | 目标 Phase | Gate |
|----|---------|-----------|------|
| Demangle 剩余 8 模式 | 仅工作量 | **18.A** | 无 |
| CAB/ISO9660 归档 | 引擎无实现，纯 Rust 可写 | **18.B** | 无 |
| BZ2/XZ/LZMA 裸流 | 依赖选型待评估 | **18.C** | 纯 Rust 实现成熟度评审 |
| SSDeep/TLSH 模糊哈希 | native 依赖或纯 Rust 移植 | **18.C** | 依赖评估 + ADR |
| 反汇编新架构 | capstone-rs native 依赖 | **18.D** | ADR（native vs 纯 Rust 库） |
| InfoDB 注释/书签 | 存储 schema + 跨视图 API | **19** | ADR 0037 复审通过 |
| 静态脱壳 | 逐 packer + 真实语料 | **20** | UPX 语料与 oracle 就绪 |
| NFD 引擎 | 第二套引擎 + 规则许可证 | **21** | specabstract 许可证审计 |
| 多语言 17 种 | 需人工校验 | 持续 | ADR 0038，按需增量 |
| XStyles 主题生态 | 纯样式生态 | 不做 | — |

## Phase 18：纯 Rust 无阻塞补齐

### 18.A Demangle 剩余模式（上游 XDemangle 的 8 个未实现模式）

当前 `demangle.rs` 枚举已注册以下模式但返回原串。按上游
`detectMode`/`xdemangle.cpp` 逐一实现精简解码：

| 模式 | 特征前缀 | 实现策略 | 预估工作量 |
|------|---------|---------|-----------|
| Swift | `$s`/`$S` | `symbolic-demangle`（MIT，含 Swift）或自实现 `$s<module><name>` 基础解码 | 中 |
| Go | `go.`/`type:`/`main.`/`go:`, reflect 类型串 | 自实现（Go 符号非严格 mangling，主要是命名空间还原） | 小 |
| GNAT (Ada) | `_ada_`/`___` | 自实现 `___<name>` + `*_clean`/`initialize` 后缀 | 小 |
| GNU v2 | `__<len><name>`（无 `_Z`） | 自实现 g++ 2.x 旧格式（长度前缀 + `__<sig>` 参数编码） | 中 |
| Haskell | `_ZC`/`.text:..._info` GHC 符号 | 自实现 `ZC<mod>_<name>`/`c<len>` 编码 | 小 |
| OCaml | `caml<Module>__<name>_<id>` | 自实现，几乎是纯文本切分 | 极小 |
| Tru64 (Compaq C++) | `__<name>__<sig>`（无 `_Z`） | 自实现 `name__args` 分隔格式 | 中 |
| SunPro (Sun C++) | `__0`/`__1` 前缀 | 自实现 `__1<sig>` 格式 | 中 |

**策略说明**：8 个模式全部走"前缀识别 → 结构化解码"自实现，
不追求上游 100% 语义（上游自身部分模式也只输出 name+args）。
每个模式 ≥3 个真实样本测试向量（从上游 `xdemangle.cpp` 的
测试注释或真实二进制符号提取，不抄实现代码）。

**验收**：`detectMode` 输出与上游逐模式一致（可用上游二进制
`diec`/`die` GUI 的 Demangle 对话框做 oracle）；新增模式无 panic；
COMPATIBILITY.md 模式矩阵更新。

### 18.B CAB / ISO9660 归档支持

引擎 `archive_unpack.rs` 扩展：

| 格式 | 实现 | 说明 |
|------|------|------|
| CAB | `cab` crate（MIT，纯 Rust）或自实现 MSZIP/LZX 头 | 列表先行，提取视 crate 解码器完整性 |
| ISO9660 | 自实现 PVD + 目录记录遍历 | 纯只读目录遍历，量小 |

完成后 GUI `list_archive`/`extract_archive_member` 自动获得新格式
（probe 层已有 `CabProbe`/`Iso9660Probe`），前端零改动。

**验收**：CAB/ISO 样本列表与上游 `list` 一致；嵌套扫描
`--archives` 覆盖两种新格式；畸形镜像负向测试。

### 18.C 模糊哈希与裸压缩流（评估 → ADR）

1. **SSDeep**：上游用 libfuzzy（C）。Rust 选型：
   - `ssdeep` crate —— libfuzzy native 绑定 ❌（违反纯 Rust 偏好）
   - `fuzzyhash-rs`/自实现 spamsum —— 算法公开、量中（~500 行）
   - **决策项**：自实现 vs native vs deferred → ADR
2. **TLSH**：上游用 tlsh（C++）。纯 Rust 有 `tlsh` crate 移植版
   （成熟度待验证）。同上评估。
3. **BZ2/XZ/LZMA 裸流**：`lzma-rs`（纯 Rust LZMA/XZ）与
   `bzip2-rs`（纯 Rust decode）成熟度评估；通过则在
   `archive_unpack` 加裸流解压路径。

**验收**：每项产出结论（实现/不实现+理由）；实现的项带
RFC/官方向量测试。

### 18.D 反汇编架构扩展（评估 → ADR）

现状 iced-x86 + yaxpeax-arm。上游 XCapstone 覆盖 ~15 架构。

选型：`capstone` crate（capstone-sys native）vs `yaxpeax-*` 纯 Rust
系列（yaxpeax-mips/ppc/sparc/rx 等，覆盖不齐）vs 维持现状。

**Gate**：先确认下游用户真实需求（MIPS/PPC 固件样本占比），
再决定 native 依赖。产出 ADR，不直接编码。

## Phase 19：InfoDB（ADR 0037 复审）

**Gate**：ADR 0037 复审确认分析师工作流需求成立。

设计草案要点（立项时细化）：

- 存储：`tauri-plugin-sql`（SQLite，per-file db）vs 旁车
  `<file>.diec.json` —— 上游用 SQLite，倾向对齐
- Schema：`bookmarks(offset, note, color)`、`comments(offset, text)`、
  `labels(address, name)`，file_id = SHA256 内容寻址
- API：`add/remove/list` 三操作 × 三类条目，Tauri 命令薄适配
- UI：Hex/Disasm 右键 "Add comment/bookmark"；offset 行渲染注释列
- 失效：文件内容变更（hash 不匹配）时标记孤儿条目不删除

## Phase 20：静态脱壳（逐 packer 立项）

**Gate**：每类壳先有 ≥3 个真实打包样本 + 上游 `die` GUI Unpack
输出的对照 oracle。

顺序建议（按样本可得性）：

1. UPX（开源壳，可自造样本，上游 xupxdecoder 语义清晰）
2. ASPack / PECompact（需找历史样本）
3. 其余按需求驱动

单 packer = 一个子任务（stub 识别 → dump → import 重建），
不做通用脱壳器。

## Phase 21：NFD 引擎（最大遗留项）

**Gate**：specabstract 规则库许可证审计通过 + 独立 Phase 预算批准。

范围（若立项）：

1. `die-nfd` crate：SpecAbstract 规则解析（其格式与 DIE 规则
   不同，是二进制 signature + 结构匹配）
2. 引擎集成：scan pipeline 第二 pass，results 标 `engine=nfd`
3. GUI：恢复 `nfd_enabled` + scan engine selector 合并（upstream
   `comboBoxScanEngine` 形态）

工作量预估：接近 DIE 引擎移植本体（Phase 3 级别），不拆进
其它 Phase。

## 持续项（不设 Phase）

- **多语言**：ADR 0038 — 收到经审校的语言 JSON 即加入，不设里程碑
- **XStyles 主题**：不移植（非功能差距）

## 执行顺序建议

```
18.A demangle  ← 无依赖，最先做（收尾上游模式矩阵）
18.B CAB/ISO   ← 无依赖
18.C/18.D      ← 评估类，产出 ADR 即可
19/20/21       ← 各自 Gate 触发，互不依赖，可并行推进
```

## 退出条件（Phase 18）

- demangle 8 模式解码正确 + Auto 探测对齐（上游 oracle 差分）
- CAB/ISO9660 `list_archive`/`extract_archive_member` 可用
- 18.C/18.D 各产出 ADR（实现或 deferred 均有记录）
- `cargo fmt/clippy/test` 全绿 + 前端 build + 矩阵文档更新
