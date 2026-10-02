# Phase 21 剩余项归化：NFD/SpecAbstract 收尾规划

> 状态：草案（2026-10-08）。Phase 21.A–I 已完成（codegen、通用 pass、
> 8 格式 dispatch、PE handle_* 第一批~第三批）。本文档把剩余
> deferred 项按依赖关系归化为可独立立项的批次。

## 剩余工作量盘点（按上游行数）

| handler（nfd_pe.cpp） | 行数 | 状态 |
|---|---|---|
| `handle_Protection` | 1651 | 未移植（最大单块） |
| `handle_Microsoft` | 676 | 已移植非 Rich 子集；Rich→工具描述链 deferred |
| `handle_FixDetects` | 584 | 未移植（后置去重/抑制） |
| `handle_Installers` | 563 | 未移植 |
| `handle_NETProtection` | 326 | 未移植 |
| `handle_VisualBasicCryptors` | 319 | 未移植 |
| `handle_DelphiCryptors` | 281 | 未移植 |
| `handle_wxWidgets` | 264 | 未移植 |
| `handle_UnknownProtection` | 201 | 未移植（兜底启发） |
| `handle_PrivateEXEProtector` | 68 | 未移植 |
| `handle_Tools` 残余 | ~80 | AutoIt 2.XX 版本资源分支等 |
| `handle_GCC`/`handle_Borland`/… | — | ✅ 已移植（21.H/21.I） |

## 缺失的共享原语（先行项，解锁多个 handler）

| 原语 | 解锁项 | 说明 |
|------|--------|------|
| **VS_VERSIONINFO 解析** | AutoIt 2.XX（`getResourcesVersionValue("FileDescription")` + `getFileVersionMS`）、安装器/工具的版本资源分支 | 资源树 type=16 leaf → `VS_VERSION_INFO` → StringFileInfo 键值。纯解析器，bounded 实现 ~150 行 |
| **.NET metadata US heap**（`#US` stream 用户字符串） | `mapDotAnsiStringsDetects` 门控的全部分支（`handle_NETProtection` 主体、`handle_Borland` 的 Delphi.NET 分支、dotNet 工具链） | 需解析 CLI header → metadata root → stream header → `#US` blob 堆。有界 |
| **Rich→工具描述表** | `handle_Microsoft` 剩余 600 行（Rich compid→编译器/工具描述） | `xpe.cpp` 的 MS-Rich 描述表 codegen（与 nfd_codegen 同流程） |
| **entropy/EP 节属性原语** | `handle_UnknownProtection`（启发式兜底）、`handle_Protection` 若干分支 | EP 节可读/可写/熵判定 |

## 批次划分

### 21.J — 共享原语层（先做，无争议）

1. `VS_VERSIONINFO` 解析器（`pe_version.rs`）：`FileVersionMS`、
   `StringFileInfo` 键查询、多语言表遍历。
2. `#US` heap 提取 + `dotAnsiStrings` scan map（`stringScan` 复用，
   `PE_DOTNETANSISTRING_RECORDS`/`PE_DOTNETUNICODESTRING_RECORDS`
   表已生成）。
3. Rich 描述表 codegen（`tools/nfd_codegen.py` 扩展或专用提取器）。

验收：原语单测 + 无回归。

### 21.K — 安装器/SFX 组（高价值、表驱动为主）

- `handle_Installers`（InnoSetup/NSIS/WISE/InstallShield/Ghost/
  Gentee/BitRock/CreateInstall 等）：绝大多数是 overlay/header/
  import/资源名 map 命中 → installer 记录 + 版本补全；Inno 卸载器
  需 `0x30` 处 `"Uninstall"` dword + 深扫分支。
- `handle_SFX`：RAR/ZIP/7z/CAB/WinZip/UPX SFX — overlay 与
  section-name detect 组合。
- `handle_wxWidgets`（264 行）：`.rdata`/imports wxWidget 标记 +
  版本串。

依赖：21.J 的 version-resource 原语（部分安装器分支）。

### 21.L — .NET 保护组

- `handle_NETProtection`（326 行）：dotAnsiStrings/detects →
  ConfuserEx/Obfuscar/Dotfuscator 等记录。
- `handle_Borland` 的 `EMBARCADERODELPHIDOTNET` 分支补齐。

依赖：21.J 的 `#US` heap。

### 21.M — Cryptor/Packer 保护组（最大工作量）

- `handle_Protection`（1651 行）：按信号源切片落地——
  EP-detect 链 / section-name 链 / import 链 / overlay 链 /
  linker+compiler 组合链，每片独立可测。
- `handle_VisualBasicCryptors`（319）、`handle_DelphiCryptors`（281）：
  VB/Delphi 特征 + cryptor 节名/字符串。
- `handle_PrivateEXEProtector`（68）。
- `handle_UnknownProtection`（201）：兜底启发（EP 节特征/熵/非标准
  节数），**最后做**——它依赖"其余 handler 均无命中"的全量状态。

### 21.N — 后置修正与 .NET 精化

- `handle_FixDetects`（584 行）：结果抑制/修正规则（上游大量
  "如果 X 且 Y 则移除/改写"），必须在 handler 覆盖足够后做，
  否则修正逻辑无可修正对象。
- `handle_NETProtection` 精化 + `handle_Microsoft` Rich 链收尾。

### 21.O — 非 PE 格式启发残余

- ELF：`handle_Protection`、剩余 `.comment`/`note` 提取器（目前已
  移植 44 个提取器链主体，剩 protection 启发）。
- Mach-O：protection 段启发（VMProtect 等已做，剩杂项）。
- NE/LE/LX：heuristic handler（当前仅表驱动 linker-header/EP）。
- JavaClass/PDF/JPEG/CFBF/Amiga/JAR：`getInfo` 主体（上游纯
  heuristic，无表）——PDF/JPEG 版本提取已部分做，其余按上游
  `nfd_*.cpp` 逐个立项。
- 文本：`handle_Texts` 源语言 regex 启发（当前仅 Plain text）。

### 21.P — 上游差分验证（Gate 项）

上游 `diec` CLI **不跑** SpecAbstract（仅 GUI `nfd_widget` 用），
无现成 CLI oracle。路径：

1. 编译上游 SpecAbstract 独立 harness（`dep/SpecAbstract` 含
   CMake/qmake 工程，依赖 Qt5/6 Core + Formats/XArchive deps）。
   工作量：中等，需 Qt 构建环境 — **Gate：批准在本机/容器装 Qt
   构建依赖**。
2. 输出 dump（`XScanEngine::SCAN_STRUCT` 全记录 + version/info），
   与 `diec --nfd --format json` 逐样本 diff。
3. 语料：自造样本（Inno/NSIS 用工具打包 hello；Delphi/FPC/Qt 用
   对应编译器真实产物）+ 现有 corpus。

**Gate 理由**：缺 oracle 时保护组 handler 的对错只能靠合成 fixture
自证——21.M/21.N 在立项前最好先有差分基线，否则只能做到
"有界近似"而非行为对齐。

## 建议顺序

```
21.J（原语）→ 21.K（安装器/SFX）→ 21.L（.NET）→
21.P（差分 harness，可与 K/L 并行准备环境）→
21.M（保护组大切片）→ 21.N（FixDetects 收尾）→ 21.O（杂格式）
```

- 21.J 是硬依赖（K/L/M 的多条分支都用 version-resource 与 #US）。
- 21.N 必须排在 21.M 之后（FixDetects 修正的是 Protection 结果）。
- 21.P 若 Gate 不通过（无 Qt 环境），21.M/N 退化为"合成 fixture
  + 上游代码逐行对照"的弱验证模式，且 COMPATIBILITY 中相应行
  保持 ⚠ partial 标注。

## 风险与已记录 quirk

- `handle_FixDetects` 依赖累积状态，单独测试意义有限，需集成测试。
- `sVCLVersion` 恒空（上游注释掉赋值）——已复刻，勿"修复"。
- `mapVersions` (0,1) 死键、`get_Rust_vi` 版本恒空等已记入
  `doc/upstream-bugs.md`。
- 节名在我们的解析层已大写化：所有上游"原始节名大小写敏感比较"
  统一放宽为 `eq_ignore_ascii_case`（已注释记录）。
