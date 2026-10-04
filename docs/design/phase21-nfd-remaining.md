# Phase 21 剩余项归化：NFD/SpecAbstract 收尾规划

> 状态：草案（2026-10-08）。Phase 21.A–I 已完成（codegen、通用 pass、
> 8 格式 dispatch、PE handle_* 第一批~第三批）。本文档把剩余
> deferred 项按依赖关系归化为可独立立项的批次。

## 终态目标（确认）

**所有 `COMPATIBILITY.md` 中 ⚠ partial 的 NFD 行最终都要补齐全量
移植并对齐上游可观察行为**，不是"有条件才做"。Phase 21 装不下就
顺延到 Phase 22（非 PE 格式启发残余）与 Phase 23（差分验证与
收尾）。矩阵升级规则不变：handler 移植完成先标 ⚠（源码对照级），
上游差分收敛后才升 ✅。

## 剩余工作量盘点（按上游行数）

| handler（nfd_pe.cpp） | 行数 | 状态 |
|---|---|---|
| `handle_Protection` | 1651 | 未移植（最大单块） |
| `handle_Microsoft` | 676 | ✅ 全量（含 Rich→工具描述链 + `_fixRichSignatures`） |
| `handle_FixDetects` | ~30 | ✅ 已移植（6 组名称抑制规则；实际行数远小于初估） |
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

### 21.M — Cryptor/Packer 保护组（最大工作量）✅ 已落地

- `handle_Protection`（1651 行）已全量移植（`pe_handlers::protection`）：
  MPRESS/HyperTech/Spoon-Xenocode/SerGreen/MoleBoxUltra/NativeCryptor/
  ActiveMark/SecuROM/ZLIB→PyInstaller、UPX vi（`upx_vi`/`upx_header_vi`
  含格式白名单+方法→info 表）、PECompact 构建号表、Enigma、PESpin/
  WinUpack/ORIEN/WWPACK32/FSG 版本表、NPACK/EncryptPE/PEPack/VCasm/
  EXE32Pack 横幅、~80 个 import+EP/section/header 机械转发、
  ZProtect 双路径（签名比较+空首节+熵>7.6）、ExeFog 头门、
  ASPack EP-follow（复用管线内既有 loop）、LARP64（64 位分支）。
- `handle_VisualBasicCryptors`（39 名转发 + 1337EXECRYPTER/AGAIN
  NATIVITY 特例）、`handle_DelphiCryptors`（34 名 + CIGICIGI 的
  AYARLAR 资源门）已移植。
- `handle_PrivateEXEProtector`（PEP/TurboLinker + 节特征 + 导入形状）。
- `handle_UnknownProtection`：UNK_UPXLIKE、EP 启发提升、UPX vi 兜底、
  .aspack+.adata、PECompact 兜底、KKRUNCHY、generic 节/熵报告
  （isProtectionPresent 门 = packer+protector+sfx+installer+
  netobfuscator+dongle 已存在）。
- 小 handler：SafeengineShielden/VProtect/TTProtect/VMProtect/tElock/
  Armadillo/Obsidium/Themida/StarForce/Petite。
- `pe_scan` 调用序已重排为上游 getInfo 顺序。
- 未完成项：`handle_FixDetects`（→21.N）、`handle_PolyMorph`（E2.
  已含于 petools 转发）、EP 签名的 `match_signature_pe` RVA-相对
  跳转在 compareEntryPoint 中用平坦文件偏移语义（`$$` 近似）——
  Phase 23 差分验证。

### 21.N — 后置修正与 .NET 精化 ✅ 已落地

- `handle_FixDetects`：6 组名称抑制规则已移植
  （RLPACK/BACKDOORPECOMPRESS→移除 MSLINKER/MASM/MASM32，
  EPEXEPACK→移除 AHPACKER，VC+++Delphi→移除 Delphi，
  MSLINKER+TURBOLINKER→移除 TURBOLINKER，VS+BorlandDelphi→移除
  Delphi tool，SIMPLEPACK+FASM→移除 FASM）。
- `handle_Microsoft` Rich 链收尾：`MSDOS_richScan` 列表形式
  （`msrich_scan_list`）+ `_fixRichSignatures`（build>25000 →
  36 行 minor 阈值表重建 major.minor.build；MSLINKER 优先取
  optional header linker minor 10..=40）+ 逆序遍历选最高版本
  linker/compiler（UTC→VC++、UTC/Basic→VB `mapVersions.key`
  反向查找、MASM）；import-VB 覆盖 rich-VB、.NET else 补
  VBNET/JSCRIPT。
- AutoIt 2.XX：`FileDescription == "Compiled AutoIt Script"` →
  `getFileVersionMS`（dwFileVersionMS hi.lo）。
- 修正两处既有偏差：`collect_rich` 的 compid/build 高低位曾反
  序且回扫步长误为 -8（上游 -4 单 dword 找 DanS，命中后 +16
  正向 +8 读条目）；engine 曾把原始 rich 记录灌入 header map
  （上游仅 handle_Microsoft 消费 rich——已移除，`msrich_scan`
  删除，留 `msrich_scan_list`）。

### Phase 22 — 非 PE 格式启发残余（原 21.O，独立成 phase）

对应 COMPATIBILITY 的 6 行 ⚠：ELF、Mach-O 32/64、Mach-O FAT、
NE、LE/LX、文本。

- **22.A ELF**：`handle_Protection`、剩余 `.comment`/`note`
  提取器（目前已移植 44 个提取器链主体，剩 protection 启发）。
- **22.B Mach-O**：protection 段启发（VMProtect 等已做，剩杂项）；
  FAT 维持 generic 兜底（上游上限），COMPATIBILITY 行保留 ⚠ 并
  注明"已达上游上限"。
- **22.C NE/LE/LX**：heuristic handler（当前仅表驱动
  linker-header/EP）。
- **22.D 小众格式**：JavaClass/PDF/JPEG/CFBF/Amiga/JAR `getInfo`
  主体（上游纯 heuristic）——PDF/JPEG 版本提取已部分做。
- **22.E 文本**：`handle_Texts` 源语言 regex 启发（~20 种语言）。

### Phase 23 — 上游差分验证（原 21.P，Gate 已开）

上游 `diec` CLI **不跑** SpecAbstract（仅 GUI `nfd_widget` 用），
无现成 CLI oracle。**已确认：允许用 Qt 构建上游 harness 做对比，
但 Qt 只属于 oracle 侧工具，`die-rust` 任何 crate 不得引入 Qt。**

路径：

1. 在 `upstream/`（或独立目录）编一个 Qt console harness，链接
   `dep/SpecAbstract` + `dep/Formats`/`XArchive`，
   `SpecAbstract::scan()` → dump 全部 `SCAN_STRUCT`
   （type/name/version/info）→ 文本快照。构建产物不提交，快照可
   提交为哈希清单。
2. `diec --nfd --format json` 输出与快照逐样本 diff（正向漏检 /
   负向误报 / 版本值差异三路对比）。
3. 语料：自造样本（Inno/NSIS 打包 hello；MinGW/FPC/Qt 等真实
   编译器产物）+ 现有 corpus。

**Gate 已开**（Qt 仅 oracle 侧）：21.M/21.N 移植完成后依赖此
harness 收敛；收敛前 COMPATIBILITY 对应行保持 ⚠（覆盖完成但
未经差分验证）。

## 建议顺序

```
21.J（原语）→ 21.K（安装器/SFX）→ 21.L（.NET）→
Phase 23 harness（可与 K/L 并行准备 Qt 环境）→
21.M（保护组大切片）→ 21.N（FixDetects 收尾）→
Phase 22（非 PE 杂格式）→ Phase 23 差分收敛 → 全量 ✅
```

- 21.J 是硬依赖（K/L/M 的多条分支都用 version-resource 与 #US）。
- 21.N 必须排在 21.M 之后（FixDetects 修正的是 Protection 结果）。
- Phase 22/23 互不阻塞，可与 21.M 并行推进。
- handler 移植完成后一律先 ⚠，Phase 23 diff 收敛后逐行升 ✅。

## 风险与已记录 quirk

- `handle_FixDetects` 依赖累积状态，单独测试意义有限，需集成测试。
- `sVCLVersion` 恒空（上游注释掉赋值）——已复刻，勿"修复"。
- `mapVersions` (0,1) 死键、`get_Rust_vi` 版本恒空等已记入
  `doc/upstream-bugs.md`。
- 节名在我们的解析层已大写化：所有上游"原始节名大小写敏感比较"
  统一放宽为 `eq_ignore_ascii_case`（已注释记录）。
