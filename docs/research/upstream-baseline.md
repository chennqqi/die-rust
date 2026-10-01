# 上游基线

Status: In Review  
Upstream: `horsicq/DIE-engine@23fec32cac2a562342c1c2db8e22ce231b58f346`  
Last updated: 2026-10-01

## 结论摘要

DIE-engine 基线（2026-10-01 升级）固定为：

| 项目 | 值 |
| --- | --- |
| Repository | `https://github.com/horsicq/DIE-engine` |
| Branch | `master` |
| Commit | `23fec32cac2a562342c1c2db8e22ce231b58f346` |
| Submodule count | 58（全部位于 `dep/` 前缀下） |
| Main license | MIT |

Detect-It-Easy 规则 sibling subtree 固定为
`8925358d2298957d758b6bba74c393b622322efc`（`db`/`db_extra`/`db_custom`/
`dbs_min`/`dbs_special`/`yara_rules`/`peid_rules` tree 均已由
`tools/verify_upstream.py` 逐树核对一致）。

**基线历史**：2026-07-29 首轮基线为
`74eaf505c250ab47e709024e9dc41657cd8f2254`（`Detect-It-Easy` 为
`c2c17dfa5ea4e078ba31eab55d87430c96622fb6`）。下文"完整性记录"、
"构建系统静态分析"中的 SHA-256 和源码链接基于首轮基线采集，仍作为
上游证据保留；新基线的差异审计见 [`upstream-sync.md`](../design/upstream-sync.md)
及 `doc/requirements-analysis-006-2026-10-01.md`。新基线将 submodule
全部迁移至 `dep/` 前缀，`components.lock.toml` 中全部 `gitlink_path`
已更新为 `dep/<component>`。

固定 SHA 是兼容性实验的唯一身份；文档中的日期或版本号不能替代 SHA。

## 获取方式

```sh
git clone https://github.com/horsicq/DIE-engine.git
git -C DIE-engine checkout 23fec32cac2a562342c1c2db8e22ce231b58f346
git -C DIE-engine submodule update --init --recursive
git -C DIE-engine submodule status --recursive
```

仓库中的 subtree 只物化主仓库和规则数据；Linux qmake/CMake CLI 实验会在隔离
容器中从固定 SHA 初始化全部 58 个直接 submodule。构建、产物和可重复性边界见
[`upstream-build-baseline.md`](upstream-build-baseline.md) 与
[`upstream-cmake-differential.md`](upstream-cmake-differential.md) 与
[`upstream-qt6-differential.md`](upstream-qt6-differential.md)。实验尚未
覆盖完整发布打包及 macOS；Windows Qt5 的 68 行能力基线虽已闭合，但不是
官方发布包复现，因此本文件仍为 Draft。

本仓库目前还物化了两个可审计快照：

- `upstream/DIE-engine/`：主仓库 squash subtree。
- `upstream/Detect-It-Easy/`：与主仓库 gitlink 一致的规则/发布数据 squash subtree。

其他核心 submodule 目前只在 `upstream/components.lock.toml` 锁定 SHA，源码分析使用外部临时 checkout。该状态不等同于完整 recursive build checkout。

## 完整性记录

| 文件 | SHA-256 |
| --- | --- |
| `LICENSE` | `BE0FE2D727CD0A754FB0B2FDC579EAD8F19EF575840B4DAEF221BE201701EAAD` |
| `.gitmodules` | `7AA824AFAC7F4C74A995519989A9089EF1FA23022E4A9570667A7785B173ACB9` |

主仓库 `LICENSE` 为 MIT License，copyright 为 `2012-2026 hors<horsicq@gmail.com>`。本轮检查的 `Detect-It-Easy`、`Formats`、`StaticScan`、`XScanEngine`、`die_script`、`signatures`、`XOptions`、`XFileInfo` 和 `XEntropyWidget` 均有以 `MIT License` 开头的独立 `LICENSE` 文件。固定 XScanEngine external research checkout 的 LICENSE SHA-256 为 `ac4f868b0034a4047dd1394409e412a25b03013a42f75f20fb0a4f9b4692a827`，其 HostApi 头文件清单见 [`host-api-inventory.md`](host-api-inventory.md)。

完整 58 个直接组件均已固定根 LICENSE path/hash，全部首行为 MIT，且确认没有嵌套
`.gitmodules`；58 份根文本有 12 个不同 hash。机器清单与限制见
[`component-license-inventory.md`](component-license-inventory.md)。这仍不是完整
许可证审计：bundled code 文件头、构建工具及测试样本仍需逐项核对。YARA、
PEiD 与 signatures 数据已完成固定路径/hash/可见标记审计，但多项第三方来源
许可仍未关闭，见
[`rule-asset-provenance.md`](rule-asset-provenance.md)。

## Submodule 基线

主仓库记录 58 个直接 submodule。完整名称如下：

```text
Detect-It-Easy Formats SpecAbstract StaticScan XArchive XQwt XOptions
XStyles XTranslation XDEX FormatDialogs FormatWidgets Controls
XMemoryMapWidget XEntropyWidget XCapstone XHashWidget die_script die_widget
nfd_widget archive_widget XMIME XSingleApplication XMIMEWidget XHexView
XDisasmView XGithub XShortcuts XHexEdit signatures XDemangle
XDemangleWidget XCppfilt XDynStructs XDynStructsEngine XDynStructsWidget
XFileInfo XPDF XInfoDB XSymbolsWidget XOnlineTools XAboutWidget
hex_templates XExtractorWidget XExtractor XUpdate XVisualizationWidget
XDecompiler XYara yara_widget XDataConvertorWidget XScanEngine
XDisasmCore XRegionsWidget XStaticUnpacker XPEID build_tools peid_widget
```

首轮核心源码分析使用以下主仓库 gitlink（2026-10-01 基线）：

| Submodule | Commit | 初步角色 |
| --- | --- | --- |
| `Detect-It-Easy` | `8925358d2298957d758b6bba74c393b622322efc` | 发布数据、`db*` 规则库、YARA/PEiD 规则 |
| `Formats` | `65b04bebf41d3090fd4d4223065945ffa88a689d` | 二进制格式探测和解析基础 |
| `StaticScan` | `fcdcb25b16d0e0c6b2f82c2b270b2a3d58c1e11d` | 静态扫描相关 UI/模型；与 CLI 范围关系待确认 |
| `XScanEngine` | `2550d2dab08329a6319a72d0abb722c152d8c940` | 扫描编排、结果模型、递归和数据库加载 |
| `die_script` | `3a19ceb6d385b8d3e39d5e3d686391d87d252844` | DIE 规则脚本运行时 |
| `signatures` | `5d80fb2863d02e9366aee7b3ade6abb7d6598dbb` | crypto/junk 二进制签名，不等同于 `db` 脚本规则 |
| `XOptions` | `954afe89663f7edfb6a376db724c25ac7994594d` | CLI 选项定义 |
| `XFileInfo` | `7fa7027182b3ff10bfa231f1f0b3532e319d50fc` | `--info` 和 `--struct` 信息输出 |
| `XEntropyWidget` | `7487d256681b487fb921ea87a12317182d4079ac` | `--entropy` 的非 UI 处理代码 |

全部 58 个直接 gitlink 的 repository URL 和 commit SHA 已记录在
[`../../upstream/components.lock.toml`](../../upstream/components.lock.toml) 的
`[gitlink]` 表中，可通过以下命令与基线重复核对：

```sh
python3 tools/verify_upstream.py
```

该清单覆盖主仓库的直接 submodule。固定 source image 审计确认 58 个组件都没有
嵌套 `.gitmodules`，因此 git submodule closure 在本 commit 到此终止；普通
vendored 目录仍需独立 source/license 审计。

## 构建系统静态分析

主入口 [`CMakeLists.txt`](https://github.com/horsicq/DIE-engine/blob/74eaf505c250ab47e709024e9dc41657cd8f2254/CMakeLists.txt) 要求 CMake 3.18，并进入 `src/`。

[`src/CMakeLists.txt`](https://github.com/horsicq/DIE-engine/blob/74eaf505c250ab47e709024e9dc41657cd8f2254/src/CMakeLists.txt)：

- 自动选择 Qt 5 或 Qt 6。
- Qt 组件包含 Core、Widgets、Concurrent、Network、PrintSupport、OpenGL、Svg、Sql；Qt 5 额外使用 Script/ScriptTools，Qt 6 使用 Qml。
- 添加 `XCppfilt`、`XCapstone`、`XArchive`、`XYara` 和 `Formats/xsimd`。
- 同时构建 `gui`、`console` 和 `lite`。

[`src/console/CMakeLists.txt`](https://github.com/horsicq/DIE-engine/blob/74eaf505c250ab47e709024e9dc41657cd8f2254/src/console/CMakeLists.txt) 为 `diec` 定义：

- C++17。
- 编译开关 `USE_DEX`、`USE_PDF`、`USE_ARCHIVE`、`USE_XSIMD`。
- 链接 `xsimd`、`bzip2`、`lzma`、`zlib`、`capstone_x86`、`ppmd`。
- 链接 Qt Core、Concurrent，以及 Qt 5 Script 或 Qt 6 Qml。
- Windows 额外链接 `Wintrust` 和 `Crypt32`。

仓库也包含 Autoconf 生成物和 qmake `.pro/.pri` 文件。哪个构建入口是各平台发布基线，仍需通过官方 release workflow 和实际构建验证。

## 数据资产

`Detect-It-Easy` 固定版本包含：

- `db/`：Amiga、APK、Archive、AtariST、Binary、CFBF、COM、DEX、DOS16M、DOS4G、ELF、Image、IPA、ISO9660、JAR、JavaClass、JPEG、LE、LX、MACH、MACHOFAT、MSDOS、NE、NPM、PDF、PE、PNG、PYC、RAR、ZIP。
- `db_extra/`：Amiga、COM、ELF、MSDOS、PE。
- `db_custom/`：默认没有规则类别目录。
- `dbs_min/`、`dbs_special/`：用途和发布选择规则待分析。2026-10-01
  基线中 `dbs_special/` 新增 `db_dubious/`（低置信度规则迁入）与
  `experimental/`。
- `yara_rules/`、`peid_rules/`：固定 `diec` CLI 不加载；Detect release tree
  与 XYara/XPEID component tree 又不是字节镜像。它们属于 GUI/替代引擎及
  发布物审计范围，见
  [`rule-asset-provenance.md`](rule-asset-provenance.md)。

## 尚未完成

- [`component-license-inventory.md`](component-license-inventory.md) 已确认全部
  58 个直接组件 commit/root LICENSE，并证明没有嵌套 `.gitmodules`。
- Linux Qt5 qmake、Qt5 CMake、Qt6 CMake 和 Windows Qt5 qmake CLI 候选
  oracle 已构建。Windows clean build、官方 CMake/xsimd 断点及一个 PE64 smoke
  见 [`windows-qt5-build-baseline.md`](windows-qt5-build-baseline.md)；Windows
  默认 26-sample baseline、首轮 338-case option/output/special 及
  46-case path/nested、18-case database、17-case 特殊路径、8-case
  filesystem、7-case long-path、5-case ADS、剩余 21-sample 普通 output 和
  21-sample special 矩阵已归档；同 special 矩阵的 Linux Qt5/Qt6 raw 与
  Windows structured projection 三方差分，以及同 output 矩阵的 Linux
  Qt5/Qt6/Windows JSON 与有效性差分也已完成。完整能力差分、CMake 发布打包
  和 bit-for-bit 验证仍待完成；macOS 已建立固定 x86_64/Qt5 CLI-only
  bootstrap 与候选报告 validator，但尚未在 Darwin 主机执行，见
  [`macos-qt5-oracle-plan.md`](macos-qt5-oracle-plan.md)。
- release workflow、预编译包与源码构建之间的数据资产差异。
- bundled code、规则原始来源和最终发布组合的许可证审计；YARA/PEiD/signature
  资产路径与可见标记已固定，但 GPL/未知来源仍需书面评审。
- 已采集 Linux Qt5 qmake/CMake 与 Qt6 CMake 产物的链接证据；完整静态依赖与
  发布产物清单仍待采集。
- 已完成自扫描 smoke baseline、26 个项目生成安全样本的默认 JSON/退出码差分
  及 Windows 首轮 option/output/special/path/nested/database 矩阵；特殊路径、
  Unicode/Hidden/前导短横线、Junction/`\\?\`、324/325-code-unit 长路径首轮
  矩阵、显式 ADS/目录不枚举 named stream 及 26-sample 普通 output/special
  以及 17-case ZIP database 也已完成；Linux Qt5/Qt6 的全 26-sample
  output/special 扩展也已完成；Windows 19-case engine cache/DACL harness
  也已完成两轮；新增 37-case engine-contract、CLI option/profiling 和
  10-case rule-orchestration 双轮及 private signature-path engine harness
  双轮、五组 result-model harness 各双轮，再加入 86 次 legacy/archive
  dispatch、debug-data paired harness 双轮、archive-option 128 次及
  count-boundary 22 次、archive-limit 30 次及 path closure 46 次执行后，
  Windows 68 行 closure 已分类为 68 complete、0 partial、0 missing，并已由
  总覆盖生成器接纳；
  CLI profiling 保留 `image_ICNS.sg`
  的精确 Windows/Linux 顺序差异，而规则编排 canonical 语义完全相同；
  23-case path closure 已固定 4096-entry、reparse cycle、同步 TOCTOU、
  WSL UNC/extended-UNC 及本地/redirector access denial；macOS runtime、
  其他 UNC
  provider、EFS/integrity level、畸形扩展矩阵和其余跨平台原始输出仍待采集。

## 主要证据

- [主仓库 commit](https://github.com/horsicq/DIE-engine/tree/74eaf505c250ab47e709024e9dc41657cd8f2254)
- [`.gitmodules`](https://github.com/horsicq/DIE-engine/blob/74eaf505c250ab47e709024e9dc41657cd8f2254/.gitmodules)
- [`LICENSE`](https://github.com/horsicq/DIE-engine/blob/74eaf505c250ab47e709024e9dc41657cd8f2254/LICENSE)
- [`release_version.txt`](https://github.com/horsicq/DIE-engine/blob/74eaf505c250ab47e709024e9dc41657cd8f2254/release_version.txt)
