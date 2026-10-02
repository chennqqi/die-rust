# 调研文档

本目录只记录上游事实、实验结果和证据，不提前写入本项目的实现决策。

Phase 0 计划形成：

- [`upstream-baseline.md`](upstream-baseline.md)：版本、构建、submodule、依赖和许可证（In Review）。
- [`windows-qt5-build-baseline.md`](windows-qt5-build-baseline.md)：固定
  Windows x64/MSVC 2019/Qt 5.15.2 的 clean qmake CLI 构建、官方 CMake
  xsimd 断点、二进制身份与最小 PE64 smoke（Draft）。
- [`macos-qt5-oracle-plan.md`](macos-qt5-oracle-plan.md)：固定
  macOS x86_64/Qt 5.15.2 CLI-only qmake bootstrap、候选报告 validator 和
  68 行 runtime closure 接纳门禁；当前仅 infrastructure ready，未采集
  runtime（Draft）。
- [`macos-privilege-path-candidate.md`](macos-privilege-path-candidate.md)：
  受限 runner-temp fixture 上的 root/runner、mode、ACL deny-read/search 与
  ownership 12-case 候选矩阵、安全清理和 raw replay 契约；当前未采集 Darwin
  runtime（Draft）。
- [`capability-matrix.md`](capability-matrix.md)：CLI/engine 能力与证据索引（Draft）。
- [`capability-coverage-report.md`](capability-coverage-report.md)：68 个稳定能力在
  Linux Qt5/Qt6、Windows 和 macOS 上的 runtime/source-only、corpus-missing
  与 platform-missing 闭集报告（Draft）。
- [`source-only-closure-plan.md`](source-only-closure-plan.md)：Linux Qt5
  source-only 闭集及最后一项 depth/expanded-byte 关闭证据（Draft）。
- [`archive-limit-behavior.md`](archive-limit-behavior.md)：受资源约束的 archive
  depth 64/约 32 MiB 累计展开量递增、peak RSS 与 cooperative cancellation
  证据（In Review）。
- [`qt6-archive-limit-runtime-evidence.md`](qt6-archive-limit-runtime-evidence.md)：
  相同 14-case archive-limit corpus 和取消 control 的固定 Qt5/Qt6 配对证据，
  关闭 Linux Qt6 `CAP-NEST-009`（In Review）。
- [`archive-iteration-boundary.md`](archive-iteration-boundary.md)：aggressive
  archive 第 99999/100000/100001 条 Qt5/Qt6 哨兵、源码循环顺序、NUL dot-entry
  差异和受控分配失败证据（In Review）。
- [`qt6-count-boundary-runtime-evidence.md`](qt6-count-boundary-runtime-evidence.md)：
  Qt6 archive 三点、resource 21/2001、Qt5/Qt6 ISO NUL 根因及
  `CAP-NEST-004` 闭环证据（In Review）。
- [`archive-adversarial-behavior.md`](archive-adversarial-behavior.md)：ZIP
  deflate/ZipCrypto、高压缩比、CRC/压缩流/offset/method 畸形、local-header
  fallback 与 mixed-member filter（In Review）。
- [`archive-truncation-behavior.md`](archive-truncation-behavior.md)：7Z、
  RAR4、CAB 和 ISO9660 的 26-case EOF 前缀阶梯、104 次固定 Qt5 oracle
  与格式识别/成员展开边界（In Review）。
- [`archive-structure-behavior.md`](archive-structure-behavior.md)：7Z、
  RAR4、CAB 和 ISO9660 的 56-case CRC/size/offset/method/record-field/0/max
  突变及 224 次固定 Qt5 oracle（In Review）。
- [`archive-multirecord-behavior.md`](archive-multirecord-behavior.md)：7Z、
  RAR4、CAB 和 ISO9660 的正序/逆序/重名/空首记录两成员矩阵及 64 次固定
  Qt5 oracle（In Review）。
- [`iso9660-endian-behavior.md`](iso9660-endian-behavior.md)：ISO9660
  17 个 `both16`/`both32` 字段的 LE-only/BE-only 冲突对、35 个样本及
  140 次固定 Qt5 oracle（In Review）。
- [`archive-format-behavior.md`](archive-format-behavior.md)：
  7Z Copy/LZMA/LZMA2/PPMd7/BZip2/Deflate/Deflate64 与
  x86/ARM64 BCJ+LZMA2、BCJ2+LZMA2 no-branch/E8/E9/JCC、RAR4、CAB
  Store/MSZIP、ISO9660 正向解包、7Z 七种基础 coder+AES 与完整 x86/ARM64
  filter × 七种基础 coder × AES 成功密码契约、Copy/PPMd7 错误密码残留输出、
  BCJ2+LZMA2+4×AES 正确密码失败边界及 CAB
  LZX/Quantum 普通/激进失败边界、
  发布 CLI 默认对照与 7Z/CAB `Binary` 顶层 quirk（Draft）。
- [`archive-rar5-store-behavior.md`](archive-rar5-store-behavior.md)：
  项目生成 RAR5 Store 单成员与 solid 双成员、8 次固定 Qt5 oracle、源码
  solid-store 分派及明确排除专有压缩算法/第三方 binary 的语料边界（Draft）。
- [`archive-rar-compressed-behavior.md`](archive-rar-compressed-behavior.md)：
  固定外部 CC0 候选的 RAR3/RAR5 method-5、solid 状态、许可证边界和
  aggressive oracle（Draft）。
- [`archive-gap-closure.md`](archive-gap-closure.md)：
  固定 engine 五类解包 family 闭集、成对运行控制、100000/100001、
  depth-64/33,554,546-byte 证据及 `CAP-GAP-006` disposition（Draft）。
- [`npm-dispatch-reachability.md`](npm-dispatch-reachability.md)：
  NPM 精确归档路径检测、公共 GZIP 自动分派不可达、强制 NPM 规则分支及
  双 Qt5 release 对照（Draft）。
- [`generic-archive-dispatch-reachability.md`](generic-archive-dispatch-reachability.md)：
  ZIP/TAR/GZIP 自然分派、singleton `FT_ARCHIVE` 门控、强制通用 adapter
  重检测及双 Qt5 quiet/verbose 对照（Draft）。
- [`signature-path-filter-behavior.md`](signature-path-filter-behavior.md)：
  private signature-file path comparator 的严格绝对路径语义、公共不可达边界，
  以及 Linux Qt5/Qt6 与原生 Windows Qt5 配对证据（Draft）。
- [`debug-data-dispatch-behavior.md`](debug-data-dispatch-behavior.md)：
  同一 PE 的 resource 正控制、direct debug 正例与 recursive debug 负例
  （Draft）。
- [`legacy-dispatch-oracle.md`](legacy-dispatch-oracle.md)：Amiga Hunk/Atari ST
  的固定源码边界、8-case 生成语料、双 Qt5 与双轮 Qt6 detector/scanner
  分派门禁（Draft）。
- [`dos-dispatch-reachability.md`](dos-dispatch-reachability.md)：DOS/COM 七个
  公共 detector 成员与 BW DOS16M branch-only 路径的固定源码审计、双 Qt5
  与双轮 Qt6 运行门禁（Draft）。
- [`result-metadata-behavior.md`](result-metadata-behavior.md)：`SCAN_RESULT`
  四个标量字段、四个公共扫描入口的 filename/size/filetype/time 契约及
  Qt5 harness（Draft）。
- [`result-list-behavior.md`](result-list-behavior.md)：`SCAN_RESULT` 的
  records/errors/debug/handlers 四列表、顺序和重复项 Qt5 契约（Draft）。
- [`result-flag-behavior.md`](result-flag-behavior.md)：`SCANSTRUCT` 的
  heuristic/advanced heuristic/unknown 三标记真值表（Draft）。
- [`result-id-behavior.md`](result-id-behavior.md)：`SCANSTRUCT.id`、
  `parentId` 的完整字段及 resource edge/UUID 父子关系（Draft）。
- [`result-enum-behavior.md`](result-enum-behavior.md)：`SCANSTRUCT` 原始
  type/name、数值 enum、规范字符串及 Unknown 边界（Draft）。
- [`windows-result-model-behavior.md`](windows-result-model-behavior.md)：
  五组原生 Windows Qt5 result-model harness 双轮、Linux Qt5 完整文档配对和
  六个 result-model 能力行闭环（Draft）。
- [`windows-dispatch-behavior.md`](windows-dispatch-behavior.md)：
  DOS/COM、Amiga/Atari 公共 CLI 与 BW/NPM/Archive 直连 harness 的原生
  Windows Qt5 双轮证据，关闭三个 dispatch 能力行（Draft）。
- [`windows-debug-dispatch-behavior.md`](windows-debug-dispatch-behavior.md)：
  原生 Windows Qt5 的 resource/debug paired harness、九项分派关系与 Linux
  Qt5 完整语义文档对照，关闭 `CAP-NEST-007`（Draft）。
- [`windows-archive-option-behavior.md`](windows-archive-option-behavior.md)：
  原生 Windows Qt5 的 64-case engine archive-option 双轮矩阵、Windows
  release 控制和 Linux Qt5 detection tree 对照，关闭 `CAP-NEST-003`
  （Draft）。
- [`windows-count-boundary-behavior.md`](windows-count-boundary-behavior.md)：
  原生 Windows Qt5 的 archive 99999/100000/100001 和 resource 21/2001
  双轮精确边界，关闭 `CAP-NEST-004`（Draft）。
- [`source-analysis.md`](source-analysis.md)：模块关系及扫描/规则调用链（In Review）。
- [`rule-compatibility.md`](rule-compatibility.md)：规则语法、内建函数和宿主 API（In Review）。
- [`rule-runtime-spike.md`](rule-runtime-spike.md)：Boa 全库解析、真实复杂规则、宿主绑定和资源限制验证（Draft）。
- [`rquickjs-rule-runtime-spike.md`](rquickjs-rule-runtime-spike.md)：rquickjs/QuickJS-NG 全库执行、sloppy 语义、native 构建和资源限制验证（Draft）。
- [`rquickjs-static-link.md`](rquickjs-static-link.md)：rquickjs/QuickJS-NG 的 Windows/Linux Rust staticlib、C 链接、CRT、系统依赖和许可证闭包（Draft）。
- [`nintendo-certified-rule.md`](nintendo-certified-rule.md)：唯一 legacy 规则的项目生成语料与真实 detect 基线（Draft）。
- [`binary-rule-lifecycle.md`](binary-rule-lifecycle.md)：Binary 数据库分层、init/include 选择、共享引擎生命周期和排序缺陷（Draft）。
- [`rule-orchestration.md`](rule-orchestration.md)：priority 比较器边界、数据库分层、init/include、mode/file-type 过滤、Unknown 及 `CAP-GAP-010` 闭合基线（Draft）。
- [`signature-language.md`](signature-language.md)：signature 文法、固定 oracle、静态/动态调用清单和边界行为（Draft）。
- [`pe-rule-runtime-differential.md`](pe-rule-runtime-differential.md)：真实 PE32 context、`PE.compareEP` 与原样 Cygwin32 规则的 Qt5/Rust 正反截断差分（Draft）。
- [`elf-rule-runtime-differential.md`](elf-rule-runtime-differential.md)：真实 ELF32/ELF64 context、`ELF.compareEP` 与原样 Burneye 规则的 Qt5/Rust 正反截断差分（Draft）。
- [`macho-rule-runtime-differential.md`](macho-rule-runtime-differential.md)：真实 Mach-O64 x86_64/arm64 context、`MACH.compareEP` 与原样 Rust compiler 规则的 Qt5/Rust 差分（Draft）。
- [`dex-rule-runtime-differential.md`](dex-rule-runtime-differential.md)：真实 DEX035 string-table context、`DEX.isDexStringPresent` 与原样 QDBH 规则的 Qt5/Rust 正反截断差分（Draft）。
- [`apk-rule-runtime-differential.md`](apk-rule-runtime-differential.md)：真实 APK/ZIP central-directory context、`APK.isArchiveRecordPresent` 与原样 QDBH 规则的 Qt5/Rust 正反截断差分（Draft）。
- [`archive-rule-runtime-differential.md`](archive-rule-runtime-differential.md)：真实 ZIP metadata context、`Archive.isVerbose`/format getters 与原样 Archive 规则的 Qt5/Rust verbose 门控和截断差分（Draft）。
- [`pdf-rule-runtime-differential.md`](pdf-rule-runtime-differential.md)：真实 PDF object/string context、`PDF.getStringValuesByKey`/header comment 与原样 Tools 规则的 Qt5/Rust 类型、去重和截断差分（Draft）。
- [`rule-syntax-inventory.md`](rule-syntax-inventory.md)：全规则 AST 语法、全局引用和宿主调用形状清单（Draft）。
- [`host-api-inventory.md`](host-api-inventory.md)：XScanEngine C++ slot、继承、默认参数与规则调用覆盖（Draft）。
- [`global-host-api-inventory.md`](global-host-api-inventory.md)：die_script 非格式 native globals、规则顶层函数与直接调用分类（Draft）。
- [`global-host-api-runtime-differential.md`](global-host-api-runtime-differential.md)：真实 `DiE_ScriptEngine` 的 Qt 5/Qt 6 global HostApi 转换、query coercion、raw stderr、副作用与异常差分（Draft）。
- [`format-host-api-runtime-differential.md`](format-host-api-runtime-differential.md)：真实格式 QObject 的 Qt 5/Qt 6 参数数量、转换、stderr 与异常差分（Draft）。
- [`global-typo-error-behavior.md`](global-typo-error-behavior.md)：两个固定规则未定义 global 的可达性、Qt 5 错误和 CLI framing（Draft）。
- [`script-scope-semantics.md`](script-scope-semantics.md)：Qt Script 跨规则 lexical 环境与 QuickJS 差分（Draft）。
- [`script-state-semantics.md`](script-state-semantics.md)：Qt Script 跨规则 var/function/global 持久状态与 wrapper 风险（Draft）。
- [`c-static-link-spike.md`](c-static-link-spike.md)：Windows/Linux C staticlib、所有权、panic/CRT 和系统依赖验证（Draft）。
- [`rust-toolchain-upgrade-1.97.1.md`](rust-toolchain-upgrade-1.97.1.md)：固定默认 Rust 1.97.1、保留 MSRV 1.88 的 Rust 门禁与 Windows/Linux static-link 复验（Draft）。
- [`cli-dependency-and-license.md`](cli-dependency-and-license.md)：CLI 源码/链接依赖闭包与许可证初审（Draft）。
- [`product-source-closure.md`](product-source-closure.md)：固定 Linux Qt5
  `diec` 的 223 个直接对象、8 archive/36-built/14-included member、
  237-source 产品闭包、AUTOMOC 来源和 XUCL 缺失 `ACC_LICENSE` 旗标（In Review）。
- [`linux-cmake-install-tree.md`](linux-cmake-install-tree.md)：固定 Linux Qt5
  默认 CMake install 的 4,916-file staging tree、三产品/资产布局、重复路径、
  来源映射、runtime rules 和 LICENSE/NOTICE 边界（In Review）。
- [`linux-release-trees.md`](linux-release-trees.md)：固定 Linux Qt5 AppImage
  pre-linuxdeploy 与 portable post-build tree 的脚本忠实复演、产品/规则/Qt
  内容差异、multiarch 路径缺口、LICENSE 边界和两次原始 tar 命令的
  mtime 非确定性，并以两次规范化 control 证明 tar/tar.gz 字节可重复
  （In Review）。
- [`xucl-origin.md`](xucl-origin.md)：将 XArchive 的 XUCL 两个内嵌文件固定到
  官方 UCL 1.03，保存 token 来源映射、精确 `ACC_LICENSE` 和
  `GPL-2.0-or-later` 技术分类（In Review）。
- [`xarchive-license-closure.md`](xarchive-license-closure.md)：固定 Linux Qt5 CMake CLI 的 XArchive 编译单元、头文件依赖与文件级许可证证据（Draft）。
- [`xarchive-final-link-closure.md`](xarchive-final-link-closure.md)：固定 Linux
  Qt5 CMake CLI 的 XArchive 四个 archive、22 个构建 member 与 GNU ld
  最终抽取闭包；证明仅 `LzmaDec.c.o` 被抽取并记录符号交集假阳性边界（In Review）。
- [`xcapstone-license-closure.md`](xcapstone-license-closure.md)：固定 Linux
  Qt5 CMake CLI 的 XCapstone direct object、Capstone x86 archive 10/11
  member 最终 ELF 符号见证、71-file 依赖闭包及 MIT/BSD/LLVM-NCSA 三份
  许可证文本（In Review）。
- [`xsimd-license-closure.md`](xsimd-license-closure.md)：固定 Linux Qt5
  CMake CLI 的 Formats/xsimd 三个单 member archive、最终 ELF 符号见证、
  六文件依赖闭包和 MIT/copyright 归属（In Review）。
- [`embedded-compression-origins.md`](embedded-compression-origins.md)：XArchive 聚合 Brotli/Zstandard 的固定官方源码、token 指纹与许可证追溯（Draft）。
- [`rar-decoder-provenance.md`](rar-decoder-provenance.md)：XArchive RAR
  decoder 与 RARLAB 官方 UnRAR 7.13 归档/固定镜像的逐文件来源、许可证及
  acknowledgments 差异和 Rust 复用门禁（Draft）。
- [`yara-license-closure.md`](yara-license-closure.md)：XYara 内嵌 YARA v4.5.2 的实际构建闭包、官方内容映射、TLSH/Authenticode/Bison 许可证和 compiler warning（Draft）。
- [`rule-asset-provenance.md`](rule-asset-provenance.md)：Detect release 与 XYara/XPEID/signatures 数据树的逐文件哈希、历史、可见许可信号、CLI 可达性和打包路径（Draft）。
- [`runtime-rule-assets-license.md`](runtime-rule-assets-license.md)：`db`/`db_extra`/
  `db_custom` 的 2,268 文件分发身份、根 MIT/文件级标记、归属信号和未关闭法律
  评审（Draft）。
- [`runtime-png-provenance.md`](runtime-png-provenance.md)：runtime 22 个 PNG
  的原仓库 Git/blob 历史、两次来源提交、C100/R100、PNG metadata、来源时/
  pinned LICENSE 与贡献政策边界（In Review）。
- [`process-benchmark-runner.md`](process-benchmark-runner.md)：严格 plan、输入/
  executable 身份、bounded output、wall time/peak RSS 和统计报告的跨平台进程级
  benchmark 契约（Draft）。
- [`upstream-performance-baseline.md`](upstream-performance-baseline.md)：固定
  Linux Qt5 容器内的 process/database/单文件/batch/nested latency、noise 和
  peak-RSS 描述性基线（In Review）。
- [`upstream-performance-affinity.md`](upstream-performance-affinity.md)：固定
  Linux Qt5 五层 warm suite 的单 WSL2/Linux vCPU affinity 复验、cgroup
  证明、control RSS 采样边界与剩余物理核心/cold 门禁（In Review）。
- [`upstream-performance-repeated-sessions.md`](upstream-performance-repeated-sessions.md)：
  同一固定 affinity suite 的三次独立 invocation、51 warmup/270 measured、
  跨 session latency/p95/RSS 漂移及禁止冻结阈值的边界（In Review）。
- [`upstream-benchmark-file-access.md`](upstream-benchmark-file-access.md)：五个
  固定 case 双次 ptrace 的 2,283-file successful regular-file union、实际
  `.sg` 打开集合、33 个非脚本差集与 cold-controller 边界（In Review）。
- [`upstream-benchmark-page-cache.md`](upstream-benchmark-page-cache.md)：
  静态 controller 对相同 case 的完整 warm、逐文件
  `POSIX_FADV_DONTNEED`、前后 `mincore` 与双次 per-path residency
  复验，同时保留 metadata/overlayfs/cold 边界（In Review）。
- [`upstream-benchmark-file-content-performance.md`](upstream-benchmark-file-content-performance.md)：
  process runner plan/report schema v2 通过 preflight/exec/finalize 链接入同一
  静态 controller，对 warm/file-content 两状态完成五 case × 十组 ABBA
  latency/direct-child peak-RSS 测量、逐 run 身份/页状态证据与明确的
  system-cold/Rust/阈值边界（In Review）。
- [`upstream-benchmark-cache-environment.md`](upstream-benchmark-cache-environment.md)：
  固定容器 overlayfs、namespace、capability、只读 `/proc/sys` 与
  `drop_caches=EROFS` 的双次只读观察，以及三层 cache-state taxonomy 的环境
  边界（In Review）。
- [`windows-benchmark-cache-state.md`](windows-benchmark-cache-state.md)：
  固定原生 Windows build 26100/NTFS 的双次只读 API/token 观察，证明全局
  cache flush 需要当前 token 不具备的 privilege，并明确
  `NO_BUFFERING`、flush 与 process working-set 操作不能冒充 Linux per-file
  nonresident 或 dedicated system-cold（In Review）。
- [`macos-benchmark-cache-state.md`](macos-benchmark-cache-state.md)：
  固定 Apple XNU commit、`fcntl`/`mincore`/`msync`/`madvise` 契约，并建立
  unlink 后 temporary fixture 的双轮 `MS_INVALIDATE` + residency
  runtime-candidate 计划；当前仍无 Darwin observation，不 admission 第二层或
  system-cold（In Review）。
- [`upstream-build-baseline.md`](upstream-build-baseline.md)：固定 Linux Qt5/qmake CLI 构建与行为实验（Draft）。
- [`upstream-cmake-differential.md`](upstream-cmake-differential.md)：官方 CMake CLI 构建及与 qmake 的原始输出差分（Draft）。
- [`upstream-qt6-differential.md`](upstream-qt6-differential.md)：固定 Qt 6 CMake CLI 构建、Qt 5/Qt 6 原始差分与规则 warning 最小化（Draft）。
- [`qt6-capability-closure-plan.md`](qt6-capability-closure-plan.md)：将现有
  Qt6 证据映射到全部 68 项能力；当前为 68 complete/0 partial/0 missing，
  `CAP-GAP-007` closed（In Review）。
- [`qt6-cli-runtime-evidence.md`](qt6-cli-runtime-evidence.md)：固定 Qt5/Qt6
  的 26 样本分派、五样本七 formatter 和 escaping/nested 输出差分，并保留
  PE 的 Qt6 stderr 差异（In Review）。
- [`qt6-scan-nested-runtime-evidence.md`](qt6-scan-nested-runtime-evidence.md)：
  固定五样本 scan options 与 8 样本 nested gate 差分，并保存 alltypes 的
  Qt6 trailing MSDOS diagnostics（In Review）。
- [`qt6-special-runtime-evidence.md`](qt6-special-runtime-evidence.md)：
  固定五样本 special formatter/priority 和 28-case entropy/info/struct
  精确边界的 Qt5/Qt6 差分（In Review）。
- [`qt6-path-runtime-evidence.md`](qt6-path-runtime-evidence.md)：固定
  14-case 多目标、目录、空目录、重复/缺失 target 与 recursive path
  差分，并界定仍缺的复杂文件系统边界（In Review）。
- [`qt6-path-boundary-runtime-evidence.md`](qt6-path-boundary-runtime-evidence.md)：
  固定 23 个特殊路径、9 个 filesystem、5 个 large-directory、4 个 TOCTOU
  与 6 个 locale/filesystem case 的双轮 Qt6 完整重放，闭合
  `CAP-CLI-IN-003`（In Review）。
- [`qt6-database-runtime-evidence.md`](qt6-database-runtime-evidence.md)：
  固定 18-case database load/error/messages 矩阵及 parse/runtime error
  raw-first 诊断差分（In Review）。
- [`qt6-option-profiling-runtime-evidence.md`](qt6-option-profiling-runtime-evidence.md)：
  固定 verbose/profiling/test/createtest 九用例与 292 条 Binary 规则 profiling
  order 的 Qt5/Qt6 差分（In Review）。
- [`qt6-engine-contract-runtime-evidence.md`](qt6-engine-contract-runtime-evidence.md)：
  固定 37-case 四入口、device/subdevice、filter、cancel 与 sort 引擎契约，
  并验证 23 条确定性关系与 Qt5 完全一致（In Review）。
- [`qt6-rule-orchestration-runtime-evidence.md`](qt6-rule-orchestration-runtime-evidence.md)：
  固定 10-case 三层数据库、priority、init、file-type 与 mode gate 的 Qt5/Qt6
  规则编排差分（In Review）。
- [`qt6-result-model-runtime-evidence.md`](qt6-result-model-runtime-evidence.md)：
  固定五组 Qt6 engine harness 的 scalar、四类列表、flags、IDs、enums 与
  record metadata，并逐字段分类时间、UUID 和 parse diagnostic 差异（In Review）。
- [`qt6-signature-path-runtime-evidence.md`](qt6-signature-path-runtime-evidence.md)：
  固定 Qt6 private signature-path harness 的七用例完整输出，并验证与 Qt5
  逐字节相同（In Review）。
- [`qt6-debug-dispatch-runtime-evidence.md`](qt6-debug-dispatch-runtime-evidence.md)：
  固定 public resource 正控制、debug-data omission 与 direct debug 正例，并
  保留 Qt6 四行 PE warning（In Review）。
- [`qt6-resource-context-runtime-evidence.md`](qt6-resource-context-runtime-evidence.md)：
  固定 RT_MANIFEST 四种 recursive/aggressive 组合的完整 Qt6 raw 流、context
  字段与 Qt5 对照，并保留每次调用的四行 PE warning（In Review）。
- [`qt6-archive-option-runtime-evidence.md`](qt6-archive-option-runtime-evidence.md)：
  固定 64 个 engine archive-option case、32 个 release control 和内容寻址
  raw catalog，并验证与 Qt5 的完整语义一致性（In Review）。
- [`qt6-archive-dispatch-runtime-evidence.md`](qt6-archive-dispatch-runtime-evidence.md)：
  固定 APK/IPA/JAR/ZIP/RAR/NPM/ISO9660/Archive 八成员的公共与
  property-only Qt6 分派闭集（In Review）。
- [`behavior-baseline.md`](behavior-baseline.md)：确定性安全语料、原始输出哈希和多格式行为（Draft）。
- [`cli-json-schema-inventory.md`](cli-json-schema-inventory.md)：固定 CLI normal/entropy/info/struct JSON 字段、类型、顺序与失败边界（Draft）。
- [`cli-output-boundaries.md`](cli-output-boundaries.md)：固定 JSON/XML/CSV/TSV/plain text 的 Unicode/控制字符转义、嵌套排序和格式缺陷；闭合 `CAP-GAP-004`（Draft）。
- [`windows-output-matrix-extension.md`](windows-output-matrix-extension.md)：
  将 Windows 普通输出的 7-case 矩阵扩展到全部 26 个 baseline 样本，并固定
  四个动态 filetype 元素名导致的 invalid XML（Draft）。
- [`cross-platform-output-matrix-extension.md`](cross-platform-output-matrix-extension.md)：
  将剩余 21 样本的 7-case output 矩阵接入 Linux Qt5/Qt6，并与 Windows JSON
  projection、文档有效性及 priority 做三方差分（Draft）。
- [`scan-option-boundaries.md`](scan-option-boundaries.md)：固定 deep 实际增量、aggressive resource gate、默认 21/aggressive 2001 精确计数及 PE 每目录 1000 项 parser 限制；闭合 `CAP-GAP-005`（Draft）。
- [`cli-special-modes.md`](cli-special-modes.md)：entropy/info/struct 的 schema、优先级、临界熵、层级 filter、格式方法和多目标行为；闭合 `CAP-GAP-001`（Draft）。
- [`windows-special-matrix-extension.md`](windows-special-matrix-extension.md)：
  将 Windows entropy/info/struct 的 19-case 矩阵扩展到全部 26 个 baseline
  样本，固定结构化输出有效性和四组模式优先级（Draft）。
- [`cross-platform-special-matrix-extension.md`](cross-platform-special-matrix-extension.md)：
  将剩余 21 样本的 19-case special 矩阵接入 Linux Qt5/Qt6，并与 Windows
  structured projection 做三方差分（Draft）。
- [`cli-path-behavior.md`](cli-path-behavior.md)：多目标、目录递归、输出聚合和错误顺序（Draft）。
- [`special-path-behavior.md`](special-path-behavior.md)：固定 Linux Qt5 的
  NFC/NFD、非 UTF-8 原始字节、控制字符、hidden、前导短横线和目录排序
  （In Review）。
- [`path-filesystem-behavior.md`](path-filesystem-behavior.md)：固定 Linux Qt5 的
  file/directory/dangling symlink、alias 重复、mode-000 权限、depth-64 与
  self-cycle OS 边界（In Review）。
- [`large-directory-behavior.md`](large-directory-behavior.md)：固定 Linux Qt5
  flat/nested 4096-entry 完整枚举、顺序、描述性资源及 CLI 未接线
  `PDSTRUCT` cancellation 的源码边界（In Review）。
- [`path-toctou-behavior.md`](path-toctou-behavior.md)：固定 Linux Qt5 在完整
  枚举后的 symlink old→new 原子替换、unlink、stable controls 与当前路径
  reopen 行为（In Review）。
- [`path-locale-filesystem-behavior.md`](path-locale-filesystem-behavior.md)：
  固定 Linux Qt5 完整 `C`/`C.utf8`/`POSIX` locale 清单与 tmpfs/
  `ext2/ext3` volume 的两个大小写排序 profile，闭合 `CAP-GAP-003`
  （Draft）。
- [`cli-option-behavior.md`](cli-option-behavior.md)：verbose/messages/profiling channel 与 test/create test 遗留入口行为（Draft）。
- [`database-error-behavior.md`](database-error-behavior.md)：数据库缺失/损坏、规则错误和不可读输入（Draft）。
- [`database-archive-cache.md`](database-archive-cache.md)：ZIP 规则数据库边界、发布 CLI cache 可达性，以及 engine cache stale/corrupt/cancel 行为（Draft）。
- [`database-load-sizing.md`](database-load-sizing.md)：固定三层规则树、规范
  `ZIP_STORED` 尺寸及 directory/archive/cache 共用资源上限候选（In Review）。
- [`windows-database-archive-behavior.md`](windows-database-archive-behavior.md)：
  原生 Windows Qt5 的 17-case ZIP database 双轮差分、受限跨平台规范化和
  与 engine-only cache 证据的 reachability 边界（Draft）。
- [`windows-database-cache-behavior.md`](windows-database-cache-behavior.md)：
  原生 Windows Qt5 的 19-case engine cache/DACL 双轮基线、Linux 语义投影
  和平台 cache-byte 差异（Draft）。
- [`macos-database-cache-candidate.md`](macos-database-cache-candidate.md)：
  macOS Qt5 的 qmake main-object 替换 build closure、test-HOME 隔离、
  19-case engine cache/permission 双轮候选与离线 raw-replay validator；
  尚无 Darwin runtime（Draft）。
- [`windows-capability-closure-plan.md`](windows-capability-closure-plan.md)：
  将 23 份 Windows runtime 报告逐项映射到 68 行能力清单，当前为
  68 complete、0 partial、0 missing，且已接入总覆盖报告（In Review）。
- [`windows-path-closure-behavior.md`](windows-path-closure-behavior.md)：
  固定 Windows Qt5 的 4096-entry 顺序、dangling/cyclic reparse、同步
  TOCTOU、WSL UNC/extended-UNC 与本地/redirector access denial，关闭
  `CAP-CLI-IN-003`（In Review）。
- [`windows-archive-limit-behavior.md`](windows-archive-limit-behavior.md)：
  固定 Windows Qt5 的 depth 64、33,554,546-byte 累计展开量和取消部分前缀，
  30 次执行的确定性语义投影与 Linux Qt5 相等（In Review）。
- [`windows-cli-option-behavior.md`](windows-cli-option-behavior.md)：
  固定 Windows verbose/test/create-test/messages 和 292-rule profiling
  顺序，保留 `image_ICNS.sg` 的精确平台移动差异（Draft）。
- [`windows-rule-orchestration.md`](windows-rule-orchestration.md)：
  固定 Windows Qt5 的十个规则层、init/include、priority、mode/type gate
  case；canonical 语义和 14 条关系与 Linux Qt5 完全相同（Draft）。
- [`windows-engine-contract-behavior.md`](windows-engine-contract-behavior.md)：
  固定 Windows Qt5 的 37-case engine 入口、I/O/range、filter、sort 与
  cancellation 双轮证据，除 Qt 版本身份外与 Linux Qt5 完整语义相同（Draft）。
- [`database-layer-behavior.md`](database-layer-behavior.md)：main/extra/custom 同名规则、分层顺序、加载与运行时 gate（Draft）。
- [`engine-contract-behavior.md`](engine-contract-behavior.md)：engine 过滤/排序/停止/入口，以及 device/subdevice short-read、I/O、seek 和范围边界；闭合 `CAP-GAP-009` 与 `CAP-GAP-011`（Draft）。
- [`nested-scan-behavior.md`](nested-scan-behavior.md)：archive/resource/overlay 的选项可达性、结果树和资源限制（Draft）。
- [`data/cli-dependencies.toml`](data/cli-dependencies.toml)：固定组件依赖边、LICENSE blob 和 bundled code 证据。
- [`data/product-source-closure-linux-qt5.json`](data/product-source-closure-linux-qt5.json)：
  固定最终 ELF 的 237 个 compile source、逐组件/direct/archive/AUTOMOC 身份、
  根许可证及 `PRODUCT-LICENSE-GAP-001`。
- [`data/linux-cmake-install-tree.json`](data/linux-cmake-install-tree.json)：
  固定默认 CMake install 的 manifest、完整 staging tree identity、来源/路由、
  三产品二进制、重复内容和 CLI-only install 失败边界。
- [`data/linux-release-trees.json`](data/linux-release-trees.json)：固定 AppImage
  前置 AppDir 和两种 portable tree 的逐文件身份摘要、来源、规则/数据、qmake
  multiarch 布局及 fail-closed scope。
- [`data/xucl-origin.json`](data/xucl-origin.json)：官方 UCL 1.03 归档身份、
  XUCL 两文件的 12/64-token shingle 映射、许可证正文 hash 与 fail-closed
  复制/翻译结论。
- [`data/xarchive-license-closure-linux.json`](data/xarchive-license-closure-linux.json)：XArchive 106 个实际编译单元、217 个依赖文件及许可证/来源标记。
- [`data/xarchive-final-link-closure-linux.json`](data/xarchive-final-link-closure-linux.json)：
  XArchive 四个 archive 的 22-built/1-included/21-excluded GNU ld map、byte-identical
  链接重放、LZMA 五文件闭包及八个符号交集假阳性。
- [`data/xcapstone-license-closure-linux.json`](data/xcapstone-license-closure-linux.json)：
  XCapstone direct object、Capstone x86 archive 11 个构建/10 个抽取 member、
  最终 ELF 符号见证、71 个文件及三份许可证 hash。
- [`data/xsimd-license-closure-linux.json`](data/xsimd-license-closure-linux.json)：
  Formats/xsimd 三个单 member archive 的最终 ELF 符号见证、六文件依赖闭包、
  CUDA 排除关系和根 MIT LICENSE hash。
- [`data/embedded-compression-origins.json`](data/embedded-compression-origins.json)：聚合 Brotli/Zstandard 与固定官方 commit/生成物/许可证的内容对照。
- [`data/rar-decoder-origin.json`](data/rar-decoder-origin.json)：固定
  XArchive RAR decoder 的引入历史、RARLAB 官方归档与镜像的 159-file closure、
  两档 token shingle、许可证/归属证据与开放法律评审。
- [`data/yara-license-closure-linux.json`](data/yara-license-closure-linux.json)：YARA 51-object target、109-file dependency closure、官方 v4.5.2/TLSH 来源链和文件级许可证证据。
- [`data/rule-assets.json`](data/rule-assets.json)：五组固定 YARA/PEiD/signature 资产、逐文件历史/哈希、release/component 差异及 CLI/GUI/打包可达性证据。
- [`data/runtime-rule-assets-license.json`](data/runtime-rule-assets-license.json)：
  runtime 三层规则树的 2,268 文件 hash、作者/URL/许可标记和 22 个 PNG 清单。
- [`data/runtime-png-history.json`](data/runtime-png-history.json)：22 个 PNG
  的逐 blob/chunk/CRC、三种历史口径、两次来源 commit 和开放法律评审证据。
- [`data/baseline-corpus.json`](data/baseline-corpus.json)：生成语料的文件名、意图、大小和 SHA-256。
- [`data/output-boundary-fixture.json`](data/output-boundary-fixture.json)：输出转义规则、输入和嵌套语料的 hash-bound 清单。
- [`data/cli-output-boundaries-linux-qt5.json`](data/cli-output-boundaries-linux-qt5.json)：10-case 双 Qt5 formatter oracle 的完整原始 streams、身份和派生事实。
- [`data/cli-output-boundaries-linux-qt5-qt6.json`](data/cli-output-boundaries-linux-qt5-qt6.json)：
  10-case Qt5/Qt6 escaping/nested formatter 完整原始 streams、身份和派生事实。
- [`data/cli-output-matrix-linux-qt5-qt6.json`](data/cli-output-matrix-linux-qt5-qt6.json)：
  26 样本分派与五样本七 formatter 的 Qt5/Qt6 成对流哈希和 detection tree。
- [`data/cli-scan-nested-matrix-linux-qt5-qt6.json`](data/cli-scan-nested-matrix-linux-qt5-qt6.json)：
  五样本八 scan-option 及 8 样本四 nested gate 的成对哈希、相对变化和
  detection tree。
- [`data/qt6-alltypes-diagnostics.json`](data/qt6-alltypes-diagnostics.json)：
  alltypes/combined 三次重复的完整原始流、JSON 前缀、trailing diagnostics
  与地址规范化事实。
- [`data/cli-special-matrix-linux-qt5-qt6.json`](data/cli-special-matrix-linux-qt5-qt6.json)：
  五样本 19 special vectors 的成对退出码与 stdout/stderr 哈希。
- [`data/cli-special-boundaries-linux-qt5-qt6.json`](data/cli-special-boundaries-linux-qt5-qt6.json)：
  28-case entropy/info/struct 精确边界、两侧 oracle 身份和派生关系。
- [`data/cli-path-matrix-linux-qt5-qt6.json`](data/cli-path-matrix-linux-qt5-qt6.json)：
  14-case 基础 path matrix 的成对流哈希、filename prefixes、structured
  framing 和 recursive 相对变化。
- [`data/cli-database-matrix-linux-qt5-qt6.json`](data/cli-database-matrix-linux-qt5-qt6.json)：
  18-case database load/error/messages 的成对流哈希、load-error 标记与
  JSON framing。
- [`data/qt6-database-diagnostics.json`](data/qt6-database-diagnostics.json)：
  malformed parse/runtime throw 两次重复的完整原始流、JSON 前缀和精确诊断。
- [`data/cli-option-behavior-linux-qt5-qt6.json`](data/cli-option-behavior-linux-qt5-qt6.json)：
  九用例 CLI option 的完整 canonical streams、两侧身份和关系断言。
- [`data/binary-rule-order-linux-qt5-qt6.json`](data/binary-rule-order-linux-qt5-qt6.json)：
  两侧 292 条 Binary signature profiling announcements 的完整固定顺序。
- [`data/engine-contract-linux-qt6.json`](data/engine-contract-linux-qt6.json)：
  固定 Qt6 engine harness 的 37-case 原始身份、23 条关系、fixture 与源码审计，
  并与 Qt5 确定性投影成对校验。
- [`data/engine-contract-windows-qt5.json`](data/engine-contract-windows-qt5.json)：
  固定原生 Windows Qt5 engine-contract harness 的构建身份、双轮 raw、
  37-case/23-relationship Linux Qt5 比较与七文件源码审计。
- [`data/windows-qt5-cli-option-behavior.json`](data/windows-qt5-cli-option-behavior.json)：
  固定九个确定性 option case、292-rule 双轮 order、三个同样本 Linux
  control 和精确 Windows/Linux 顺序差异。
- [`data/rule-orchestration-linux-qt5-qt6.json`](data/rule-orchestration-linux-qt5-qt6.json)：
  固定 Qt5/Qt6 CMake oracle 的 10-case 规则执行顺序、detection、原始流身份和
  14 条关系。
- [`data/result-model-engine-qt6.json`](data/result-model-engine-qt6.json)：
  五组固定 Qt6 result-model harness 报告、Qt5 字段级差异和 CAP-RESULT-006
  组合证据。
- [`data/signature-path-engine-qt6.json`](data/signature-path-engine-qt6.json)：
  private comparator 的七用例 Qt6 运行时矩阵及固定 harness/image/raw-stream
  身份。
- [`data/debug-dispatch-engine-qt6.json`](data/debug-dispatch-engine-qt6.json)：
  Qt6 Formats 枚举、public recursive omission、direct debug detection 与精确
  stderr 差异。
- [`data/scan-option-boundary-fixture.json`](data/scan-option-boundary-fixture.json)：deep/aggressive 规则与 1/22/2002-resource PE 的 hash-bound 清单。
- [`data/scan-option-boundaries-linux-qt5.json`](data/scan-option-boundaries-linux-qt5.json)：8-case 双 Qt5 scan-option oracle 的去重原始 streams、身份和派生事实。
- [`data/scan-option-boundaries-linux-qt6.json`](data/scan-option-boundaries-linux-qt6.json)：
  相同 8-case 的双轮 Qt6 raw-stable 复验、Qt5 摘要对比和 21/2001 count
  边界。
- [`data/capability-traceability.json`](data/capability-traceability.json)：68 个稳定
  `CAP-*` 的验证层级、证据路径、平台范围和三个开放 coverage gap。
- [`data/capability-coverage.json`](data/capability-coverage.json)：68 行 × 4 平台
  的 272-cell 闭集分类、closed/open gap 到能力的显式映射和未分类计数。
- [`data/macos-qt5-oracle-plan.json`](data/macos-qt5-oracle-plan.json)：
  hash-bind macOS Qt5 CLI oracle bootstrap、validator 与上游构建入口，并明确
  保持 `platform_missing` 的预执行计划。
- [`data/qt6-capability-closure-plan.json`](data/qt6-capability-closure-plan.json)：
  将固定 Qt6 证据映射到全部 68 项能力并证明 closure required 为 0。
- [`data/archive-limit-engine-qt5-qt6.json`](data/archive-limit-engine-qt5-qt6.json)：
  14 个正常 archive-limit case、取消 control、Qt6 raw streams 和 Qt5 稳定
  projection 对照。
- [`data/archive-limit-engine-windows-qt5.json`](data/archive-limit-engine-windows-qt5.json)：
  相同 14 个正常 case 和取消 control 的 Windows Qt5 双轮执行、Linux Qt5
  稳定语义对照及 harness/build 身份。
- [`image-dispatch-behavior.md`](image-dispatch-behavior.md)：固定七种非
  JPEG/PNG 图像的自然 Binary fallback、强制 generic Image null adapter 和
  `CAP-GAP-012` 闭合证据。
- [`data/source-only-closure.json`](data/source-only-closure.json)：与当前空
  source-only 闭集严格相等的可执行关闭清单。
- [`data/legacy-dispatch-corpus.json`](data/legacy-dispatch-corpus.json)：
  Amiga Hunk/Atari ST 正例、截断、错误端序和近似 magic 控制的 hash-bound 清单。
- [`data/legacy-dispatch-linux-qt5.json`](data/legacy-dispatch-linux-qt5.json)：
  Amiga 正常分发及 Atari detector-only/Binary fallback 的双 Qt5 成对基线。
- [`data/legacy-dispatch-linux-qt5-qt6.json`](data/legacy-dispatch-linux-qt5-qt6.json)：
  相同 8-case 的双轮 Qt6 raw-stable 复验、Qt5 CMake 逐 stream 对比和
  `CAP-DISPATCH-003` 闭环报告。
- [`data/dos-dispatch-source-audit.json`](data/dos-dispatch-source-audit.json)：
  DOS/COM detector、BW legacy magic、scanner 分支和 property bypass 的
  SHA/line-bound 审计。
- [`data/dos-dispatch-corpus.json`](data/dos-dispatch-corpus.json)：七个公共
  DOS/COM filetype 的 19-case 正例、截断、近似 magic、chain、后缀和大小边界。
- [`data/dos-dispatch-linux-qt5.json`](data/dos-dispatch-linux-qt5.json)：
  七个公共 DOS/COM filetype 的 19-case 双 Qt5 runtime 基线。
- [`data/dos-dispatch-linux-qt5-qt6.json`](data/dos-dispatch-linux-qt5-qt6.json)：
  相同 19-case 的双轮 Qt6 detection-tree 对比、`info/string` extras 和
  MSDOS TypeError raw-first 分类。
- [`data/bw-dispatch-engine-qt5.json`](data/bw-dispatch-engine-qt5.json)：
  BW DOS16M automatic-negative 与 compact-property forced-positive 引擎基线。
- [`data/bw-dispatch-engine-qt5-qt6.json`](data/bw-dispatch-engine-qt5-qt6.json)：
  BW automatic/forced-property 双轮 Qt6 与 Qt5 完整 JSON/raw 等价报告。
- [`data/result-metadata-engine-qt5.json`](data/result-metadata-engine-qt5.json)：
  四个公共扫描入口的 `SCAN_RESULT` 标量字段、filename 语义和原始流哈希。
- [`data/result-list-fixture.json`](data/result-list-fixture.json)：两条重复
  detection、runtime error、parse error 和安全 Binary 输入的逐文件哈希。
- [`data/result-lists-engine-qt5.json`](data/result-lists-engine-qt5.json)：
  四个结果列表的空/非空、顺序、重复项和 handler option runtime 基线。
- [`data/result-flag-fixture.json`](data/result-flag-fixture.json)：normal、
  `~` heuristic、`!` advanced heuristic 与空数据库的逐文件哈希。
- [`data/result-flags-engine-qt5.json`](data/result-flags-engine-qt5.json)：
  三个独立结果 flag 的四行 Qt5 runtime 真值表和原始流哈希。
- [`data/result-ids-engine-qt5.json`](data/result-ids-engine-qt5.json)：
  PE root/resource child 的完整 ID、parent ID、UUID anchor 与 edge 元数据。
- [`data/result-enum-fixture.json`](data/result-enum-fixture.json)：已知别名、
  heuristic、自定义原文与 Unknown fallback 的安全规则和输入哈希。
- [`data/result-enums-engine-qt5.json`](data/result-enums-engine-qt5.json)：
  原始 type/name、数值 enum、规范投影和保留 Unknown 槽位 Qt5 基线。
- [`data/signature-path-fixture.json`](data/signature-path-fixture.json)：
  main/extra 两层同名规则、良性 Binary 输入及七组 path-filter case 的哈希清单。
- [`data/signature-path-engine-qt5.json`](data/signature-path-engine-qt5.json)：
  private comparator 的 exact/empty/missing/case/`..`/basename Qt5 运行时矩阵。
- [`data/path-corpus.json`](data/path-corpus.json)：由基线字节组成的确定性嵌套目录树。
- [`data/special-path-fixture.json`](data/special-path-fixture.json)：确定性
  USTAR 特殊路径语料清单，不提交生成出的 TAR。
- [`data/special-path-engine-qt5.json`](data/special-path-engine-qt5.json)：
  23-case 双 Qt5 特殊路径/非 UTF-8 Oracle 的完整原始 streams、身份和冻结排序。
- [`data/path-filesystem-fixture.json`](data/path-filesystem-fixture.json)：
  symlink、权限、64 层目录与 self-cycle 的 deterministic GNU tar 清单。
- [`data/path-filesystem-engine-qt5.json`](data/path-filesystem-engine-qt5.json)：
  9-case 双 Qt5 文件系统路径 Oracle 的原始 streams、预检与冻结边界。
- [`data/large-path-fixture.json`](data/large-path-fixture.json)：empty、single、
  flat 256/4096 和 nested 4096 的 deterministic materialization plan。
- [`data/large-path-engine-qt5.json`](data/large-path-engine-qt5.json)：5-case 双
  Qt5 大目录 Oracle、完整原始 streams、source cancellation contract 与资源记录。
- [`data/path-toctou-fixture.json`](data/path-toctou-fixture.json)：32 MiB blocker、
  old/new targets、四个 mutation case 与 SIGSTOP/SIGCONT 同步协议。
- [`data/path-toctou-engine-qt5.json`](data/path-toctou-engine-qt5.json)：4-case
  双 Qt5 TOCTOU Oracle、mutation identity、source order 与原始 streams。
- [`data/path-locale-fixture.json`](data/path-locale-fixture.json)：21 个
  locale/case/normalization/非法 UTF-8 basename 与两种 filesystem 的确定性计划。
- [`data/path-locale-filesystem-engine-qt5.json`](data/path-locale-filesystem-engine-qt5.json)：
  3 locale × 2 filesystem × 2 Oracle 的完整顺序、charmap、原始 streams
  与源码契约。
- [`data/path-boundaries-linux-qt5-qt6.json`](data/path-boundaries-linux-qt5-qt6.json)：
  五组 47-case、94 次 Qt6 路径边界执行、25 个内容寻址 raw artifact 及
  Qt5 行为投影对照。
- [`data/database-fixture.json`](data/database-fixture.json)：项目生成的数据库成功/故障 fixture。
- [`data/database-archive-linux-qt5.json`](data/database-archive-linux-qt5.json)：两套固定 Qt5 oracle 的 17-case ZIP 数据库矩阵及两侧原始 stream。
- [`data/windows-qt5-cli-database-archive.json`](data/windows-qt5-cli-database-archive.json)：
  原生 Windows Qt5 的 17-case ZIP database、双轮 raw summary 及 Linux Qt5
  精确差分。
- [`data/database-cache-cli.json`](data/database-cache-cli.json)：发布 CLI cache-disabled 源码身份、删除副作用与 engine cache header 摘要。
- [`data/database-cache-engine-qt5.json`](data/database-cache-engine-qt5.json)：
  固定 Qt5 engine harness 的 cache miss/hit/stale、header/record corruption、
  cancel、write/permission failure 和 8-writer concurrency 十九状态原始报告。
- [`data/database-load-sizing.json`](data/database-load-sizing.json)：完整固定
  三层规则树的文件/path/container 观察量、8×/64× 候选 profile 和行为报告
  hash bindings。
- [`data/database-cache-engine-windows-qt5.json`](data/database-cache-engine-windows-qt5.json)：
  原生 Windows Qt5 的相同十九状态、两轮 raw stream hash、DACL 权限投影及
  Linux Qt5 cache-size 对照。
- [`data/windows-capability-closure-plan.json`](data/windows-capability-closure-plan.json)：
  hash-bound 的 Windows 68 行 closure 状态、证据路径、缺失范围和建议实验。
- [`data/database-layer-fixture.json`](data/database-layer-fixture.json)：三层同名/priority 规则的项目生成 fixture 清单。
- [`data/database-layers-engine-qt5.json`](data/database-layers-engine-qt5.json)：固定 Qt5 engine 的三层 materialization、同名保留和 runtime gate 原始报告。
- [`data/nested-corpus.json`](data/nested-corpus.json)：安全的 archive/resource/overlay 嵌套语料清单。
- [`data/archive-iteration-boundary-corpus.json`](data/archive-iteration-boundary-corpus.json)：
  三个 100001-record ISO9660 的确定性哨兵位置、大小和 SHA-256 清单。
- [`data/archive-iteration-boundary-engine-qt5.json`](data/archive-iteration-boundary-engine-qt5.json)：
  aggressive 第 100000 条可达、第 100001 条不可达的固定源码、镜像、原始输出
  和资源报告。
- [`data/archive-iteration-boundary-engine-qt6.json`](data/archive-iteration-boundary-engine-qt6.json)：
  第 99999 条可达、第 100000/100001 条不可达及每例额外 dot-entry Stream
  的固定 Qt6 报告。
- [`data/qt-null-filename-semantics-qt5-qt6.json`](data/qt-null-filename-semantics-qt5-qt6.json)：
  单 NUL `QByteArray` 在 Qt5/Qt6 `QString::fromLatin1` 下的 direct root-cause
  对照。
- [`data/archive-adversarial-corpus.json`](data/archive-adversarial-corpus.json)：
  12 个项目生成 ZIP 压缩、加密、畸形和 filter 控制的 hash manifest。
- [`data/archive-adversarial-engine-qt5.json`](data/archive-adversarial-engine-qt5.json)：
  44 次 release/harness default/archive/aggressive 原始输出、源码契约和结构摘要。
- [`data/archive-truncation-corpus.json`](data/archive-truncation-corpus.json)：
  7Z/RAR4/CAB/ISO9660 四个完整控制的 26 个确定性 EOF 前缀及逐文件哈希。
- [`data/archive-truncation-engine-qt5.json`](data/archive-truncation-engine-qt5.json)：
  26-case × 4 模式的 104 次原始输出、源码契约和严格截断边界摘要。
- [`data/archive-structure-corpus.json`](data/archive-structure-corpus.json)：
  四格式 56 个 control/结构字段 mutation 的 changed-byte 与 hash-bound 清单。
- [`data/archive-structure-engine-qt5.json`](data/archive-structure-engine-qt5.json)：
  56-case × 4 模式的 224 次原始输出、源码契约和结构字段行为摘要。
- [`data/archive-multirecord-corpus.json`](data/archive-multirecord-corpus.json)：
  四格式 × 正序/逆序/重名/空首记录的 16 个项目生成两成员 archive 清单。
- [`data/archive-multirecord-engine-qt5.json`](data/archive-multirecord-engine-qt5.json)：
  16-case × 4 模式的 64 次原始输出、固定身份及记录顺序/重名/空成员摘要。
- [`data/iso9660-endian-corpus.json`](data/iso9660-endian-corpus.json)：
  ISO9660 17 个双端序字段 × LE/BE 单侧 alternate 加控制的 35-case 清单。
- [`data/iso9660-endian-engine-qt5.json`](data/iso9660-endian-engine-qt5.json)：
  35-case × 4 模式的 140 次原始输出、固定身份及 LE/BE 冲突行为摘要。
- [`data/archive-format-corpus.json`](data/archive-format-corpus.json)：
  项目生成的七种 7Z 单 coder、x86/ARM64 BCJ+LZMA2、
  BCJ2+LZMA2 no-branch/E8/E9/JCC filter 链、七种基础 coder+7zAES、
  x86/ARM64 BCJ+LZMA2+7zAES、
  BCJ2+LZMA2+4×7zAES、RAR4
  store、CAB Store/MSZIP/LZX、带固定 LGPL 来源切片的 Quantum 与 ISO9660
  fixture 清单。
- [`data/archive-format-engine-qt5.json`](data/archive-format-engine-qt5.json)：
  四十一个 archive/coder 样本的 default/release/archive/aggressive 原始输出、
  六十六个 7Z AES 直接密码 case、固定身份和结构化摘要。
- [`data/rar5-store-corpus.json`](data/rar5-store-corpus.json)：
  两个项目生成 RAR5 Store/solid fixture 的 header、成员、solid 位与 hash-bound
  清单。
- [`data/rar5-store-engine-qt5.json`](data/rar5-store-engine-qt5.json)：
  RAR5 Store 单 PDF 与 solid 双 PDF 的 8 次固定 Qt5 原始输出、源码契约和
  结构化摘要。
- [`data/rar-compressed-fixture-source.json`](data/rar-compressed-fixture-source.json)：
  四个外部非 SFX RAR3/RAR5 压缩样本的固定来源、CC0/creator evidence、
  header/method/solid 结构和开放再分发评审。
- [`data/rar-compressed-engine-qt5.json`](data/rar-compressed-engine-qt5.json)：
  RAR3/RAR5 压缩/solid 的 16-run 固定 engine oracle、原始输出和确定性投影。
- [`data/archive-gap-closure.json`](data/archive-gap-closure.json)：
  六份固定 archive oracle 与 Formats/XScanEngine 源码共同生成的
  `CAP-GAP-006` 机器闭合报告。
- [`data/archive-dispatch-linux-qt5-qt6.json`](data/archive-dispatch-linux-qt5-qt6.json)：
  八成员 public/private Qt6 archive 分派、NPM/generic harness、14 个
  content-addressed raw artifact 与 Qt5 projection 对照。
- [`data/npm-dispatch-fixture.json`](data/npm-dispatch-fixture.json)：
  项目生成的 NPM 精确路径正例、无效 JSON 正例及路径/大小写近似反例清单。
- [`data/npm-dispatch-engine-qt5.json`](data/npm-dispatch-engine-qt5.json)：
  NPM 直接检测、自动/强制 engine 分派、双 Qt5 release 原始输出及源码/规则
  哈希契约。
- [`data/generic-archive-dispatch-fixture.json`](data/generic-archive-dispatch-fixture.json)：
  项目生成的 ZIP/TAR/GZIP 通用 Archive 分派 fixture 清单。
- [`data/generic-archive-dispatch-engine-qt5.json`](data/generic-archive-dispatch-engine-qt5.json)：
  自动/强制 quiet/verbose 分派、双 Qt5 release 原始输出和源码/规则哈希契约。
- [`data/resource-context-chain-qt5.json`](data/resource-context-chain-qt5.json)：RT_MANIFEST 父扫描、resource context、scan ID 与原样规则结果的四模式端到端基线。
- [`data/resource-context-chain-qt6.json`](data/resource-context-chain-qt6.json)：
  同一 RT_MANIFEST 四模式的 Qt6 完整 raw stdout/stderr、逐案 Qt5 对照和
  九项 context/gate 关系。
- [`data/archive-option-engine-qt5-qt6.json`](data/archive-option-engine-qt5-qt6.json)：
  192 次 Qt5/Qt6 archive-option/release 执行、20 个唯一 raw stream、
  18 个 detection tree 与 11 项 option/gate 关系。
- [`data/archive-option-engine-windows-qt5.json`](data/archive-option-engine-windows-qt5.json)：
  128 次原生 Windows Qt5 engine 执行、32 个 release control、18 个
  detection tree 与 11 项 option/gate 关系。
- [`data/count-boundaries-windows-qt5.json`](data/count-boundaries-windows-qt5.json)：
  archive 三点和 resource 八案各双轮的 22 次原生 Windows Qt5 执行、
  完整 Linux Qt5 对照及十四项关系。
- [`data/subdevice-source-audit.json`](data/subdevice-source-audit.json)：固定 XScanEngine/Formats 源码哈希、resource/overlay 调度及 debug-data 可达性审计。
- [`data/debug-dispatch-fixture.json`](data/debug-dispatch-fixture.json)：
  同时含 RT_MANIFEST resource 与 CodeView/RSDS debug directory 的项目生成 PE。
- [`data/debug-dispatch-engine-qt5.json`](data/debug-dispatch-engine-qt5.json)：
  Formats 枚举、public recursive omission 与 direct debug detection 的 paired
  Qt5 报告。
- [`data/debug-dispatch-engine-windows-qt5.json`](data/debug-dispatch-engine-windows-qt5.json)：
  原生 Windows Qt5 两轮 paired harness、九项关系及 Linux Qt5 完整语义文档
  对照。
- [`data/boa-rule-runtime.json`](data/boa-rule-runtime.json)：Boa spike 输入哈希、固定版本和稳定结果摘要。
- [`data/rquickjs-rule-runtime.json`](data/rquickjs-rule-runtime.json)：rquickjs spike 输入哈希、固定版本和稳定结果摘要。
- [`resource-limit-evidence.md`](resource-limit-evidence.md)：区分固定上游
  archive/resource 临界值、oracle container 外部限额与 QuickJS 故障注入值，
  明确哪些证据不能直接升格为生产默认。
- [`include-graph-sizing.md`](include-graph-sizing.md)：全库 2,235 个程序文件的
  56 个 literal include 调用闭包、30 个 scope 的传递 evaluation/depth sizing，
  以及 Binary 静态结果与已有动态 trace 的连续性。
- [`data/include-graph-sizing.json`](data/include-graph-sizing.json)：绑定固定规则树、
  资产报告和逐 scope 计数的机器可读 include sizing。
- [`../design/data/resource-limit-policy-candidate.json`](../design/data/resource-limit-policy-candidate.json)：
  由固定报告、ADR 与 API SHA-256 绑定的统一资源限制评审候选；保留 9 个
  unresolved budget 和 `admitted=false`。
- [`data/rquickjs-static-link.json`](data/rquickjs-static-link.json)：rquickjs staticlib 三条 native smoke、链接依赖和 18-package 许可证清单。
- [`data/context-rule-qt5.json`](data/context-rule-qt5.json)：三条原样 Binary 规则在 resource/debugdata/text context 下的 8-case Qt5 基线。
- [`data/pe-rule-fixture.json`](data/pe-rule-fixture.json)：原样 Cygwin32 PE 规则的项目生成正例、反例和截断 PE32 输入。
- [`data/pe-rule-qt5.json`](data/pe-rule-qt5.json)：固定 XPE/PE_Script/QScriptEngine 的 3-case PE 规则 oracle。
- [`data/elf-rule-fixture.json`](data/elf-rule-fixture.json)：原样 Burneye ELF 规则的项目生成 ELF32/ELF64 正例、反例和截断输入。
- [`data/elf-rule-qt5.json`](data/elf-rule-qt5.json)：固定 XELF/ELF_Script/QScriptEngine 的 6-case ELF 规则 oracle。
- [`data/macho-rule-fixture.json`](data/macho-rule-fixture.json)：原样 Rust compiler Mach-O 规则的项目生成 x86_64/arm64 正例、反例和截断输入。
- [`data/macho-rule-qt5.json`](data/macho-rule-qt5.json)：固定 XMACH/MACH_Script/QScriptEngine 的 4-case Mach-O 规则 oracle。
- [`data/dex-rule-fixture.json`](data/dex-rule-fixture.json)：原样 QDBH DEX 规则的项目生成 string-table 正例、反例和 EOF 截断输入。
- [`data/dex-rule-qt5.json`](data/dex-rule-qt5.json)：固定 XDEX/DEX_Script/QScriptEngine 的 3-case DEX 规则 oracle。
- [`data/apk-rule-fixture.json`](data/apk-rule-fixture.json)：原样 QDBH APK 规则的项目生成 central record 正例、大小写反例和 local-record 截断输入。
- [`data/apk-rule-qt5.json`](data/apk-rule-qt5.json)：固定 XAPK/APK_Script/QScriptEngine 的 3-case APK 规则 oracle。
- [`data/archive-rule-fixture.json`](data/archive-rule-fixture.json)：原样 Archive metadata 规则的项目生成 stored ZIP、quiet 反例和 central-directory-only 输入。
- [`data/archive-rule-qt5.json`](data/archive-rule-qt5.json)：固定 XZip/Archive_Script/QScriptEngine 的 3-case Archive 规则 oracle。
- [`data/pdf-rule-fixture.json`](data/pdf-rule-fixture.json)：原样 PDF Tools 规则的项目生成 literal/hex/name object 与缺失 `endobj` 输入。
- [`data/pdf-rule-qt5.json`](data/pdf-rule-qt5.json)：固定 XPDF/PDF_Script/QScriptEngine 的 3-case PDF 规则 oracle。
- [`data/nintendo-certified-corpus.json`](data/nintendo-certified-corpus.json)：PS3/PS Vita Certified File 分支语料清单。
- [`data/nintendo-certified-baseline.json`](data/nintendo-certified-baseline.json)：双 oracle 原始输出哈希和 detection 摘要。
- [`data/binary-rule-lifecycle.json`](data/binary-rule-lifecycle.json)：固定 Binary records、helper 解析、源码 hash 和比较器环证据。
- [`data/binary-rule-order-linux-qt5.json`](data/binary-rule-order-linux-qt5.json)：固定 qmake/CMake oracle 的 292 条 Binary profiling 执行顺序。
- [`data/rule-orchestration-fixture.json`](data/rule-orchestration-fixture.json)：项目生成的规则编排数据库、输入和期望模式顺序清单。
- [`data/rule-orchestration-linux-qt5.json`](data/rule-orchestration-linux-qt5.json)：固定 qmake/CMake oracle 的规则编排原始哈希与规范化基线。
- [`data/rule-orchestration-windows-qt5.json`](data/rule-orchestration-windows-qt5.json)：固定 Windows Qt5 oracle 的十个规则编排 case、双轮 raw 身份和 Linux Qt5 逐字段对照。
- [`data/signature-path-engine-windows-qt5.json`](data/signature-path-engine-windows-qt5.json)：固定 Windows Qt5 private signature-path harness 的七用例双轮与 Linux Qt5 完整文档对照。
- [`data/result-model-engine-windows-qt5.json`](data/result-model-engine-windows-qt5.json)：五组固定 Windows Qt5 result-model harness 的双轮、30 次 case observation 与六行闭环证据。
- [`data/dispatch-engine-windows-qt5.json`](data/dispatch-engine-windows-qt5.json)：
  固定 Windows Qt5 的 86 次 legacy/archive dispatch 执行、72 次 case
  observation 与三行闭环证据。
- [`data/cli-option-behavior-linux.json`](data/cli-option-behavior-linux.json)：固定 qmake/CMake oracle 的 verbose/messages/profiling 与 test/create test 原始 CLI 基线。
- [`data/script-scope-fixture.json`](data/script-scope-fixture.json)：项目生成的跨规则作用域 fixture 清单。
- [`data/script-scope-qt5.json`](data/script-scope-qt5.json)：固定 qmake/CMake oracle 的作用域行为基线。
- [`data/script-state-fixture.json`](data/script-state-fixture.json)：项目生成的跨规则持久状态 fixture 清单。
- [`data/script-state-qt5.json`](data/script-state-qt5.json)：固定 qmake/CMake oracle 的持久状态行为基线。
- [`data/binary-cross-rule-state.json`](data/binary-cross-rule-state.json)：固定 Binary 顺序的跨规则状态静态审计摘要。
- [`data/signature-parser.json`](data/signature-parser.json)：signature 文法、Rust spike、固定 oracle 身份和差分覆盖摘要。
- [`data/signature-oracle-vectors.json`](data/signature-oracle-vectors.json)：89 个项目生成的 XBinary/`Binary_Script` 输入向量。
- [`data/signature-oracle-qt5.json`](data/signature-oracle-qt5.json)：固定 Qt 5 harness 的 89-case 原始结构化基线。
- [`data/signature-static-inventory.json`](data/signature-static-inventory.json)：全规则具名 signature API 调用点和保守静态值清单。
- [`data/net-bytecode-patterns.json`](data/net-bytecode-patterns.json)：固定 PE Generic 规则的 .NET bytecode pattern 有限值域。
- [`data/rule-syntax-inventory.json`](data/rule-syntax-inventory.json)：2235 个规则脚本的 AST、运算符、global 和宿主调用机器清单。
- [`data/host-api-inventory.json`](data/host-api-inventory.json)：固定 XScanEngine 宿主声明、继承和规则 arity 覆盖清单。
- [`data/host-api-arity-qt5.json`](data/host-api-arity-qt5.json)：固定 Qt 5 QObject wrapper 的额外实参与缺失方法异常基线。
- [`data/host-api-arity-qt6.json`](data/host-api-arity-qt6.json)：固定 Qt 6 QObject wrapper 的参数转换、diagnostic 与异常基线。
- [`data/host-api-arity-qt5-qt6.json`](data/host-api-arity-qt5-qt6.json)：两个格式 QObject runtime observation 的逐字段机器差分。
- [`data/global-host-api-inventory.json`](data/global-host-api-inventory.json)：固定 die_script global 注册面、规则函数和 undeclared direct-call 分类。
- [`data/global-host-api-qt5.json`](data/global-host-api-qt5.json)：真实 `DiE_ScriptEngine` 的 Qt 5 native global/query conversion、隔离对象图、空 `argv[0]` library mode、include error、PDSTRUCT、raw streams 与副作用基线。
- [`data/global-host-api-qt6.json`](data/global-host-api-qt6.json)：真实 `DiE_ScriptEngine` 的 Qt 6 native global/query conversion、cyclic-array crash、空 `argv[0]` library mode、include error、PDSTRUCT、raw stderr 与副作用基线。
- [`data/global-host-api-qt5-qt6.json`](data/global-host-api-qt5-qt6.json)：两个 runtime observation 的 94-field 逐字段机器差分。
- [`data/global-typo-corpus.json`](data/global-typo-corpus.json)：两个未定义 global 分支的 project-generated 安全最小语料及规则哈希。
- [`data/global-typo-errors-qt5.json`](data/global-typo-errors-qt5.json)：固定 qmake/CMake oracle 的 detection、trailing diagnostic 与原始输出哈希。
- [`data/global-typo-errors-qt5-qt6.json`](data/global-typo-errors-qt5-qt6.json)：固定 Qt 5/Qt 6 oracle 的相同 detection 与 runtime-specific `ReferenceError` 文本。
- [`data/qt5-qt6-cli.json`](data/qt5-qt6-cli.json)：固定 CMake Qt 5/Qt 6 CLI 的基础、安全语料和不可读输入原始差分。
- [`data/qt6-rule-warnings.json`](data/qt6-rule-warnings.json)：Qt6 PE warning 的可重复二分及唯一规则来源。
- [`data/qt-integer-bridge-fixture.json`](data/qt-integer-bridge-fixture.json)：项目生成的四类 Qt 整数返回桥接规则清单。
- [`data/c-static-link.json`](data/c-static-link.json)：C static-link spike 输入哈希、ABI 符号、平台依赖和稳定结果摘要。
- [`data/rust-toolchain-upgrade-1.97.1.json`](data/rust-toolchain-upgrade-1.97.1.json)：默认/MSRV 工具链身份、五个 spike 门禁和六条 native C consumer 复验摘要。
- [`data/windows-qt5-build-baseline.json`](data/windows-qt5-build-baseline.json)：
  Windows clean qmake build、Qt/MSVC 身份、官方 CMake xsimd 链接失败和最小
  PE64 runtime smoke 的机器证据。
- [`data/baseline-corpus-windows-qt5.json`](data/baseline-corpus-windows-qt5.json)：
  6 个 CLI 控制 case 与 26 个安全样本的 64 次原生 Windows Qt5 执行、原始
  hash、确定性检查和 Linux Qt5 detection projection 差分。
- [`data/windows-qt5-cli-matrix.json`](data/windows-qt5-cli-matrix.json)：
  338-case option/output/special 的 676 次原生 Windows Qt5 执行。
- [`data/windows-qt5-cli-output-remaining.json`](data/windows-qt5-cli-output-remaining.json)：
  剩余 21 个 baseline 样本 × 7 个普通输出 case 的 294 次原生 Windows Qt5
  执行、JSON continuity 和结构化输出有效性检查。
- [`data/linux-qt5-qt6-cli-output-remaining.json`](data/linux-qt5-qt6-cli-output-remaining.json)：
  剩余 21 个 baseline 样本 × 7 个普通输出 case 的 294 次 Linux Qt5/Qt6
  容器执行、精确 PE warning 和 Windows JSON projection 对照。
- [`data/windows-qt5-cli-special-remaining.json`](data/windows-qt5-cli-special-remaining.json)：
  剩余 21 个 baseline 样本 × 19 个 entropy/info/struct case 的 798 次原生
  Windows Qt5 执行、结构化 projection 和优先级检查。
- [`data/linux-qt5-qt6-cli-special-remaining.json`](data/linux-qt5-qt6-cli-special-remaining.json)：
  剩余 21 个 baseline 样本 × 19 个 special case 的 798 次 Linux Qt5/Qt6
  容器执行、raw 差分及 Windows structured projection 对照。
- [`data/windows-qt5-cli-path-nested.json`](data/windows-qt5-cli-path-nested.json)：
  14-case path 与 32-case nested 的 92 次原生 Windows Qt5 执行。
- [`data/windows-qt5-cli-database.json`](data/windows-qt5-cli-database.json)：
  18-case database success/error 的 36 次原生 Windows Qt5 执行及受限
  path/CRLF normalization 对照。
- [`data/windows-special-path-fixture.json`](data/windows-special-path-fixture.json)：
  Windows 可表示 Unicode/空格/Hidden 路径和不可表示 Linux 控制的固定清单。
- [`data/windows-qt5-cli-special-paths.json`](data/windows-qt5-cli-special-paths.json)：
  17-case Windows Unicode/特殊路径矩阵的 34 次原生 Qt5 执行。
- [`upstream-gui-analysis.md`](upstream-gui-analysis.md)：上游 DIE-engine
  三个 GUI 变体（`die`/`diel`/`diec`）的程序结构、功能清单、组件依赖和
  交互流程分析，固定到 `DIE-engine@ab0ea3e`，含 `die_widget`/`XOptions`/
  `XScanEngine` submodule 源码分析（Accepted）。
- [`cli-upstream-gap-closure.md`](cli-upstream-gap-closure.md)：diec CLI 与
  上游 release `diec` 的全部可观察行为差距分析，含 6 项缺口（G1-G6）、
  上游行为规范、diec 现有基础设施评估、RAR 许可证调研和 ADR 需求，为
  ROADMAP Phase 13 提供证据基础（Draft）。
- [`gui-gap-analysis-v4.md`](gui-gap-analysis-v4.md)：die-gui 与上游
  `die` GUI 的第四轮差距复核，固定到 `DIE-engine@23fec32`（2026-09-30），
  逐项实测当前实现（非复述 v3 结论），识别 V4-01~V4-22 差距项与
  v3 基线后的上游增量，为 ROADMAP Phase 17 提供证据基础（Draft）。
  历史轮次：v2/v3 未索引，见同目录 `gui-gap-analysis-v2.md` /
  `gui-gap-analysis-v3.md`。

每份文档遵守 [`../README.md`](../README.md) 的证据和状态约定。实验附件如需版本化，应使用文本格式并放入主题对应的子目录。
