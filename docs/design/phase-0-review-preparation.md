# Phase 0 评审准备材料

Status: Draft

Last updated: 2026-07-30

## 用途

本文汇总 Phase 0 三个可在 Windows 环境推进的阻塞项的当前证据状态和剩余缺口，
为设计/ADR 评审、许可证书面评审和性能基线冻结提供结构化输入。macOS 基线
(P0-BLOCK-005) 需 Darwin 主机执行，不在本文范围。

## P0-BLOCK-004: 许可证审计

### 实现方式与许可证边界

本项目用 Rust 从零重写上游 `diec` CLI 的扫描引擎，不复制、翻译或链接上游 C++
源码。上游二进制仅作为固定 oracle 运行。因此：

- **上游 C++ 组件许可证不传染 Rust 二进制**：XUCL (GPL)、UnRAR、Brotli、
  Zstandard 等组件的许可证约束仅适用于上游 C++ 编译产物，不影响独立重写的
  Rust 实现。
- **Rust 三方 crate 各自带许可证**：选用 `bzip2`、`lzma`、`zstd`、`brotli` 等
  crate 时，按 crate 自身许可证评估，与 XArchive 剥离声明无关。
- **引擎与规则分离**：`die-rust` 是扫描引擎，不包含检测规则。`db*` 规则文件
  来自独立的 `Detect-It-Easy` 仓库，由用户自行获取。引擎加载外部规则数据，
  不构成对规则代码的引用或衍生，引擎项目的许可证不约束规则文件。
- **上游 C++ 许可证审计仍有参考价值**：明确哪些组件不能直接复制代码。

### 上游 C++ 审计证据（参考性）

| 证据 | 文档 | 关键结论 |
| --- | --- | --- |
| 58 组件根许可证清单 | `component-license-inventory.md` | 58/58 根 MIT；12 个不同 SHA-256 |
| XUCL 来源追溯 | `xucl-origin.md` | UCL 1.03 GPL-2.0-or-later；不可复制到 Rust |
| RAR decoder 来源 | `rar-decoder-provenance.md` | UnRAR 7.13 逐字节匹配；不可复制到 Rust |
| 嵌入压缩来源 | `embedded-compression-origins.md` | Brotli MIT / Zstandard BSD+GPLv2；用 Rust crate 替代 |
| 产品源码闭包 | `product-source-closure.md` | 237 compile source；仅参考，不约束 Rust |
| XYara 构建闭包 | `yara-license-closure.md` | YARA build-only；不进入 `diec` CLI |

### YARA/PEiD/signatures 不进入当前 CLI 范围（但为未来 GUI 记录）

#### 源码级证据

`diec` CLI 不集成 YARA/PEiD/signatures（`rule-asset-provenance.md`）：

- `src/console/main_console.cpp` 只构造 `DiE_Script`，只注册 `db`/`db_extra`/
  `db_custom` 三类数据库路径
- `src/console/CMakeLists.txt` 不包含 XYara/XPEID/FormatWidgets
- `diec.dir/link.txt` 无 YARA、PEiD 或 signatures token

#### 三个辅助引擎的作用

**YARA**（XYara，MIT 许可证）：
- 独立的 YARA 扫描线程类，继承 `XThreadObject`
- 加载 `.yar` 规则文件，编译 YARA 规则，对文件执行 YARA 扫描
- 返回 `SCAN_STRUCT`（rule name、offset、size）
- 与 DiE_Script 规则引擎是**两个独立的并行检测通道**
- GUI CMake 默认 `WITH_YARA=ON`，链接 `yara` 库
- 规则文件：`Detect-It-Easy/yara_rules/`（8 文件，10,056 条规则）和
  `XYara/yara_rules/`（10 文件，10,069 条规则），两套不是镜像
- 部分规则文件含 GPLv2 标记（`crypto_signature.yar`、`packer.yar`、
  `packer_compiler_signatures.yar`）

**PEiD**（XPEID，MIT 许可证）：
- 继承 `XScanEngine`，是 PEiD `userdb.txt` 解析器和扫描器
- 重写 `_processDetect()` 和 `getSignaturesFromData()`
- 使用 PEiD 格式签名数据库识别 PE 文件的 packer/compiler
- GUI qmake 收集 `XPEID/xpeid.cpp`
- 规则文件：`Detect-It-Easy/peid_rules/`（11 文件，8,890 sections）和
  `XPEID/peid/`（14 文件，4,136 sections），两套不是镜像

**Signatures**（SearchSignatures，MIT 许可证）：
- GUI widget（在 `FormatWidgets/` 下），使用 `$data/signatures`
- 包含 `crypto.db`（3,085,459 bytes，crypto 签名）和 `junks.db`（junk 代码签名）
- `signatures.cmake` 只在定义 `X_RESOURCES` 时安装
- 四个数据文件无文件内许可证/来源标记，只有 component root MIT

#### 当前结论

`diec` CLI 的扫描能力 = `DiE_Script` 引擎 + `db*` 规则。YARA/PEiD/signatures
是 GUI 专属的辅助检测通道，不是 CLI 的可观察能力。Phase 0-6 不实现这些辅助
引擎，也不分发这些资产。

#### 未来 GUI 准备记录

ROADMAP Phase Future 明确 GUI 在核心库、CLI 和 C ABI 稳定后调研。当 Rust 项目
实现 GUI 时，需要：

1. **YARA 集成**：Rust 侧可用 `yara-rust` crate 或 FFI 绑定 YARA 库；需单独
   建立 YARA 规则的 capability matrix 和 runtime differential
2. **PEiD 集成**：需实现 PEiD userdb.txt 解析器；上游两套数据树不是镜像，
   需选择 Detect release tree 或 component tree
3. **Signatures 集成**：需实现 crypto/junk 签名数据库扫描器
4. **许可证门禁**：YARA 规则文件含 GPLv2 标记，PEiD/signatures 数据文件来源
   未完全确认；未来 GUI 分发这些资产时需完成许可证评审
5. **独立 capability matrix**：YARA/PEiD/signatures 不能伪装为 CLI 必需能力，
   需单独建立运行时差分和规则完整性门禁

### 剩余缺口

1. **Rust crate 许可证清单**：Phase 1 crate 选定后，用 `cargo deny` 或
   `cargo about` 生成依赖许可证清单。这是 Rust 项目的标准实践，不属于
   Phase 0 评审范围。
2. **NOTICE 文件**：发布前按 Rust crate 自身 LICENSE 要求生成 NOTICE 文件。
   同样是 Phase 1 实现期常规工作。

### 不再阻塞的事项

- ~~XUCL MIT/GPL 组合~~：Rust 侧不引用 XUCL 代码，GPL 传染性不适用
- ~~RAR decoder notice 缺失~~：Rust 侧用 `unrar` crate 或不支持 RAR 压缩
- ~~Brotli/Zstandard 声明剥离~~：Rust 侧用对应 crate，各自带 LICENSE
- ~~XArchive/XCapstone/XSIMD 编译闭包~~：不编译上游 C++ 组件
- ~~Windows/macOS/Qt6 闭包~~：不编译上游，平台闭包无许可证意义
- ~~db\* 规则资产分发许可~~：引擎项目不包含规则，规则由用户自行获取
- ~~YARA/PEiD/signatures 分发许可~~：不进入 CLI 范围，不分发
- ~~NOTICE/SBOM Phase 0 评审~~：Phase 1 实现期常规工作

### 评审输入准备状态

P0-BLOCK-004 的许可证阻塞已基本消解。上游 C++ 审计证据保留为参考文档。
剩余的 Rust crate 许可证清单和 NOTICE 文件是 Phase 1 实现期标准工作。
建议将 P0-BLOCK-004 状态从 Open 降为 Review Ready，等待评审确认关闭。

## P0-BLOCK-002/003: 设计文档与 ADR 评审

### 设计文档状态

| 文档 | 状态 | 阻止 Accepted |
| --- | --- | --- |
| Architecture | In Review | ADR 0002/0006、canonical result、limits、许可证和平台门禁 |
| API | In Review | ADR 0003、modern schema、候选准入、thread/path policy |
| C ABI | In Review | ADR 0001、runtime thread model、三平台和 Go/Python 验证 |
| Testing | In Review | ADR 0004、Windows/macOS oracle、Rust benchmark、production limit 验证 |
| Risks | In Review | 设计/ADR 评审结论及 runtime/license/platform/performance blocker |

### ADR 状态

14 个 Proposed ADR，全部 review_ready=true，全部 acceptance_ready=false。
关键未满足 acceptance 见 `adr-review-readiness.md`。

### 评审约束

- 评审可接受决策方向，但 acceptance conditions 被机器证据满足前不得改 Accepted
- 若 acceptance conditions 是实现期门禁，应先修改 ADR 拆分 Decision acceptance 与 Implementation exit
- 不能将 spike/Linux-only 证据外推为完整兼容

### 评审输入准备状态

评审输入结构完整，可提交评审。主要阻塞：需人工评审结论 + runtime/license/platform/performance blocker 关闭。

## P0-BLOCK-006: 性能基线与资源限制

### 已完成的技术证据

| 证据 | 文档 | 状态 | 关键结论 |
| --- | --- | --- | --- |
| 缓存环境边界 | `upstream-benchmark-cache-environment.md` | In Review | WSL2 容器无独立 cache domain |
| Page cache | `upstream-benchmark-page-cache.md` | In Review | per-file mincore=0 可控；非 system-cold |
| 文件内容性能 | `upstream-benchmark-file-content-performance.md` | In Review | 100 child paired；ratio 1.33-8.76x |
| Windows 缓存 | `windows-benchmark-cache-state.md` | — | warm 可复用；system-cold 需 dedicated infra |
| macOS 缓存 | `macos-benchmark-cache-state.md` | — | XNU flag + MS_INVALIDATE 候选 |
| 资源限制候选 | `resource-limit-policy.md` | — | 完整但未准入；hash-bound 机器契约 |

### 剩余缺口

1. **Production budget 冻结**：limit 候选已有机器契约，未冻结为 production 阈值。
2. **Rust 成对 benchmark**：需 Rust 实现后与上游成对测量。
3. **Dedicated system-cold**：需独立基础设施，非容器内可完成。
4. **macOS runtime benchmark**：需 Darwin 主机。
5. **Release size benchmark**：需最终发布包。

### 评审输入准备状态

上游 baseline 测量方法和缓存控制策略已充分验证。Resource limit 候选完整但需评审冻结。
Rust 侧 benchmark 需实现后执行。当前可提交 limit 候选评审和 cache 策略评审。

## 下一步建议

1. **许可证**：将本文许可证部分提交给发布/法律责任人，启动书面评审流程。
2. **设计/ADR**：组织设计文档和 ADR 评审会议，先接受决策方向，拆分 Decision acceptance 与 Implementation exit。
3. **性能**：冻结 resource limit 候选为 production 阈值（需评审），确认 cache 策略三层模型。
4. **macOS**：准备 Darwin 主机环境，执行已固定的 bootstrap 和 baseline 采集计划。
