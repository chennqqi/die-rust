# Phase 14 方法论回顾与系统性缺口清单

**日期**：2026-08-23
**背景**：Phase 0-13 声称"规则加载 100%、差分 0 不匹配"，但用户实际使用仍反馈了
3 个阻断性问题（ELF `_B` 未定义、PE host API 不完整、`--alltypes` 格式误报）。
本文档分析此前对齐方法论的系统性缺陷，举一反三梳理现有缺口，作为 Phase 15 的输入。

## 一、方法论缺陷根因

### 缺陷 1：差分测试是"自证"而非"他证"

**现象**：`corpus_differential.rs` 的 `CORPUS_EXPECTATIONS` 是硬编码的 `(type, name)` 对，
由开发者手工编写，而非从上游 DIE-engine 的实际输出中提取。

**后果**：
- 开发者根据自己的理解设定期望值，如果理解本身就是错的（如"ELF 文件无检测"），
  测试会"通过"但实际是错的
- 上游规则更新后，期望值不会自动更新，差分测试无法发现回归
- `testing.md` 设计了完整的"运行上游 oracle → 保存 raw record → 比较"流程，
  但从未实现

**Phase 14 的证据**：
- `minimal.elf` 的期望值是 `&[]`（无检测），但这是因为 ELF 规则全部抛 `ReferenceError`
  导致无检测，开发者把"bug 导致的结果"当成了"正确期望"
- `with-tables.exe` 的期望值也是 `&[]`，同理

### 缺陷 2：加载成功 ≠ 执行成功

**现象**：Phase 3/6 声称"1186/1186 规则加载成功（100%）"，但只验证规则文件能被
解析，不验证规则执行时是否抛异常。

**后果**：
- ELF 规则全部抛 `ReferenceError: _B is not defined`，但"100% 加载"统计完全不可见
- PE 规则抛 `TypeError: not a function`（`PE.isNET` 未定义），同样不可见
- 用户看到的是"100% 加载"的绿色信号，实际检测能力已失效

**根因**：`batch_load_*.rs` 测试只调用 `load_database`，不调用 `init` + `evaluate_rule`。
规则加载和规则执行是两个完全不同的阶段，加载成功只证明语法正确，不证明运行时正确。

### 缺陷 3：Host API 完整性声称缺乏对照验证

**现象**：`COMPATIBILITY.md` 用 ✅ 标记了 30+ 项 host API 能力，但没有逐项对照上游
help 文档或 `_init` 脚本。

**后果**：
- `PE.isNET`（大写）未实现，但 `COMPATIBILITY.md` 声称 `.NET detection: ✅`
- `PE.isResourceGroupNamePresent`/`isResourceGroupIdPresent` 未实现
- `PE.section`/`PE.resource` 数组硬编码为空，被 bridge JS 覆盖了 `_init` 脚本的填充
- 13 个 .NET 方法全是 stub（返回 false/空），但文档未标注
- 6 个 resource 枚举方法全是 stub

**根因**：没有建立"上游 help 文档方法清单 → bridge 实现对照表"的审计流程。

### 缺陷 4：`--alltypes` 测试只验证去重，不验证误报

**现象**：Phase 10 的 `--alltypes` 测试（`dedup.rs`）只验证"去重后检测数 ≤ 去重前"，
没有"不相关格式不应产生检测"的负向断言。

**后果**：`--alltypes /usr/bin/ls`（ELF）产生 CFBF/DEX/JPEG/PDF/PNG/Java Class 等
11 个误报，但测试全部"通过"。

### 缺陷 5：差分测试覆盖范围严重不足

**现象**：
- 只加载 `db/` 规则，不加载 `db_extra/`（PE 阻断规则多在此目录）
- 只用合成最小样本，不用真实系统二进制（`/usr/bin/ls`、`/usr/bin/bash`）
- 不覆盖小众格式（MSDOS/Amiga/AtariST/COM/DOS16M/DOS4G）
- 不覆盖 db_extra 的 protector/cryptor/installer/joiner/keygen 检测

**后果**：`db_extra/PE/cryptor_404crypter.1.sg` 调用 `PE.isNET()`，但此规则从未被
差分测试执行过，所以 `PE.isNET` 缺失从未被发现。

### 缺陷 6：设计文档与实际实现脱节

**现象**：`docs/design/testing.md` 设计了完整的差分流程（上游 oracle、raw record、
waiver 机制、能力矩阵追踪），但 `corpus_differential.rs` 只实现了最简单的硬编码期望值。

**后果**：设计文档给了"已覆盖"的错觉，实际实现远不如设计。

## 二、方法论缺陷的系统性表现

| 缺陷 | Phase 14 发现的阻断问题 | 此前为何未发现 |
|------|------------------------|---------------|
| 自证非他证 | ELF 规则全抛 ReferenceError | 期望值硬编码为"无检测"，把 bug 结果当正确 |
| 加载≠执行 | ELF `_B` 未定义、PE `isNET` 未定义 | 只测加载不测执行 |
| Host API 无对照 | PE 13 个 .NET 方法全 stub、6 个 resource 方法全 stub | 无 help 文档对照审计 |
| --alltypes 无负向断言 | ELF --alltypes 产生 11 个误报 | 只测去重不测误报 |
| 覆盖范围不足 | db_extra 规则从未被执行 | 不加载 db_extra、不用真实二进制 |
| 设计与实现脱节 | 所有上述问题 | 设计文档给了"已覆盖"错觉 |

## 三、举一反三：现有缺口清单

基于三个并行调研（方法论回顾、host API 方法对照、语料覆盖盲区），以下是系统性
检查后发现的现有缺口，按优先级排列。

### P0：阻断性缺口（影响检测能力）

| # | 缺口 | 影响 | 证据 |
|---|------|------|------|
| G1 | PE .NET 方法 13/13 全 stub | .NET 程序的 protector/cryptor/installer/compiler 检测全失效 | `isNetObjectPresent`/`compareEP_NET`/`getNETVersion` 等返回 false/空 |
| G2 | PE resource 枚举方法 6/6 全 stub | `PE.resource` 数组为空，resource 相关检测失效 | `getResourceNameByNumber` 等返回空/0 |
| G3 | `Binary.calculateMD5`/`calculateCRC32` 底层未实现 | 依赖哈希的规则失效 | HostApi trait 返回 `NotImplemented` |
| G4 | 差分测试不加载 db_extra | 100+ 个 db_extra 规则从未被差分测试执行 | `corpus_differential.rs` 只用 `DatabaseBuilder::new(db_root())` |
| G5 | 差分测试无脚本异常断言 | 规则执行异常不可见 | `corpus_differential.rs`/`edge_corpus.rs` 不检查 `structured_diagnostics` |
| G6 | 差分测试非真差分 | 自定期望值掩盖了 bug | 硬编码 `CORPUS_EXPECTATIONS`，无上游 oracle |

### P1：重要缺口（影响完整性）

| # | 缺口 | 影响 | 证据 |
|---|------|------|------|
| G7 | `PE.getDisasmLength` 缺失 | 反汇编长度相关规则失效 | Binary.md:535 声明，bridge 未实现 |
| G8 | `Binary.adler32` 缺失 | 依赖 adler32 的规则失效 | Binary.md:300 声明，bridge 未实现 |
| G9 | `ELF.getRunPath` 缺失 | ELF runpath 检测失效 | ELF.md:211 声明，bridge 未实现 |
| G10 | `MACH.getNumberOfCommands`/`getCommandId`/`isCommandPresent` 缺失 | Mach-O load command 检测失效 | MACH.md:29-37 声明，bridge 未实现 |
| G11 | `Util.shl64`/`shr64`/`secondsToTimeStr` 缺失 | 有符号移位和时间格式化规则失效 | Util.md:35/44/105 声明，bridge 未实现 |
| G12 | 小众格式无语料（MSDOS/Amiga/AtariST/COM/DOS16M/DOS4G） | 这些格式的规则从未被差分测试执行 | corpus/ 无对应样本 |
| G13 | db_extra protector/cryptor/installer 无语料 | 90+ 个 PE 扩展规则无样本验证 | corpus/ 无对应样本 |
| G14 | `--alltypes` 负向断言覆盖有限 | 仅 Phase 14 新增的 3 个测试有负向断言 | `differential_hardened.rs` 只覆盖 ELF/PE/Mach-O |
| G15 | `COMPATIBILITY.md` 的 ✅ 标记不准确 | 文档声称完整但实际有 stub | .NET/resource 方法标 ✅ 但全 stub |

### P2：改进缺口（提升质量）

| # | 缺口 | 影响 |
|---|------|------|
| G16 | 无上游 DIE-engine oracle 集成 | 无法做真差分 |
| G17 | `batch_load_*.rs` 只测加载不测执行 | 加载≠执行的问题持续存在 |
| G18 | 无 host API 方法覆盖率自动统计 | 无法量化 host API 完整性 |
| G19 | `corpus/manifest.json` 只有 `intended_format`，无期望检测值 | 语料清单信息不足 |

## 四、Phase 15 建议

基于上述缺口清单，建议 Phase 15 聚焦"对齐方法论重建"而非继续加功能：

1. **真差分测试框架**：集成上游 DIE-engine 作为 oracle，自动生成期望值
2. **规则执行覆盖率**：对每个规则执行 `init + evaluate_rule`，统计异常数
3. **Host API 方法对照表**：自动从上游 help 文档提取方法清单，对照 bridge 实现
4. **db_extra 纳入差分测试**：所有差分测试加载 db/ + db_extra
5. **脚本异常断言**：所有差分测试添加"脚本异常数应为 0"断言
6. **`--alltypes` 系统性负向断言**：所有格式 × 所有不相关格式的交叉验证
7. **小众格式语料补充**：MSDOS/COM/Amiga 等格式的最小样本
8. **COMPATIBILITY.md 修正**：标注 stub 方法，移除不准确的 ✅ 标记
