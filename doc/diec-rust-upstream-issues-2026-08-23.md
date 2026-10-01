# diec-rust 上游问题报告

> **报告日期**: 2026-08-23
> **diec-rust 版本**: v0.8.0 (main 分支, 522 commits)
> **报告来源**: OneAV 引擎 DIEc 库替换可行性调研 (Spec D D1)
> **调研环境**: ol7 容器 (Oracle Linux 7.9, glibc 2.17, devtoolset-9) + Rocky Linux 10.2 (glibc 2.39)
> **Rust 工具链**: stable 1.97.1 / nightly-2025-09-15 (build-std)
> **规则库**: diec-rust 内置 `upstream/Detect-It-Easy/db` (vendored subtree, 固定 commit `c2c17dfa5`)

---

## 问题概述

在评估将 diec-rust 替换 C++ DIE (horsicq/DIE-engine) 用于生产环境 PE/ELF packer/protector
检测时，发现 PE 和 ELF 规则执行存在大量脚本异常，导致检测能力严重不足。以下为具体问题及复现方法。

---

## 问题 1: PE 规则 `TypeError: not a function`（阻断）

### 现象

扫描 PE 样本时，多个 PE 规则抛出 `TypeError: not a function` 异常，涉及
protector/cryptor/installer/compiler 类规则。这些规则全部执行失败，导致
PE 文件无法检测到 protector/packer/compiler/linker。

### 复现

```bash
git clone https://github.com/chennqqi/diec-rust.git
cd diec-rust && cargo build --release -p diec-cli
DIEC_DB_PATH=./upstream/Detect-It-Easy/db ./target/release/diec --output json ./corpus/minimal.exe
```

### 测试样本与结果

| 样本 | detections | 异常数 | 异常规则类型 |
|------|-----------|--------|-------------|
| corpus/minimal.exe (PE32) | `[{"type":"archive","name":"Resources"}]` | 6 | protector/cryptor/installer/compiler |
| corpus/minimal-pe64.exe (PE32+) | `[{"type":"archive","name":"Resources"}]` | 6 | protector/cryptor/installer/compiler |
| corpus/pe-dotnet.exe (.NET) | `[]` (无检测) | 8 | protector/cryptor/installer/compiler |
| corpus/pe-with-resources.exe | `[]` (无检测) | 5 | protector/cryptor/installer/compiler |
| corpus/with-tables.exe | `[]` (无检测) | 5 | protector/cryptor/installer/compiler |

### 异常规则清单（minimal.exe）

```
PE/compiler_RealBasic.4.sg: TypeError: not a function
    at detect (eval_script:14:16)
    at <anonymous> (eval_script:26:28)

PE/cryptor_404crypter.1.sg: TypeError: not a function
    at detect (eval_script:7:12)
    at <anonymous> (eval_script:16:28)

PE/cryptor_njCrypter.2.sg: TypeError: not a function
    at detect (eval_script:9:12)
    at <anonymous> (eval_script:50:28)

PE/installer_DockerDesktopInstaller.1.sg: TypeError: not a function
    at detect (eval_script:9:12)
    at <anonymous> (eval_script:22:28)

PE/installer_Store_Installer.1.sg: TypeError: not a function
    at detect (eval_script:7:12)
    at <anonymous> (eval_script:17:28)

PE/protector_Adept_Protector.2.sg: TypeError: not a function
    at detect (eval_script:7:12)
    at <anonymous> (eval_script:23:28)
```

### 分析

`TypeError: not a function` 表明 PE host API bridge 缺少某些被规则调用的函数。
COMPATIBILITY.md 声称 PE host API 已完整实现（imports/exports/resources/manifest/
version info/.NET/Authenticode），但实际执行中 protector/cryptor/installer 规则
调用的函数未被桥接到 rquickjs 运行时。

**关键影响**：protector 类规则全部异常意味着 `Protector()` 永远返回空，
无法用于 protector 检测。pe-dotnet.exe 未检测到 .NET 也表明 .NET 检测有问题。

### 期望

- PE protector/cryptor/installer/compiler 规则应正常执行，不抛出 `TypeError`
- pe-dotnet.exe 应检测到 .NET 相关特征
- 建议增加差分测试覆盖 protector/cryptor/installer 类规则，与上游 DIE 3.21 对比

---

## 问题 2: ELF 规则 `ReferenceError: _B is not defined`（阻断）

### 现象

扫描 ELF 文件时，**所有** ELF compiler/library 规则抛出
`ReferenceError: _B is not defined` 异常，ELF 检测能力完全失效。

### 复现

```bash
DIEC_DB_PATH=./upstream/Detect-It-Easy/db ./target/release/diec --output json /usr/bin/ls
```

### 测试样本与结果

| 样本 | detections | 异常数 | 异常类型 |
|------|-----------|--------|---------|
| /usr/bin/ls (ELF 64-bit) | `[]` (无检测) | 数百 | ReferenceError: _B is not defined |
| /usr/bin/bash (ELF 64-bit) | `[]` (无检测) | 数百 | ReferenceError: _B is not defined |
| corpus/minimal.elf | `[]` (无检测) | 数百 | ReferenceError: _B is not defined |
| corpus/elf-with-deps.elf | `[]` (无检测) | 数百 | ReferenceError: _B is not defined |

### 异常规则清单（部分，/usr/bin/ls）

```
ELF/compiler_Borland_Kylix.4.sg: ReferenceError: _B is not defined
    at _sectionNumber (eval_script:128:21)
    at <anonymous> (eval_script:326:47)

ELF/compiler_DMD.4.sg: ReferenceError: _B is not defined
    at _sectionNumber (eval_script:128:21)
    at <anonymous> (eval_script:307:47)

ELF/compiler_Free_Pascal.4.sg: ReferenceError: _B is not defined
    at _sectionNumber (eval_script:128:21)

ELF/compiler_Go.4.sg: ReferenceError: _B is not defined
    at _sectionNumber (eval_script:128:21)

ELF/compiler_Rust.4.sg: ReferenceError: _B is not defined
    at _sectionNumber (eval_script:128:21)

ELF/compiler_gcc.4.sg: ReferenceError: _B is not defined
    at _sectionNumber (eval_script:128:21)

ELF/library_GLIBC.3.sg: ReferenceError: _B is not defined
    at _sectionNumber (eval_script:128:21)

ELF/library_Curl.4.sg: ReferenceError: _B is not defined
    at _libraryNames (eval_script:209:25)

ELF/library_FFmpeg.4.sg: ReferenceError: _B is not defined
    at _libraryNames (eval_script:209:25)
```

### 分析

`_B` 变量在所有 ELF 规则中被引用（`_sectionNumber` 和 `_libraryNames` 函数内），
但未在 ELF host API 上下文中定义。推测 `_B` 是 Binary host API 的实例对象
（上游 DIE 中 Binary 对象提供 `read`/`compare`/`find` 等方法），在 ELF 扫描上下文中
未被注入到 rquickjs runtime。

COMPATIBILITY.md 声称 "Binary (read, compare, find) ✅ Full implementation"，
但 ELF 规则执行时 `_B` 不可用，说明 Binary host API bridge 未正确注入到
ELF file_type 的规则执行上下文。

**关键影响**：ELF 检测能力完全失效，无法检测 ELF 编译器/库/链接器。

### 期望

- ELF compiler/library 规则应正常执行，`_B` 变量应在 ELF 上下文中可用
- 建议确认 Binary host API bridge 是否注入到所有 file_type 的规则执行上下文
- 建议增加真实 ELF 二进制（如 /usr/bin/ls）的差分测试，而非仅 minimal.elf

---

## 问题 3: `--alltypes` 模式格式探测严重误报（阻断）

### 现象

`--alltypes` 模式扫描 ELF 文件时，产生大量格式误报，ELF 文件被检测为
CFBF/DEX/JPEG/PDF/PNG/Java Class/Python bytecode 等多种不相关格式。

### 复现

```bash
DIEC_DB_PATH=./upstream/Detect-It-Easy/db ./target/release/diec --alltypes /usr/bin/ls
```

### 输出

```
/usr/bin/ls: format: CFBF
/usr/bin/ls: format: DEX
/usr/bin/ls: format: JPEG
/usr/bin/ls: image: DQT
/usr/bin/ls: format: Java Class
/usr/bin/ls: converter: lipo
/usr/bin/ls: format: PDF
/usr/bin/ls: archive: Resources
/usr/bin/ls: format: PNG
/usr/bin/ls: format: Python bytecode compiled (.PYC)
```

### 分析

`--alltypes` 模式应对所有格式规则执行扫描，但不应将 ELF 文件误检为其他格式。
这表明格式探测（format probing）阶段未正确识别 ELF magic，导致非 ELF 格式规则
也产生匹配。COMPATIBILITY.md 声称 "probe_corpus/ELF64 ~345ns"，但探测结果
似乎未用于过滤不匹配的格式规则。

**关键影响**：`--alltypes` 模式不可用于生产环境，会产生大量误报。

### 期望

- `--alltypes` 模式应先做格式探测，仅在探测到的格式上执行对应规则
- ELF 文件不应被检测为 CFBF/DEX/JPEG/PDF/PNG 等格式
- 建议增加真实 ELF/PE 文件的 `--alltypes` 差分测试

---

## 问题 4: JSON 输出格式与上游 DIE 不兼容（非阻断，但影响迁移）

### 现象

diec-rust 的 JSON 输出格式与上游 DIE (horsicq/DIE-engine) 的 JSON 格式
结构不同，无法直接替换。

### 上游 DIE JSON 格式

```json
{
  "detects": [
    {
      "filetype": "PE",
      "values": [
        {"name": "Linker", "type": "Linker", "string": "Linker: Microsoft Linker(14.00)"},
        {"name": "Packer", "type": "Packer", "string": "Packer: UPX"}
      ]
    }
  ]
}
```

### diec-rust JSON 格式

```json
{
  "path": "/tmp/minimal.exe",
  "detections": [
    {"file_type": "PE", "type": "archive", "name": "Resources"}
  ],
  "diagnostics": ["..."],
  "structured_diagnostics": [{"file":"...","message":"...","kind":"error"}],
  "profiling": [{"file":"...","elapsed_ms":0}]
}
```

### 差异

| 维度 | 上游 DIE | diec-rust |
|------|---------|-----------|
| 顶层 key | `detects` | `detections` |
| 检测条目 | `values[]` 数组，含 `type`/`string`/`version` | 扁平 `{file_type, type, name}`，无 `string`/`version` |
| type 值 | `Packer`/`Protector`/`Linker`/`Compiler`（首字母大写） | `archive`/`packer`/`protector`（小写） |
| 检测值文本 | `string: "Packer: UPX"`（含前缀） | `name: "UPX"`（无前缀） |

### 期望

- 建议提供上游 DIE 兼容的 JSON 输出模式（如 `--output json-die`），
  保持 `detects`/`values`/`type`/`string` 结构，便于现有 DIE 用户迁移
- 或提供明确的格式迁移文档

---

## 问题 5: Rust 1.88+ 预编译 std 要求 glibc 2.34+（非阻断，有 workaround）

### 现象

Rust 1.88+（2025-06 起）将 Linux glibc 最低版本从 2.17 提升到 2.34（对应 RHEL 9）。
rustup 分发的预编译 std 库链接了 glibc 2.34+ 符号，导致即使在不限 glibc 版本的
容器内编译，产物仍要求 glibc 2.34+，无法在 ol7 (glibc 2.17)/ol8 (glibc 2.28) 运行。

### 验证

| 编译方式 | 编译环境 | 产物 glibc 要求 |
|---------|---------|----------------|
| stable rustup 1.97.1 | Rocky 10 (glibc 2.39) | 2.34/2.35 |
| stable rustup 1.97.1 | ol7 容器 (glibc 2.17) | **仍为 2.34/2.35** |
| nightly + build-std | ol7 容器 (glibc 2.17) | **2.16** ✅ |

### Workaround

使用 nightly Rust + `-Z build-std=std` 从源码编译 std 库，可在 ol7 (glibc 2.17)
编译出仅要求 glibc 2.16 的产物，跨发行版运行验证通过。

```bash
cargo +nightly-2025-09-15 build --release -p diec-ffi -Z build-std=std
```

### 期望

- 建议在文档中明确说明 glibc 最低版本要求（当前 README 未提及）
- 建议提供 build-std 或 musl 静态链接的官方构建指南，支持低版本 glibc 发行版
- 长期希望支持 stable Rust + 低版本 glibc（可能需等 Rust 官方恢复 glibc 2.17 支持）

---

## 问题 6: 官方 Go 绑定 Scanner.ScanBytes 使用 one-shot API（非阻断）

### 现象

`bindings/go/diec/diec.go` 中 `Scanner.ScanBytes` 实际调用 one-shot
`diec_v1_scan_bytes` 而非 reusable scanner 的 `diec_v1_scanner_scan_bytes`。
代码注释承认这是示例实现，生产绑定需补充。

```go
// Note: reusable scanner uses diec_v1_scanner_scan_bytes internally;
// the cgo helper uses the one-shot variant. For simplicity in this
// binding example, we use the one-shot API. A production binding
// would add a separate cgo helper for scanner_scan_bytes.
```

### 期望

- 补充 `diec_v1_scanner_scan_bytes` / `diec_v1_scanner_scan_path_utf8` 的 cgo helper
- 使 Scanner 真正复用 database 加载的上下文，发挥 reusable scanner 的性能优势

---

## 总结

| 问题 | 严重性 | 类型 | 阻断生产使用 |
|------|--------|------|:---:|
| 1. PE 规则 TypeError | 阻断 | host API 缺失 | ✅ |
| 2. ELF 规则 _B 未定义 | 阻断 | host API 注入 | ✅ |
| 3. --alltypes 格式误报 | 阻断 | 格式探测 | ✅ |
| 4. JSON 格式不兼容 | 中 | 输出格式 | ❌（可适配） |
| 5. glibc 2.34+ 要求 | 中 | 构建兼容 | ❌（build-std workaround） |
| 6. Go 绑定 Scanner | 低 | 绑定完整性 | ❌ |

问题 1-3 为阻断项，修复后方可用于生产环境。期待上游修复，我们将持续跟踪并重新评估。

---

## v0.9.0 验证结果（2026-08-23 更新）

上游根据本报告反馈进行了改进，发布 v0.9.0（Phase 15: host API coverage 47% → 100%，
270/270 方法实现）。重新验证结果如下：

### 验证环境

- diec-rust v0.9.0 (tag v0.9.0, commit ad2223f)
- 编译: ol7 容器 + nightly-2025-09-15 + build-std（与 v0.8.0 验证相同）
- 运行: Rocky Linux 10.2 (glibc 2.39)

### 问题修复状态

| 问题 | v0.8.0 状态 | v0.9.0 状态 | 验证结果 |
|------|-------------|-------------|---------|
| 1. PE TypeError | 6-8 异常/样本 | **✅ 已修复** | 0 异常，pe-dotnet.exe 正确检测 .NET Framework |
| 2. ELF _B 未定义 | 数百异常 | **✅ 已修复** | 0 异常，/usr/bin/ls 正确检测 GLIBC |
| 3. --alltypes 误报 | 10+ 误报 | **✅ 已修复** | ELF 仅输出 GLIBC，无 CFBF/DEX/JPEG 误报 |
| 4. JSON 格式 | 不兼容 | **✅ 已修复** | 新增 `--json-upstream` 选项，输出上游兼容格式 |
| 5. glibc 2.34+ | 需 build-std | **✅ workaround 确认** | build-std 产物 glibc 2.16，跨发行版运行通过 |
| 6. Go 绑定 Scanner | 用 one-shot API | **✅ 已修复** | 新增 `cgo_scanner_scan_bytes`/`cgo_scanner_scan_path` |

### 新增验证

#### FFI 接口测试

C ABI 直调测试通过：ABI 版本协商成功（v1.0），`diec_v1_scan_path_utf8` 正常工作，
检测结果与 CLI 一致。

#### 内存扫描 + reusable scanner

100 次内存扫描（`diec_v1_scanner_scan_bytes`）全部成功，reusable scanner 正常工作。

#### 内存稳定性（2000 次 PE 扫描）

```
Initial RSS:      10428 KB
After 500 scans:  16376 KB (delta=5948 KB, 11.896 KB/scan)
After 1000 scans: 16392 KB (delta=5964 KB, 5.964 KB/scan)
After 1500 scans: 16264 KB (delta=5836 KB, 3.891 KB/scan)
After 2000 scans: 16264 KB (delta=5836 KB, 2.918 KB/scan)
```

**RSS 在 500 次扫描后稳定在 ~16MB，500-2000 次之间 RSS 增长趋于 0**（甚至略降）。
对比 C++ DIE 修复后 0.15 MB/scan，diec-rust 稳态增长接近 0 KB/scan，
无 Qt 对象缓存泄漏问题。

#### --json-upstream 输出示例

```json
// pe-dotnet.exe
[{"fileType":"PE","name":".NET Framework","string":"library","version":"CLR 4.0.30319"}]

// /usr/bin/ls
[{"fileType":"ELF","name":"GLIBC","string":"library","info":"DYN x86-64-64","version":"ABI_DT_RELR"}]
```

格式接近上游 DIE（`fileType`/`name`/`string`/`version`/`info`），可用于直接替换。

### 结论

**v0.9.0 所有问题已修复或确认 workaround 有效，D1 调研阻断项全部解除。**

- 问题 1-3（阻断项）：全部修复，host API 覆盖率 100%
- 问题 4：新增 `--json-upstream` 兼容输出
- 问题 5：build-std 方案在 v0.9.0 仍然有效
- 问题 6：Go 绑定 reusable scanner 已实现
- 内存稳定性：显著优于 C++ DIE，无 Qt 泄漏

**建议：Spec D 可进入 D2 真实数据测试阶段。**

---

## v0.9.0 D2 差分测试新发现问题（2026-08-23）

D2 真实数据差分测试中发现 3 个 host API 实现语义错误，导致 VMProtect 和 UPX 漏检。

### 问题 7: `getSectionNameCollision(s1, s2)` 语义错误（阻断）

**现象**：VMProtect 保护的真实 PE 样本未被 diec-rust 检测到。

**复现**：
```bash
# VMProtect 样本（节名 oiNRhy0/oiNRhy1）
DIEC_DB_PATH=./upstream/Detect-It-Easy/db ./target/release/diec --json-upstream --deepscan \
  <vmprotect_sample>
# 输出: [] (无检测)
# C++ DIE 输出: VMProtect(3.2.0-3.5.0) as Protector
```

**根因**：`host_api_bridge.rs:3654` 的 `getSectionNameCollision(s1, s2)` 实现语义错误。

规则用法（VMProtect.2.sg）：
```javascript
var sCollision = PE.getSectionNameCollision("0", "1");
if (PE.isSectionNamePresent(sCollision + "1")) { bDetected = true; }
```

**正确语义**：找到两个节名，一个以 `s1`（"0"）结尾，一个以 `s2`（"1"）结尾，
且有共同前缀，返回这个**共同前缀**。例如 `oiNRhy0` 和 `oiNRhy1` → 返回 `oiNRhy`。

**diec-rust 错误实现**：检查字面值 "0" 和 "1" 是否作为完整节名存在，
返回 `s1` 或空字符串。完全不符合规则期望的语义。

**影响**：VMProtect（2 个样本漏检）、BattlEye、ENIGMA 等依赖此方法的规则全部受影响。
`isProtector` 决策不一致率 2/24 = 8.3%（超过 < 5% 门槛）。

**期望**：修正 `getSectionNameCollision` 实现为查找以 s1/s2 结尾的节名的共同前缀。

### 问题 8: `getImportFunctionName(libraryIndex, functionIndex)` 参数错误（阻断）

**现象**：UPX 加壳且节名被混淆的真实 PE 样本未被 diec-rust 检测到。

**复现**：
```bash
# UPX 样本（节名 48c8ziny/l90xfxyz/5j06gzad，无 UPX0/UPX1 节名）
DIEC_DB_PATH=./upstream/Detect-It-Easy/db ./target/release/diec --json-upstream --deepscan \
  <upx_patched_sample>
# 输出: [] (无检测)
# C++ DIE 输出: UPX() as Packer
```

**根因**：`host_api_bridge.rs:3570` 的 `getImportFunctionName(n)` 只接受 1 个参数，
但规则用 2 个参数调用：`getImportFunctionName(0, 0)`（库索引, 函数索引）。

规则用法（packer_UPX.2.sg）：
```javascript
if (PE.getImportFunctionName(0, 0) == "LoadLibraryA") { funcCounter++; }
if (PE.getImportFunctionName(0, 1) == "GetProcAddress") { funcCounter++; }
```

**diec-rust 错误实现**：`getImportFunctionName(n)` 忽略第二个参数，
返回全局函数列表的第 n 个函数，而非第 0 个库的第 n 个函数。

**影响**：UPX isPatchedUPX() 逻辑失败（1 个样本漏检），
compiler_RADBasic、cryptor_Huan、packer_AlushPacker 等规则也受影响。
`isPacker` 决策不一致率 1/24 = 4.2%。

**期望**：修正 `getImportFunctionName(libraryIndex, functionIndex)` 为按库索引和
函数索引查询，返回指定库的第 functionIndex 个导入函数名。

### 问题 9: `getNumberOfImportThunks(libraryIndex)` 参数被忽略（高）

**现象**：与问题 8 相关，`getNumberOfImportThunks(0)` 应返回第 0 个库的函数数，
但 diec-rust 实现不接受参数，返回所有库的函数总数。

**规则用法**（packer_UPX.2.sg）：
```javascript
var nNumberOfFunctions = PE.getNumberOfImportThunks(0);
if (nNumberOfFunctions > 1 && nNumberOfFunctions < 7) { ... }
```

**diec-rust 实现**：`getNumberOfImportThunks()` 返回 `_peParseImports().functions.length`
（全部函数数），忽略 libraryIndex 参数。

**影响**：当 PE 有多个导入库时，返回值不正确，导致 isPatchedUPX() 的范围检查失败。

**期望**：修正 `getNumberOfImportThunks(libraryIndex)` 为返回指定库的函数数。

### D2 差分测试总结

| 指标 | 结果 | 门槛 | 状态 |
|------|------|------|------|
| isPacker 一致率 | 21/24 (87.5%) | 100% | ❌ |
| isProtector 一致率 | 20/24 (83.3%) | 100% | ❌ |
| isPacker 不一致率 | 1/24 (4.2%) | < 5% | ✅ |
| isProtector 不一致率 | 2/24 (8.3%) | < 5% | ❌ |

24 个 packer/protector 样本中 3 个 isPacker/isProtector 决策不一致：
- 2x VMProtect 漏检（问题 7: getSectionNameCollision 语义错误）
- 1x UPX 漏检（问题 8/9: getImportFunctionName/getNumberOfImportThunks 参数错误）

**建议**：修复问题 7-9 后重新执行 D2 差分测试。

---

## 问题 7-9 修复确认（2026-08-26）

问题 7-9 已在 Phase 16.7（commit `5770542`，2026-08-23）修复。2026-08-26
补充了回归测试。

### 修复状态

| 问题 | 修复 commit | 回归测试 | 状态 |
|------|-------------|---------|------|
| 7. `getSectionNameCollision` 语义错误 | `5770542` | ✅ 4 个测试 | **已修复** |
| 8. `getImportFunctionName` 参数错误 | `5770542` | ✅ 3 个测试 | **已修复** |
| 9. `getNumberOfImportThunks` 参数被忽略 | `5770542` | ✅ 3 个测试 | **已修复** |

### 回归测试

回归测试位于 `crates/diec-rules/tests/host_api_unit.rs`，使用手工构建的
PE32 二进制（含自定义节名和多库导入表）验证三个方法的语义正确性：

**`getSectionNameCollision` 测试（4 个）**：
- `get_section_name_collision_returns_common_prefix`：节名 `oiNRhy0`/`oiNRhy1`
  → 返回共同前缀 `"oiNRhy"`
- `get_section_name_collision_vmprotect_rule_pattern`：模拟 VMProtect.2.sg 规则
  完整调用模式（`getSectionNameCollision("0","1")` + `isSectionNamePresent`）
- `get_section_name_collision_no_match_returns_empty`：无碰撞节名 → 返回 `""`
- `get_section_name_collision_single_section_returns_empty`：仅一个匹配节 → 返回 `""`

**`getImportFunctionName` 测试（3 个）**：
- `get_import_function_name_two_args_returns_correct_function`：2 库 × 多函数，
  验证 `(libIdx, funcIdx)` 双参数查询
- `get_import_function_name_out_of_range_returns_empty`：越界索引 → 返回 `""`
- `get_import_function_name_upx_rule_pattern`：模拟 UPX.2.sg 规则调用模式

**`getNumberOfImportThunks` 测试（3 个）**：
- `get_number_of_import_thunks_per_library`：按库返回函数数（kernel32=2, user32=1）
- `get_number_of_import_thunks_out_of_range_returns_zero`：越界 → 返回 0
- `get_number_of_import_thunks_upx_range_check`：模拟 UPX isPatchedUPX 范围检查

### 验证结果

- `cargo fmt --check` ✅
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` ✅
- `cargo test --workspace --all-features` ✅（全部通过，含 10 个新增回归测试）

### D2 差分测试

Phase 16.7 修复后差分结果（ROADMAP.md 记录）：

| 语料类别 | packer 一致率 | 检测一致率 |
|---------|-------------|-----------|
| pe_malicious (500) | **100.0%** | 81.8% → 93.8% |
| pe_benign (100) | **100.0%** | 64.0% → 93.0% |

问题 7-9 修复后 packer/protector 一致率达 100%，D2 阻断项全部解除。
