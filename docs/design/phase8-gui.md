# Phase 8：GUI 设计文档

Status: Accepted
Last updated: 2026-08-05

## 目标

用 Tauri v2 实现功能对齐上游 `die` 完整 GUI 的图形界面程序 `die-gui`，
覆盖扫描、签名浏览、目录扫描、Hex 查看器、Demangle、设置、多语言和主题
等全部功能。

## 依据

- 上游 GUI 源码分析：[`docs/research/upstream-gui-analysis.md`](../research/upstream-gui-analysis.md)
- 框架选型 ADR：[`docs/design/decisions/0018-tauri-gui-framework.md`](decisions/0018-tauri-gui-framework.md)
- 现有架构：[`docs/design/architecture.md`](architecture.md)
- 现有引擎 API：`die-engine::{Scanner, scan_bytes, scan_once, ScanResult, ScanFlags, Database}`

## 架构

### crate 定位

`die-gui` 是 Tauri 应用 crate，属于适配层，依赖 `die-engine`/`die-output`/
`die-core`，核心层不反向依赖。与 `die-cli`/`die-ffi`/`die-server` 平级。

### workspace 集成

```toml
# Cargo.toml (workspace)
members = [
    "crates/die-core",
    "crates/die-formats",
    "crates/die-rules",
    "crates/die-engine",
    "crates/die-output",
    "crates/die-cli",
    "crates/die-ffi",
    "crates/die-server",
    "crates/die-gui",       # ← 新增
    "xtask",
]
```

`die-gui` 不加入 `die-ffi`/`die-server` 的依赖图，`xtask check-deps`
需更新依赖 DAG 规则以允许 `die-gui` 依赖 `tauri`。

### IPC 架构

前端（React/TS）通过 `invoke()` 调用 Rust 命令，长任务通过 `Channel`
流式推送进度：

```
Frontend (React)  ←→  Tauri IPC  ←→  Rust Commands  ←→  die-engine
     ↑                                                      ↓
     └──────── Channel<ScanProgress> ─────────────────  ScanResult
```

## 功能规格

### 7A：核心扫描 GUI（对标 diel + die 基础）

#### 7A-1 主窗口

| 功能 | 上游对应 | 实现 |
| --- | --- | --- |
| 文件名输入 | `lineEditFileName` + `toolButtonOpenFile` | 前端 input + Tauri dialog plugin |
| 拖放文件 | `dropEvent` | Tauri `onDragDropEvent` |
| Recent files 菜单 | `toolButtonRecentFiles` + `g_pRecentFilesMenu` | 前端 dropdown + settings |
| Advanced 切换 | `checkBoxAdvanced` | 前端 toggle |
| 全屏切换 | `fullScreenSlot` | Tauri window API |
| 单实例 | `XSingleApplication` | `tauri-plugin-single-instance` |
| 命令行参数 | `argv[1]` | Tauri `get_cli()` |
| 窗口标题 | `XOptions::getTitle` | Tauri config + 动态设置 |

#### 7A-2 扫描 widget

| 功能 | 上游对应 | 实现 |
| --- | --- | --- |
| 结果树展示 | `treeViewResult` + `ScanItemModel` | React TreeView 组件 |
| 结果列：String/Signature/Info | 3 列 | TreeView 3 列 |
| 点击 Signature → 显示源码 | `showSignature()` | invoke `get_signature_source` |
| 点击 Info → 显示帮助 | `showInfo()` → HTML/Google | 前端 modal + help docs |
| Flags 下拉 | `comboBoxFlags` | 前端 multi-select |
| Databases 下拉 | `comboBoxDatabases` | 前端 multi-select |
| Scan/Stop 按钮 | `pushButtonDieScanStart/Stop` | 前端 button + CancellationToken |
| 异步扫描 + 进度 | `QtConcurrent` + `QFutureWatcher` + `QTimer` | Tauri `Channel<ScanProgress>` |
| 扫描耗时显示 | `toolButtonElapsedTime` | 前端 label |
| 复制结果 | `copyResult()` | `navigator.clipboard` |
| 上下文菜单 | `customContextMenuRequested` | 前端 context menu |

#### 7A-3 扫描命令

```rust
/// Structured error DTO for all IPC commands.
/// Replaces bare `String` errors to enable frontend error
/// classification, i18n, and logging.
#[derive(Serialize, Deserialize)]
pub struct GuiError {
    /// Machine-readable error code (e.g. "DATABASE_LOAD_FAILED").
    pub code: String,
    /// Human-readable message (English, frontend i18n translates).
    pub message: String,
}

/// Scan flags mirroring upstream `XScanEngine::SF_*` and `comboBoxFlags`.
///
/// Field mapping to `die-engine::ScanFlags`:
/// - `deep`/`heuristic`/`verbose`/`aggressive`/`all_types`/`hide_unknown`
///   map directly to `ScanFlags` fields.
/// - `recursive`/`overlay`/`resources`/`archives`/`first_wrapper_only`
///   control nested-scan behavior in the engine's work-queue; they are
///   passed as scan-options metadata rather than `ScanFlags` struct fields.
///   When the engine exposes them as `ScanFlags` fields in the future,
///   the DTO mapping becomes 1:1.
#[derive(Serialize, Deserialize)]
pub struct ScanFlagsDto {
    pub recursive: bool,
    pub deep: bool,
    pub heuristic: bool,
    pub verbose: bool,
    pub aggressive: bool,
    pub alltypes: bool,
    pub overlay: bool,
    pub resources: bool,
    pub archives: bool,
    pub first_wrapper_only: bool,
    pub hide_unknown: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ScanDetectionDto {
    pub file_type: String,
    pub type_name: String,
    pub name: String,
    pub version: Option<String>,
    pub options: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ScanResultDto {
    pub path: String,
    pub detections: Vec<ScanDetectionDto>,
    pub diagnostics: Vec<String>,
    pub scan_time_ms: u64,
    pub file_size: u64,
    pub file_type: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum ScanProgress {
    Started { file_name: String, file_size: u64 },
    Progress { current: u64, total: u64, message: String },
    Finished { result: ScanResultDto },
    Error { message: String },
}

#[tauri::command]
async fn scan_file(
    state: tauri::State<'_, AppState>,
    path: String,
    flags: ScanFlagsDto,
    on_progress: tauri::ipc::Channel<ScanProgress>,
) -> Result<ScanResultDto, GuiError>;

#[tauri::command]
async fn scan_bytes(
    state: tauri::State<'_, AppState>,
    file_name: String,
    data: Vec<u8>,
    flags: ScanFlagsDto,
) -> Result<ScanResultDto, GuiError>;

#[tauri::command]
async fn stop_scan(state: tauri::State<'_, AppState>) -> Result<(), GuiError>;
```

#### 7A-4 设置持久化

| 设置分类 | 上游 `XOptions` ID | 实现 |
| --- | --- | --- |
| View | STYLE/QSS/LANG/FONT_*/STAYONTOP/ADVANCED | CSS 主题 + i18n + 前端 state |
| File | SAVELASTDIRECTORY/SAVERECENTFILES/SAVEBACKUP | settings.json |
| Scan | SCANAFTEROPEN/FLAG_*/HIDEUNKNOWN/SORT/LOG_PROFILING | settings.json |
| Database | DIE_DATABASE_*_PATH | settings.json + Tauri dialog |
| Engine | ENGINE_DIE/NFD/PEID/YARA_ENABLED | settings.json |

设置文件路径：`app_config_dir()/settings.json`，通过
`tauri-plugin-store` 或自定义 JSON 持久化。

### 7B：高级功能（对标 die 完整 GUI）

#### 7B-1 签名浏览器

| 功能 | 上游 `DialogDIESignatures` | 实现 |
| --- | --- | --- |
| 签名树（按文件类型分组） | `QTreeWidget` | React TreeView |
| 签名源码查看 | `DIE_SignatureEdit` + `die_highlighter` | Monaco/CodeMirror 编辑器 |
| 运行单个签名 | `pushButtonRun` | invoke `run_signature` |
| 调试模式运行 | `pushButtonDebug` | invoke `run_signature` (debug=true) |
| 编辑签名 | `checkBoxReadOnly` toggle | 编辑器 readOnly toggle |
| 保存签名 | `pushButtonSave` | invoke `save_signature` |
| 文本搜索 | `pushButtonFind/FindNext` | 编辑器内置搜索 |

```rust
#[tauri::command]
async fn list_signatures(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SignatureGroupDto>, GuiError>;

#[tauri::command]
async fn get_signature_source(
    state: tauri::State<'_, AppState>,
    file_type: String,
    name: String,
) -> Result<SignatureSourceDto, GuiError>;

#[tauri::command]
async fn run_signature(
    state: tauri::State<'_, AppState>,
    file_path: String,
    file_type: String,
    signature_name: String,
    debug: bool,
) -> Result<ScanResultDto, GuiError>;
```

#### 7B-2 目录扫描

| 功能 | 上游 `DialogDIEScanDirectory` | 实现 |
| --- | --- | --- |
| 选择目录 | `pushButtonOpenDirectory` | Tauri dialog |
| 扫描目录 | `pushButtonScan` | invoke `scan_directory` |
| 子目录递归 | `bSubdirectories` | 前端 checkbox |
| 结果累积 | `appendResult` | 前端 list + Channel |
| 清除/保存 | `pushButtonClear/Save` | 前端 button |

```rust
#[tauri::command]
async fn scan_directory(
    state: tauri::State<'_, AppState>,
    dir: String,
    flags: ScanFlagsDto,
    subdirectories: bool,
    on_progress: tauri::ipc::Channel<DirectoryScanProgress>,
) -> Result<Vec<ScanResultDto>, GuiError>;
```

#### 7B-3 签名 Profiling

| 功能 | 上游 `DialogDIESignaturesElapsed` | 实现 |
| --- | --- | --- |
| 每签名耗时 | `DEBUG_RECORD.nElapsedTime` | invoke `get_scan_profiling` |
| 按耗时排序 | 表格排序 | 前端 table sort |

#### 7B-4 Hex 查看器

| 功能 | 上游 `DialogDieHexViewer` + `XHexView` | 实现 |
| --- | --- | --- |
| Hex dump 显示 | `XHexView` | 前端 hex viewer 组件 |
| 偏移/ASCII/Hex 列 | `XHexView` columns | 前端 grid |
| 搜索 | `XHexView` search | 前端 search |
| 跳转偏移 | `XHexView` goto | 前端 input |

**实现选型**：

- 前端组件：`react-hex-editor`（React 原生，支持虚拟滚动和大文件）
  — 备选 `@uiw/react-textarea-code-editor` + 自定义 hex 渲染
- 大文件分块：Rust 后端通过 `tauri::ipc::Channel<&[u8]>` 流式推送文件
  分块（参考 Tauri 官方 `load_image` channel 示例），前端虚拟滚动
  仅渲染可见行
- 搜索：Rust 后端 `search_bytes(pattern, offset)` 命令返回匹配偏移列表，
  前端高亮跳转（避免前端加载全文件）

#### 7B-5 Demangle

| 功能 | 上游 `XDemangleWidget` + `XDemangle` + `XCppfilt` | 实现 |
| --- | --- | --- |
| C++ 符号 demangle | `XDemangle` | Rust `cpp_demangle` crate |
| GCC/MSVC/Itanium ABI | `XCppfilt` | `cpp_demangle` (Itanium) + `msvc-demangle` |
| Rust 符号 demangle | 无（上游无） | `rustc-demangle` crate（增值功能） |

**实现选型**：

| 依赖 | 版本 | 许可证 | 用途 |
| --- | --- | --- | --- |
| `cpp_demangle` | 0.4 | Apache-2.0/MIT | Itanium ABI C++ demangle |
| `msvc-demangle` | 0.9 | MIT | MSVC ABI C++ demangle |
| `rustc-demangle` | 0.1 | MIT/Apache-2.0 | Rust 符号 demangle（增值） |

三个 crate 均为纯 Rust，无 native 依赖，符合 AGENTS.md 约束。

```rust
#[tauri::command]
async fn demangle(symbol: String, compiler: String) -> Result<String, GuiError>;
```

#### 7B-6 Options 对话框

| 功能 | 上游 `DialogOptions` | 实现 |
| --- | --- | --- |
| 扫描引擎选项 | `XScanEngineOptionsWidget` | 前端 form |
| 签名搜索选项 | `SearchSignaturesOptionsWidget` | 前端 form |
| Hex 视图选项 | `XHexViewOptionsWidget` | 前端 form |
| 反汇编选项 | `XDisasmViewOptionsWidget` | 前端 form（反汇编未实现时禁用） |
| 在线工具选项 | `XOnlineToolsOptionsWidget` | 前端 form |
| InfoDB 选项 | `XInfoDBOptionsWidget` | 前端 form |

#### 7B-7 多语言

上游使用 `XTranslation`（Qt translation system）。Tauri 方案：

- 前端使用 `react-i18next`
- 翻译文件：`frontend/src/i18n/{en,zh-CN,...}.json`
- 语言切换：settings → i18n.changeLanguage
- 上游支持的语言从 `XTranslation` submodule 获取（en/ru/zh/zh-TW/ja/ko/
  de/es/fr/it/pl/pt-BR/tr等）

#### 7B-8 主题样式

上游使用 QSS（Qt 样式表）。Tauri 方案：

- CSS 变量定义主题色
- 上游内置主题：`orange_fix`（Windows 默认）、`Fusion`（style）
- 实现 light/dark/system 三种主题 + 自定义 QSS 等价 CSS

#### 7B-9 快捷键

上游使用 `XShortcuts`。Tauri 方案：

- 前端 `react-hotkeys-hook` 或 `useKeyPress`
- 全局快捷键：Open(Ctrl+O)、Exit(Ctrl+Q)、Fullscreen(F11)
- Hex/Disasm/Table 分组快捷键

#### 7B-10 自动更新

上游 Windows 使用 `XUpdate`。Tauri 方案：

- `tauri-plugin-updater`
- 更新源：GitHub Releases（与现有 release workflow 对齐）
- 签名验证：Tauri updater 公钥签名

### 7C：扩展功能（需独立 ADR）

以下功能依赖 native 库或上游未集成的引擎，需各自 ADR 记录权衡：

| 功能 | 依赖 | ADR |
| --- | --- | --- |
| 反汇编视图 | Capstone（`xcapstone`） | ADR 0019（待定） |
| YARA 规则 | YARA（`yara-rust`） | ADR 0020（待定） |
| PEID 签名 | PEID 数据库 | ADR 0021（待定） |
| NFD 视图 | Nauz File Detector | ADR 0022（待定） |
| 在线工具 | VirusTotal 等 API | ADR 0023（待定） |
| 熵视图 | 熵计算 | 复用 CLI `--entropy` |
| 哈希视图 | MD5/SHA1/SHA256 | Rust `sha2`/`md-5` |
| 内存映射视图 | PE/ELF section map | 复用 `die-formats` |
| 区段视图 | PE/ELF regions | 复用 `die-formats` |
| 符号表视图 | PE/ELF symbols | 复用 `die-formats` |
| 归档视图 | archive 内容 | 复用 `die-formats` |
| 数据转换器 | hex/dec/ascii/base64 | 前端实现 |
| 提取器 | overlay/archive 提取 | 复用 `die-engine` |

## 测试策略

AGENTS.md 要求"每项能力包含单元/集成测试，并按风险补充差分、FFI、fuzz、
性能和跨平台测试"。GUI 阶段按 7A/7B/7C 分阶段补充测试：

### 7A 阶段测试

**单元测试（Rust 端）**：

- IPC 命令单元测试：mock `AppState`（in-memory `Database`），验证
  `scan_file`/`scan_bytes`/`stop_scan` 返回值和 `GuiError` 错误码
- DTO 转换测试：`ScanResult` → `ScanResultDto` 字段映射完整性
- `ScanFlagsDto` → `die-engine::ScanFlags` 映射测试（含
  `first_wrapper_only` 等扩展字段的传递路径）
- 设置序列化/反序列化往返测试（`settings.json` 读写）
- `GuiError` 序列化测试（`code`/`message` 字段完整性）

**前端组件测试**：

- React 组件单元测试：`@testing-library/react` 测试结果树渲染、
  Flags/Databases 下拉交互、Scan/Stop 按钮状态
- IPC mock：`vi.mock('@tauri-apps/api/core')` 模拟 `invoke` 返回

**集成测试**：

- Tauri WebView smoke test（三平台 CI）：应用启动 → 窗口可见 →
  无 console error
- 端到端：打开文件 → 扫描 → 结果树展示 → 点击 Signature →
  签名源码显示
- 设置持久化往返：修改设置 → 重启应用 → 设置恢复

### 7B 阶段测试

**签名浏览器**：

- `list_signatures` 返回的树结构与上游 `DialogDIESignatures` 分组对齐
- `run_signature` 单签名执行结果与 CLI 对应规则输出差分
- 签名源码编辑 → 保存 → 重新加载一致性

**目录扫描**：

- `scan_directory` 批量扫描结果与 CLI `--recursive` 输出差分
- 子目录递归开关行为验证
- `Channel<DirectoryScanProgress>` 进度事件顺序和完整性

**Hex 查看器**：

- 大文件分块加载：`Channel<&[u8]>` 流式推送的正确性
- 搜索：`search_bytes` 返回的偏移列表准确性
- 跳转偏移边界测试（0、文件末尾、超出范围）

**Demangle**：

- Itanium ABI：`_ZN3foo3barEv` → `foo::bar()`
- MSVC ABI：`?bar@foo@@QEAAHXZ` → `int foo::bar()`
- Rust 符号：`_RNvCs1234_4test4main` → `test::main`
- 无效符号输入返回 `GuiError` 而非 panic

**多语言**：

- 所有 UI 字符串通过 i18n key 引用（无硬编码英文）
- 切换语言后 UI 即时更新
- 翻译文件 key 完整性检查（en vs zh-CN vs 其他语言）

**主题**：

- light/dark/system 三种主题切换
- CSS 变量覆盖完整性
- 主题持久化往返

### 7C 阶段测试

- 各扩展功能按各自 ADR 定义的测试策略
- native 依赖（Capstone/YARA）的 unsafe 边界测试

### 差分测试

- **GUI vs CLI 差分**：同一文件、同一 flags 下，GUI `scan_file` 返回的
  `ScanResultDto.detections` 与 CLI `diec --json` 输出的 detections
  逐字段对比，0 不匹配
- **签名列表差分**：`list_signatures` 返回的签名分组和名称与上游
  `DialogDIESignatures` 树结构对齐（固定到 `DIE-engine@ab0ea3e`）
- **截图验收**（可选）：关键界面截图与上游 `die` 截图对比，记录 UI/UX
  差异（不要求像素级一致，验证功能等价性）

### 跨平台 CI

扩展现有 `.github/workflows/`：

- `gui-build` job：Linux/Windows/macOS 构建 `die-gui`
- `gui-smoke` job：WebView 启动 + 基本交互 smoke test
- `gui-diff` job：GUI vs CLI 差分测试
- Linux 需安装 `libwebkit2gtk-4.1-dev`、`libgtk-3-dev`、
  `libayatana-appindicator3-dev`
- Windows 需 WebView2 bootstrapper
- macOS 使用系统 WKWebView（无额外依赖）

### WebView 渲染一致性

- 三平台 WebView 引擎差异（Windows WebView2/Chromium、macOS WKWebView/
  Safari、Linux WebKitGTK）可能导致 CSS 兼容性问题
- CI 中运行 WebView smoke test 检测启动失败和 JS console error
- CSS 使用标准化子集（避免 `-webkit-` 前缀等引擎特有特性）
- 关键布局在三平台手动验证或截图对比

## 交付物

### 代码

- `crates/die-gui/` — Tauri 应用 crate
- `crates/die-gui/src/commands.rs` — IPC 命令
- `crates/die-gui/src/state.rs` — AppState（Database 缓存）
- `crates/die-gui/src/settings.rs` — 设置持久化
- `crates/die-gui/frontend/` — React 前端
- `crates/die-gui/tauri.conf.json` — Tauri 配置

### 文档

- `docs/design/phase8-gui.md`（本文）
- `docs/design/decisions/0018-tauri-gui-framework.md`
- `docs/research/upstream-gui-analysis.md`
- 更新 `ROADMAP.md` Phase 8
- 更新 `README.md` GUI 章节

### CI/CD

- `.github/workflows/gui-build.yml` — GUI 构建矩阵
- 发布物包含 `die-gui` 可执行文件（三平台）

## 退出条件

- 功能对齐上游 `die` 完整 GUI（扫描、签名浏览、目录扫描、Hex、Demangle、
  设置、多语言、主题、快捷键、Recent files、拖放、单实例）
- 三平台（Linux/Windows/macOS）构建通过
- GUI 扫描结果与 CLI 差分 0 不匹配
- `cargo fmt --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` 通过
- `cargo test --workspace --all-features` 通过
- 7C 扩展功能（反汇编/YARA/PEID/NFD/在线工具）可 deferred 到后续 Phase

## 实现顺序

1. **7A-0**：创建 `die-gui` crate 骨架 + Tauri 配置 + workspace 集成
2. **7A-1**：主窗口 + 文件输入 + 拖放
3. **7A-2**：扫描命令 + 结果树 + Flags/Databases 控件
4. **7A-3**：异步扫描 + Channel 进度 + Stop
5. **7A-4**：设置持久化 + Recent files
6. **7B-1**：签名浏览器
7. **7B-2**：目录扫描
8. **7B-3**：签名 Profiling
9. **7B-4**：Hex 查看器
10. **7B-5**：Demangle
11. **7B-6**：Options 对话框
12. **7B-7**：多语言
13. **7B-8**：主题样式
14. **7B-9**：快捷键
15. **7B-10**：自动更新
16. **CI/CD**：GUI 构建矩阵 + 发布
