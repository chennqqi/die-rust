# ADR 0018：Tauri GUI 框架选型

Status: Accepted
Last updated: 2026-08-05

## Context

ROADMAP.md "Future：GUI — TODO" 明确 GUI 在核心库、CLI 和 C ABI 稳定后另行
调研。Phase 1-6 已完成核心库、CLI、FFI 和 HTTP 服务层，GUI 是下一个交付项。

AGENTS.md 架构约束：

- "CLI 和 FFI 是核心库的薄适配层，核心层不得依赖它们或 GUI 框架" — GUI
  必须是薄适配层，`die-engine` 不得依赖 GUI 框架。
- "优先纯 Rust、跨平台依赖。引入大型依赖、native 依赖或系统库必须记录
  权衡" — GUI 框架选型需记录权衡。
- "默认不使用 `unsafe`" — GUI 框架的 unsafe 使用需审计。

上游 DIE-engine 使用 Qt（C++ + QMake/CMake），依赖约 50 个 submodule，
构建复杂且 Qt 是大型 native 依赖。die-rust 需要选择一个跨平台 GUI 框架
实现功能对等的图形界面。

### 候选框架

| 框架 | 语言 | 模式 | 系统依赖 | 二进制大小 | 生态 | unsafe |
| --- | --- | --- | --- | --- | --- | --- |
| **Tauri v2** | Rust + Web | Web 前端 + Rust 后端 | 系统 WebView | 小（~3-10MB） | 活跃，插件丰富 | 有（WebView FFI） |
| egui/eframe | 纯 Rust | Immediate mode | 无 | 中（~15MB） | 活跃 | 少 |
| Slint | Rust + .slint | 声明式 | 无（软件渲染） | 小（~5MB） | 中等 | 少 |
| Iced | 纯 Rust | Elm/retained | 无 | 中（~15MB） | 中等 | 少 |
| GTK-rs | Rust + GTK | Retained | GTK 库 | 大 | 中等 | 有（FFI） |

### 用户决策

用户在 Phase 8 GUI 规划评审中选择 **Tauri**，理由：

- Web 前端技术栈（HTML/CSS/JS）成熟，UI/UX 表达力强，适合复杂布局
  （TreeView、Splitter、多面板、主题切换）
- Rust 后端直接调用 `die-engine`，无需额外 FFI 层
- 二进制体积小（相比 Electron），适合分发
- 跨平台支持 Linux/Windows/macOS，与 die-rust 现有 CI 矩阵对齐
- 插件生态：文件对话框、拖放、单实例、自动更新、系统托盘等

## Decision

Proposed：选择 **Tauri v2** 作为 die-rust GUI 框架，新增 `die-gui` crate
作为薄适配层。

### 架构

```
┌─────────────────────────────────────────────┐
│  die-gui (Tauri app)                       │
│  ┌───────────────┐  ┌─────────────────────┐ │
│  │  Frontend     │  │  Rust Backend       │ │
│  │  (HTML/CSS/JS)│←→│  (tauri::commands)  │ │
│  │  UI 渲染      │  │  ↓                   │ │
│  │  状态管理      │  │  die-engine        │ │
│  │  事件处理      │  │  die-output        │ │
│  └───────────────┘  │  die-core          │ │
│                     └─────────────────────┘ │
└─────────────────────────────────────────────┘
        ↓ 依赖方向：die-gui → die-engine
        die-engine 不反向依赖 die-gui
```

### crate 结构

```
crates/die-gui/
├── Cargo.toml          # tauri + die-engine 依赖
├── tauri.conf.json     # Tauri 配置
├── src/
│   ├── main.rs         # Tauri app 入口
│   ├── commands.rs     # #[tauri::command] IPC 函数
│   ├── state.rs        # AppState（Database 缓存、设置）
│   └── settings.rs     # 设置持久化
├── frontend/           # Web 前端
│   ├── package.json
│   ├── src/
│   │   ├── main.tsx    # 前端入口（React + TSX）
│   │   ├── App.tsx     # 主组件
│   │   ├── components/ # UI 组件
│   │   ├── hooks/      # 自定义 hooks
│   │   └── i18n/       # 多语言
│   └── dist/           # 构建产物（嵌入二进制）
└── icons/              # 应用图标
```

### IPC 命令设计

Tauri 前端通过 `invoke('command_name', { args })` 调用 Rust 后端命令：

```rust
#[tauri::command]
async fn scan_file(
    state: tauri::State<'_, AppState>,
    path: String,
    flags: ScanFlagsDto,
    on_progress: tauri::ipc::Channel<ScanProgress>,
) -> Result<ScanResultDto, String> { ... }

#[tauri::command]
async fn scan_bytes(
    state: tauri::State<'_, AppState>,
    file_name: String,
    data: Vec<u8>,
    flags: ScanFlagsDto,
) -> Result<ScanResultDto, String> { ... }

#[tauri::command]
async fn list_signatures(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SignatureInfo>, String> { ... }

#[tauri::command]
async fn get_signature_source(
    state: tauri::State<'_, AppState>,
    file_type: String,
    name: String,
) -> Result<String, String> { ... }

#[tauri::command]
async fn scan_directory(
    state: tauri::State<'_, AppState>,
    dir: String,
    flags: ScanFlagsDto,
    on_progress: tauri::ipc::Channel<DirectoryScanProgress>,
) -> Result<Vec<ScanResultDto>, String> { ... }
```

长任务通过 `tauri::ipc::Channel` 流式推送进度事件到前端。

### 前端技术栈

- **框架**：React 19 + TypeScript（生态成熟，组件丰富）
- **构建**：Vite（快速 HMR，Tauri 官方推荐）
- **UI 库**：shadcn/ui（基于 Radix UI，无运行时样式注入，CSS 变量
  原生支持主题切换，组件源码复制到项目内可自由修改）
- **状态管理**：Zustand（轻量，无 boilerplate，适合 Tauri IPC 异步
  状态；避免 Redux Toolkit 的额外抽象层和包体积）
- **i18n**：react-i18next
- **代码编辑器**：CodeMirror 6（签名浏览器源码查看，轻量于 Monaco）

**选型理由**：

| 选型 | 理由 |
| --- | --- |
| shadcn/ui | CSS 变量原生主题切换（对齐上游 QSS 主题）；组件源码可控；无运行时 CSS-in-JS 开销；TreeView/Dialog/Dropdown 等组件覆盖 GUI 需求 |
| Zustand | Tauri IPC 异步状态管理简单（`create((set) => ({ scanResult: ... }))`）；无 provider 嵌套；包体积 ~1KB |
| CodeMirror 6 | 签名源码查看只需高亮和只读模式，CodeMirror 6 按需加载 ~50KB vs Monaco ~2MB |

### 设置持久化

上游使用 `QSettings`（INI 文件）。Tauri 方案：

- **Rust 端**：`tauri-plugin-store` 或自定义 INI/JSON 持久化
- 设置文件路径：`app_config_dir()/settings.json`
- 设置结构对齐上游 `XOptions` 的 `ID_*` 分类

### 跨平台 WebView 权衡

Tauri v2 使用系统 WebView：

| 平台 | WebView | 预装 | 备注 |
| --- | --- | --- | --- |
| Windows | WebView2 (Chromium) | Win11 预装，Win10 需安装 | Tauri 可捆绑 bootstrapper |
| macOS | WKWebView (Safari) | 系统自带 | 无额外依赖 |
| Linux | WebKitGTK | 需安装 `libwebkit2gtk-4.1` | 发行版包管理器安装 |

**权衡记录**：

- **优点**：二进制体积小（~3-10MB vs Electron ~100MB+），内存占用低，
  启动快，Rust 后端直接调用核心库
- **缺点**：依赖系统 WebView，Linux 需安装 WebKitGTK；不同平台 WebView
  引擎差异可能导致 CSS 兼容性问题；WebView FFI 涉及 `unsafe`
- **缓解**：CI 矩阵覆盖三平台 WebView；CSS 使用标准化子集；unsafe 限制
  在 Tauri 框架内部，die-gui 自身代码 `#![forbid(unsafe_code)]`

### 与上游 Qt 的差异

| 方面 | 上游 Qt | Tauri |
| --- | --- | --- |
| 语言 | C++ | Rust + TypeScript |
| UI 声明 | .ui XML | JSX/TSX |
| 渲染 | Qt 渲染引擎 | 系统 WebView |
| 系统依赖 | Qt 库（~50MB） | WebView（系统自带或小依赖） |
| 二进制 | ~20-30MB | ~3-10MB + 前端 |
| 设置 | QSettings (INI) | JSON/INI |
| 快捷键 | XShortcuts | 前端 keybinding 库 |
| 多语言 | XTranslation (Qt) | react-i18next |
| 主题 | QSS (Qt 样式表) | CSS |
| 单实例 | XSingleApplication | tauri-plugin-single-instance |
| 自动更新 | XUpdate | tauri-plugin-updater |

### unsafe 审计

Tauri 框架内部使用 `unsafe` 与系统 WebView FFI 交互。die-gui crate 自身
代码保持 `#![forbid(unsafe_code)]`，所有 unsafe 限制在 Tauri 依赖内部。
这与 die-rust 现有策略一致（`pelite`/`goblin` 等依赖内部有 unsafe，
核心 crate 自身 forbid unsafe）。

### 依赖审计

新增依赖：

| 依赖 | 版本 | 许可证 | 用途 |
| --- | --- | --- | --- |
| `tauri` | 2.x | Apache-2.0/MIT | Tauri 核心 |
| `tauri-build` | 2.x | Apache-2.0/MIT | 构建脚本 |
| `tauri-plugin-dialog` | 2.x | Apache-2.0/MIT | 文件对话框 |
| `tauri-plugin-fs` | 2.x | Apache-2.0/MIT | 文件系统访问 |
| `tauri-plugin-single-instance` | 2.x | Apache-2.0/MIT | 单实例 |
| `tauri-plugin-store` | 2.x | Apache-2.0/MIT | 设置持久化 |
| `serde`/`serde_json` | 已有 | MIT | IPC 序列化 |

前端依赖（npm）单独审计，不进入 Cargo 供应链。

## Alternatives considered

### egui/eframe

- **优点**：纯 Rust，无系统依赖，immediate mode 简单高效
- **缺点**：UI 表达力弱于 Web（复杂 TreeView、Splitter、主题系统需手写）；
  无原生文件对话框（需 egui-file-dialog）；多语言和主题生态弱
- **不选原因**：上游 die 的 UI 复杂度（多面板、签名编辑器、Hex 查看器、
  选项对话框）用 egui 实现成本高且 UI/UX 差距大

### Slint

- **优点**：声明式 UI，轻量，Rust 原生
- **缺点**：生态较小，组件库不如 Web 丰富；商业项目需付费许可；
  复杂布局（如 Hex 查看器）实现困难
- **不选原因**：生态和组件覆盖度不足以支撑全功能 GUI

### Iced

- **优点**：纯 Rust，Elm 架构清晰
- **缺点**：retained mode 性能一般；复杂 widget（TreeView、Splitter）需
  自行实现；生态中等
- **不选原因**：缺少成熟的高级组件库

### GTK-rs

- **优点**：原生 GTK 组件，Linux 集成好
- **缺点**：GTK 是大型 native 依赖（违反"优先纯 Rust"）；Windows/macOS
  GTK 安装复杂；GTK4 与 GTK3 兼容性问题
- **不选原因**：违反 AGENTS.md "优先纯 Rust、跨平台依赖" 原则

## Consequences

- **正面**：
  - Web 前端提供丰富 UI 组件生态，降低复杂布局实现成本
  - Rust 后端直接调用 `die-engine`，无额外 FFI 层
  - 二进制体积小，适合分发
  - Tauri 插件覆盖单实例、自动更新、文件对话框等需求
  - 跨平台 CI 与现有矩阵对齐

- **负面**：
  - 系统 WebView 依赖（Linux 需 WebKitGTK，Windows 需 WebView2）
  - WebView FFI 涉及 unsafe（限制在 Tauri 内部）
  - 前端 npm 供应链需单独审计
  - WebView 引擎差异可能导致 CSS 兼容性问题
  - 前端构建增加构建步骤（Vite + tauri-build）

- **缓解**：
  - CI 三平台覆盖 WebView 差异
  - die-gui crate `#![forbid(unsafe_code)]`
  - npm 依赖固定版本，定期审计
  - CSS 使用标准化子集，避免引擎特有特性

## Evidence

- 上游 GUI 源码分析：[`upstream-gui-analysis.md`](../../research/upstream-gui-analysis.md)
- Tauri v2 文档：https://v2.tauri.app/
- Tauri v2 IPC Channel：`tauri::ipc::Channel` 流式事件
- die-rust 现有架构：`docs/design/architecture.md` section 3 非目标
  "当前 workspace 不包含 `die-gui`，也不依赖 Qt 或其他 GUI 框架"
  — 本 ADR 解除该非目标限制
