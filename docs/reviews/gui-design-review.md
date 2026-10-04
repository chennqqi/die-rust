# GUI 设计文档评审记录

- 评审日期：2026-08-05
- 评审对象：
  - `docs/research/upstream-gui-analysis.md`
  - `docs/design/decisions/0018-tauri-gui-framework.md`
  - `docs/design/phase7-gui.md`
- 评审依据：`AGENTS.md`、`ROADMAP.md`、当前兼容基线
- 评审结论：三份文档整体结构完整，但存在与阶段规划及实现细节不一致的问题；修正后可进入 Accepted

## 总体评价

三份文档为 GUI 阶段提供了较完整的功能对齐基线与 Tauri 技术方案：

- 上游分析固定到 `horsicq/DIE-engine@ab0ea3e2764c9c5616362070be5c85404e3f7756` 和 `die_widget@5b48377`，符合基线锁定要求。
- 框架选型 ADR 记录了 Tauri v2 与 egui/Slint/Iced/GTK-rs 的对比，以及 WebView 跨平台权衡。
- Phase 7/8 GUI 设计文档覆盖了核心扫描、签名浏览、目录扫描、Hex 查看器、Demangle、设置等上游功能映射。

但文档中阶段命名、crate/程序命名、前端入口命名、`ScanFlags` 完整性等细节尚不统一，需要修订后才能作为实现基线。

## 主要发现与建议

### 1. 阶段命名不一致（严重）

- `AGENTS.md` 明确：
  - Phase 7 = 维护与上游同步
  - Phase 8 = GUI 规划（已交付，TODO，尚未开始实现）
- `docs/design/phase7-gui.md` 标题与正文均使用 **"Phase 7: GUI"**，与 `AGENTS.md` 冲突。
- **建议**：
  - 文件名改为 `docs/design/phase8-gui.md`（或至少标题改为 Phase 8）。
  - 更新 `AGENTS.md`、`ROADMAP.md` 及相关引用。
  - ADR 0018 中 "用户在 Phase 7 规划评审中选择 Tauri" 应改为 "Phase 8 GUI 规划评审"。

### 2. 程序/ crate 命名不一致（中）

- `docs/design/phase7-gui.md` 目标写 "图形界面程序 `die-gui`"。
- 后文 crate、架构、Workspace 集成均使用 `die-gui`。
- **建议**：统一使用 `die-gui`，与项目 `die-*` 前缀一致。

### 3. 前端入口文件命名不一致（中）

- ADR 0018 crate 结构写 `frontend/src/main.ts`。
- 技术栈为 React + TypeScript，主组件为 `App.tsx`；React/TS 项目标准入口应为 `main.tsx`。
- **建议**：将 `main.ts` 改为 `main.tsx`，并同步 `index.html` 引用。

### 4. `ScanFlagsDto` 缺少 `first_wrapper_only`（中）

- 上游 `comboBoxFlags` 包含 `Recursive/Overlay/Resource/Archive/Deep/Heuristic/Aggressive/Verbose/AllTypes/FirstWrapperOnly`。
- `phase7-gui.md` 中的 `ScanFlagsDto` 缺少 `first_wrapper_only`。
- **建议**：补齐该字段，并与现有 `die-engine::ScanFlags` 保持同步。

### 5. 上游 submodule 获取方式不可复现（中）

- `upstream-gui-analysis.md` 写 "通过 `git clone --depth 1` 获取后分析"，未指定分支或 commit。
- 固定 commit `die_widget@5b48377` 需要可复现的克隆/检出命令。
- **建议**：改为 `git clone --depth 1 --branch 5b48377 <repo-url>`，或记录 `git fetch` + `git checkout 5b48377`。

### 6. GUI 测试策略缺失（中）

- `phase7-gui.md` 列出了功能规格和 IPC 命令，但没有给出 GUI 专属测试计划。
- `AGENTS.md` 要求："每项能力包含单元/集成测试，并按风险补充差分、FFI、fuzz、性能和跨平台测试"。
- **建议**：补充 7A/7B/7C 各阶段的测试策略，包括：
  - Tauri 命令单元测试（模拟 `tauri::State`）
  - 前端组件测试
  - 跨平台 WebView 渲染一致性检查
  - 与上游 `die` GUI 的差分/截图验收标准

### 7. IPC 错误返回统一为 `String`（轻微）

- ADR 与设计中的命令均返回 `Result<..., String>`。
- 这不利于前端错误分类、国际化和日志分析。
- **建议**：定义结构化错误 DTO，例如 `GuiError { code: String, message: String }`。

### 8. 高级功能实现细节不足（轻微）

- 7B-4 Hex 查看器、7B-5 Demangle 仅列出上游映射，未给出实现库/接口设计。
- **建议**：在细化设计或原型验证后补充具体实现路径（例如 Demangle 使用 `cpp_demangle`/`rustc-demangle` 库，Hex 查看器组件选型）。

### 9. UI 库与状态管理尚未确定

- ADR 中 UI 库、状态管理方案仍标记为 "待定"。
- **建议**：在下一轮细化中确定 `shadcn/ui`/`MUI` 与 `Zustand`/`Redux Toolkit` 选型，并补充依赖审计。

## 结论

- `docs/research/upstream-gui-analysis.md` 保持 **In Review**，修正第 5 项后可接受。
- ADR 0018 与 `docs/design/phase7-gui.md` 保持 **Proposed**；完成第 1、2、3、4、6 项修订后，可进入 **Accepted/Ready for Implementation**。
- 评审记录保存于 `docs/reviews/gui-design-review.md`。

## 修订记录（2026-08-05）

全部 9 项发现已修复：

| # | 发现 | 修复 |
| --- | --- | --- |
| 1 | 阶段命名不一致 | 文件重命名 `phase7-gui.md` → `phase8-gui.md`，标题改为 Phase 8，更新 ROADMAP/AGENTS/README 引用 |
| 2 | 程序命名不一致 | 统一使用 `die-gui`（目标章节 + CI/CD 发布物） |
| 3 | 前端入口命名 | `main.ts` → `main.tsx`（ADR 0018 crate 结构） |
| 4 | ScanFlagsDto 缺字段 | 补齐 `first_wrapper_only` + `hide_unknown`，添加与 `die-engine::ScanFlags` 的映射说明 |
| 5 | submodule 获取不可复现 | 补充 `git clone` + `git checkout 5b48377` 可复现命令 |
| 6 | GUI 测试策略缺失 | 补充 7A/7B/7C 分阶段测试策略（单元/前端组件/集成/差分/跨平台 CI/WebView 一致性） |
| 7 | IPC 错误为 String | 定义 `GuiError { code, message }` 结构化 DTO，替换所有 `Result<..., String>` |
| 8 | 高级功能细节不足 | Hex 查看器补充 `react-hex-editor` + Channel 分块 + 后端搜索；Demangle 补充 `cpp_demangle`/`msvc-demangle`/`rustc-demangle` 选型和依赖审计表 |
| 9 | UI 库/状态管理待定 | 确定 shadcn/ui + Zustand + CodeMirror 6，补充选型理由表 |

修订后状态：
- `docs/research/upstream-gui-analysis.md` → **Accepted**（第 5 项已修复）
- `docs/design/decisions/0018-tauri-gui-framework.md` → **Accepted**（第 1、3、9 项已修复）
- `docs/design/phase8-gui.md` → **Accepted**（第 1、2、4、6、7、8 项已修复）
