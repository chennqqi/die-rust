# 需求分析 019（2026-10-12）：剩余 Phase 48/49 开发

## 分析

ADR 0042 剩余 Conditional 项 = Phase 48（Tauri 自动更新）+ Phase 49
（主题扩展）。本轮按既定范围实现：

- **Phase 48**：`tauri-plugin-updater` v2.12.0（Cargo 锁）；dev
  Ed25519 密钥对经 Python `cryptography` 生成 minisign 签名夹具
  （`corpus/updater`，显式标注非生产）；测试用 `generate_context!`
  嵌入真实 `tauri.conf.json` + 本地 HTTP mock +
  `updater_builder` 端点覆盖，验证签名校验与四类失败模式
  fail-closed。生产密钥/endpoint/CI 签名管线保留为部署条件项。
- **Phase 49**：XStyles pin `948dd85` 检出后选 6 个代表 QSS 主题，
  仅翻译色板为 CSS 变量（非选择器等价——永久平台差异定位不变）。
  `custom_theme` 覆盖限定 16 个 palette 变量 + 值字符集白名单
  （防 CSS 注入）；theme 名加合法性守卫防手改 settings 崩溃。
  附带修复 App.tsx 语言下拉硬编码（改用 Phase 45
  `SUPPORTED_LANGUAGES`）。

## 验证

- `updater_flow.rs` 5/5；前端 tsc/build 通过；i18n 24×279 键全过
- 文档：ADR 0019 修订节、ADR 0042 状态表、ROADMAP、COMPATIBILITY

## XEmulator 性质确认（Blocked 项后续）

克隆 horsicq/XEmulator HEAD（b42b5f2，2026-09-25）：为 Qt/C++
库（xemuemulator 外观 + arch/os/format 三层），无 .pro 可执行目标；
上游 `xstaticunpacker.pri` 以 INCLUDEPATH+SOURCES 方式源码内嵌，
仅取 x86 核心（xemux86/memmgr/registers ≈6.9 kLOC）。XStaticUnpacker
pin 日期 2026-09-22 与其同期 → 判定为 DIE 组件库，按用户规则立项
Phase 50。上游调用点已自带步数/陷阱边界，安全设计镜像即可。
