# 分析记录 024 — Tauri updater 生产管线落地（2026-10-12）

## 需求

用户确认：要自动更新；私钥存 GitHub secret、本人管控、他人无推送
权限、PR 需安全 review。据此把 Phase 48 的"部署决策"落地为 CI 管线。

## 设计

- `tauri.conf.json`：`bundle.createUpdaterArtifacts: true`；
  `plugins.updater.pubkey` 换生产公钥（`tauri signer generate` 生成，
  私钥在仓库外 ~/.tauri/，600 权限——由用户拷入 GitHub secret）。
- `release.yml`：
  - `preflight` job：`TAURI_SIGNING_PRIVATE_KEY` secret 缺失或 conf 残留
    dev pubkey → fail-fast（不烧 60min matrix）；build/build-gui needs
    preflight。
  - `build-gui`：三个 `cargo tauri build` 步骤注入签名 env → bundler
    自动产出 updater artifacts + `.sig`；raw 收集为
    `die-gui-updater-{windows,linux,macos}` artifacts。
  - `release`：`tools/updater/gen_latest_json.py` 扫描 artifacts 生成
    `latest.json`（signature = 整个 .sig 文件文本的 base64——
    tauri-plugin-updater 的解析格式，与 dev 夹具一致）→ 作为 release
    asset 上传，endpoint `releases/latest/download/latest.json` 生效。
- 平台映射：nsis `*-setup.exe`/`*.nsis.zip`→windows-x86_64、
  `*.AppImage.tar.gz`→linux-x86_64、`*.app.tar.gz`→darwin-aarch64。

## 验证

- gen_latest_json.py 本地构造三平台 artifacts 输出与 dev 夹具同构。
- `updater_flow` 5/5（测试用 DEV_PUB 显式覆盖，不受 conf 公钥切换影响）。
- YAML parse ok。

## 残留

- 私钥拷入 GitHub secret `TAURI_SIGNING_PRIVATE_KEY`（+空密码
  `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`）由用户完成。
- 真实 release 首跑时验证 artifacts 命名与 sig 产出（无法本地预演 CI）。
