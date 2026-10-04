# Analysis 025 — 2026-10-04 — GitHub Actions 失败诊断与修复

## 请求
用户 push `7a383c490` 后 CI 又失败，要求获取失败信息、分析根因、修复。

## 证据收集（日志受限下的替代路径）
- job logs API 403（"Must have admin rights"，无 token、无 gh CLI、wine/mingw64 不可用）。
- 用 `check-runs/{id}/annotations` 拿到每个失败 step 的**退出码**：
  - msrv (ubuntu/macos/windows)：`cargo +1.88.0 clippy` / `test` → exit **101**（正常 cargo 失败）。
  - default (windows-2022)：`cargo test` → exit **127**（git-bash 下常见于"command not found"/进程未能启动）。
- run 历史 bisect：msrv clippy 自 `668c0af57`（Phase 21 NFD）起红；windows test 自 `36fa97f0f`（Phase 40）起红；`51722810c` 是最后全绿。

## 根因 A — MSRV 1.88 clippy `nonminimal_bool`（已修复+验证）
本地有 1.88.0 toolchain，直接复现 CI 命令，命中 8 处 lint：
- `pe_handlers.rs:2915`：`ok && !v.is_empty() || ok && !inf.is_empty()` → `ok && (a || b)`
- `lzh_decode.rs` ×3：`!(avail || fillup() || avail)` —— 两侧 `avail` 检查是**有意重复**（fillup 会改变 br），改为块表达式 `{ fillup(); recheck }` 保持语义
- `wim.rs` / `x86/decode.rs`：De Morgan 化简
注意点：1.97 clippy 不报这些 → AGENTS.md 已正确要求本地跑 1.88 clippy；此前提交漏跑。

## 根因 B — corpus/extract CRLF（已修复+验证）
windows-2022 镜像 git 默认 `core.autocrlf=true` → 无 `.gitattributes` 的文本型 oracle
快照 `corpus/extract/*`（无扩展名、ASCII 内容）检出为 CRLF →
`secondary_archives.rs` 15 个 `*_match_oracle` 测试逐字节比对失败。
本地用 `git -c core.autocrlf=true clone` 精确复现 15/15；新增
`.gitattributes: corpus/** -text` 后重克隆验证 **0 失败**（源码仍 CRLF、corpus 保持 LF）。

## 残余疑点 — default windows exit 127
与 msrv 的 101 不同，怀疑 die-gui `die` test exe 无法启动（缺 DLL/AV 拦截）或环境问题；
无法本地验证（wine 坏、无 mingw64）。若 push 后仍 127，需要用户从 GitHub UI 贴日志。

## 产出
- `ae2dc91bc` MSRV clippy 修复（4 文件）
- `899576d50` `.gitattributes` corpus 字节精确
- `54a1b4673` fmt 收尾
