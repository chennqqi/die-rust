# 分析记录 027 — 2026-10-04

## 需求：修复 default (windows-2022) CI 失败（updater_flow 0xC0000139）

诊断路径：无 Windows 环境，用 rustup 已有的 x86_64-pc-windows-msvc
std + clang-cl/lld-link/llvm-lib/llvm-dlltool 手工搭最小 MSVC shim
（stub 头文件 + def 生成的导入库 + crtstub.obj 补 CRT 入口符号），
交叉构建出 updater_flow.exe 用 llvm-readobj 读 --coff-imports。

关键坑：crtstub 的 mainCRTStartup 必须真实调用 main，否则
/OPT:REF 把 libtest harness 与全部测试代码 GC 成 447KB 空壳，
导入表完全失真。修正后得 17MB 真实 exe：导入 comctl32!
TaskDialogIndirect——v6-only 导出，无 manifest 即加载期 0xC0000139。

证据链：build 输出 `cargo:rustc-link-arg-bins=resource.lib`（仅
bin）→ die.exe/.unittest 有 .rsrc 过，updater_flow 无 .rsrc 挂；
gui_cli_differential/i18n_parity 无 manifest 但无 comctl32 导入
（dialog 被 GC）故过。排除：ProcessPrng（raw-dylib 静态导入但
Server 2022 有该导出）、MSYS DLL 影子（API-set 不走 PATH）。

修复：die-gui/build.rs 增加 rustc-link-arg-tests → resource.lib。
交叉构建验证 updater_flow.exe 含 .rsrc + Common-Controls 6.0.0.0。
shim 产物全部在 /tmp，未进仓库。
