# requirements analysis (split)

- 2026-10-07 Mach-O slice: analyzed nfd_mach.cpp getInfo flow (OS defaults by cputype → LC_VERSION_MIN_*/LC_BUILD_VERSION override → Foundation current_version refinement); ported Foundation/iOS/Xcode/toolchain version tables (54/28/133/93 rows) to mach_tables.rs; CAFEBABE disambiguation ported from XBinary::getFileTypeId (per-record fat_arch validity vs u32be@4>10 JAVACLASS fallback). VMProtect/Zig/Qt/Carbon/Cocoa/codesign/toolchain-version emission + Objective-C info flag. Truncated/malformed inputs bounded; MACHOFAT has no upstream NFD handler (generic fallback).

- PE handlers: ported handle_OperationSystem (subsystem map + OS-version table), handle_import (ordered import-sequence patterns), handle_DebugData, handle_Microsoft non-Rich subset; extracted MSVC build->VS (158) and linker->VS (46) tables; recorded upstream mapVersions dead-key quirk in upstream-bugs.md. New PeInfo fields: linker bytes, subsystem, machine, characteristics, os_version, image_base, dotnet_version (BSJB metadata), import_section, section flags.

- [2026-10-02] Phase21 第二批 PE handler：handle_GCC 走 detect(constdata 'gcc'/libgcc/EP GCC)+heur(GENERICLINKER+maj2/minor∈{22..36,56}) 双门控；get_GCC_vi1/vi2 解析 'GCC:'/'gcc-' 版本串；.stabstr GCC 路径标记；Watcom 用 EP 区 'Open Watcom 2002-'/'WATCOM . 1988-' vi；Signtools 读 security dir 首 WIN_CERTIFICATE(rev 0x200,type 2)→WinAuth；节名在我们层大写化→比较改 eq_ignore_ascii_case（上游对原始名大小写敏感，轻微放宽）。

- [2026-10-02] Phase21 第三批：handle_Borland 全量移植（VCL TControl 指纹需 VA→off 反查 + level-3 资源 leaf 数据偏移；sVCLVersion 恒空为上游注释 quirk）；handle_Tools 有界子集（AutoIt 2.XX 版本资源分支 defer——需 VS_VERSIONINFO 解析）。新增 export 名表/TLS dir/资源数据偏移原语。上游 get_Rust_vi 仅做存在性检查（版本恒空）。

- [2026-10-02] Phase21 剩余项归化：盘点 nfd_pe.cpp 未移植 handler（Protection 1651/FixDetects 584/Installers 563/NETProtection 326/等）→ 输出 docs/design/phase21-nfd-remaining.md：4 共享原语（VS_VERSIONINFO/#US heap/Rich 表/entropy）+ 7 批次 21.J–21.P，其中差分 oracle harness 为 Gate 项。

- [2026-10-02] 将 Phase21 剩余项升级为全量对齐计划：非 PE 启发残余拆为 Phase 22、差分验证拆为 Phase 23；Qt 仅限 oracle harness（diec-rust 不引 Qt）；⚠→✅ 需差分收敛。
