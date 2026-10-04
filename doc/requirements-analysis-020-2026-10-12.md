# Phase 50 执行分析（2026-10-12）

## 需求
用户："开始执行"——在确认 XEmulator 是 DIE 组件库（非独立 EXE）后
落地 Phase 50：pin XEmulator + oracle + x86 核心移植 +
xinstallsimple/aspack-2.11/petite 模拟器分支。

## 关键发现与决策

1. **移植范围收敛**：XStaticUnpacker 仅用 x86 核心（xemux86+memmgr+
   registers ≈6.9k 行），OS/syscall/winapi 层不需要。decode→
   micro-op→exec 三段结构忠实镜像；`run` 步数语义=终止步计入、
   `lastInfo` 取最后步、`vector=-1`、Linux 软件回退（非 Windows
   宿主 CPU 移位路径）、FRNDINT ties-to-even、BSR 全宽前导零。
   491/491 指令差分语料字节级一致。

2. **XEmulator pin `655e6da`**：与 XStaticUnpacker pin `746fb24`
   （2026-09-22）同期兼容；检出至 `dep/XEmulator` submodule，
   oracle 编译成功即验证。

3. **三个调用点形态不同**：
   - InstallSimple：init+driver 两级 stdcall 调用，共享 100M 步
     预算，唯一 guest 回调=分配器（stdcall ctx,size,flag→zeroed
     heap）。记录流 = 6 零前缀 + record[0..len-6]；下条记录起点
     `pos+len-6`（声明长度与下一条头重叠 6 字节的上游怪癖）。
   - ASPack 2.11x：EP 处 pushad 起跳，模拟至确定性 landing，
     解密后的 stub head 回填再走经典块表路径。
   - Petite：5×push+call+ret 模式定位内嵌解码器，12 参数合成栈，
     返回校验 updated_destination==dst+size 与 consumed 边界。

4. **合成 fixture 端到端差分**：无真实 InstallSimple 样本，但上游
   `_detectPEInfo`/`is_load_decoder_image` 约束可合成满足——
   UPX-DEFLATE 包装（zlib raw deflate）+ 直通 codec 合成解码器
   （签名前缀 14/16 字节对齐后继续执行，注意 sig 内 `push esi`
   需对应 pop 再 ret）。同一 fixture 喂上游 oracle 与 Rust 产出
   字节级一致报告（fnv64 ef20e706fcab011b）。

5. **借用约束**：X86 长期持有 `&mut MemoryManager`（上游同款
   m_pMemory），宿主侧交错访问经 `memory()`/`memory_mut()`
   访问器，避免模拟器与调用方的双重可变借用。

6. **归档链接入**：InstallSimple 为多记录容器，接
   `container_records`（AutoIt→BoxedApp→EnigmaVB→InstallSimple，
   上游 xformats 顺序），非 `PackerKind`/`unpack_any` 单输出路径。

## 遗留
- ASPack 2.11x/Petite 内嵌解码器的**真实样本**语料仍缺（合成
  guest 代码单测覆盖接入逻辑）；真实 InstallSimple 包获取后可
  追加 oracle 差分。
- 上游 `run` 的 TB cache 是纯优化，Rust 逐步执行等价但慢——
  100M 步预算下最坏耗时高于上游，已在调用点维持相同预算语义。
