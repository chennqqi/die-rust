# 上游 DIE-engine 已知 Bug 清单

**日期**：2026-08-23
**上游版本**：DIE-engine 4.0.0（固定 commit）
**用途**：记录上游规则和引擎中已知的 bug，避免 diec-rust 在对齐时将这些 bug
误认为自身缺陷。每条 bug 附上游源码位置、影响范围和 diec-rust 的处理策略。

---

## Bug 1：`PE.isNET()` 未定义（5 个规则抛异常）

**严重程度**：中（规则执行失败但上游静默忽略）

**上游源码位置**：
- `XScanEngine/modules/pe_script.h:46` — 定义了 `bool isNet()`（小写 t）
- `XScanEngine/modules/pe_script.cpp:239` — 实现了 `bool PE_Script::isNet()`
- **没有** `isNET`（大写 T）的定义

**受影响规则**（均位于 `db_extra/PE/`）：
1. `cryptor_404crypter.1.sg:6` — `if (PE.isNET()) {`
2. `cryptor_njCrypter.2.sg:8` — `if (PE.isNET()) {`
3. `installer_DockerDesktopInstaller.1.sg:8` — `if (PE.isNET()) {`
4. `installer_Store_Installer.1.sg:6` — `if (PE.isNET()) {`
5. `protector_Adept_Protector.2.sg:6` — `if (PE.isNET()) {`

**表现**：上游 diec 控制台输出：
```
cryptor_404crypter.1.sg: PE/cryptor_404crypter.1.sg: 6: TypeError: Property 'isNET' of object PE_Script(0x...) is not a function
```
5 个规则全部抛 `TypeError`，但上游引擎**静默忽略异常**，继续执行其他规则，
最终输出结果不受影响（这些规则本应检测 .NET 相关的 cryptor/installer/protector，
但因异常退出而不产生检测）。

**根因**：规则作者使用了 `isNET()`（大写），但引擎只注册了 `isNet()`（小写）。
JavaScript 区分大小写，所以 `PE.isNET` 为 `undefined`，调用时抛 `TypeError`。

**diec-rust 处理策略**：diec-rust 在 `host_api_bridge.rs` 中注册了 `PE.isNET`
作为 `PE.isNet` 的别名，使这 5 个规则能正常执行。这是**有意偏离上游**——上游
这些规则是死代码（永远抛异常），diec-rust 让它们恢复功能。

**更新（基线 8925358 / XScanEngine 2550d2d）**：上游 commit `eb58192d7`
正式删除 `isNET` 并把所有规则改为 `isNet`；当前规则树 0 处调用
`PE.isNET(`。diec-rust 已同步删除别名，与上游完全对齐。

---

## Bug 6：`PE.getEPSignature()` 未定义（CipherWall 规则上游死代码）

**严重程度**：中（规则执行失败但上游静默忽略）

**受影响规则**：`db_extra/PE/sfx_CipherWall.1.sg:8` —
`switch (PE.getEPSignature(19, 14))`，用于区分 CipherWall 1.5 的
"Decryptor Console"/"Decryptor GUI" 变体。

**表现**：`getEPSignature` 在基线 XScanEngine `2550d2d` 的全部模块及
die_script `3a19ceb6` 中均无定义（2022 年起的 `die_script` 历史版本中
也不存在）。上游执行该规则时抛 TypeError 被静默忽略 → CipherWall 的
options 分支上游永远不可达。

**diec-rust 处理策略**：**有意超集**——实现了
`PE.getEPSignature(offset, size)` = `getSignature(EP文件偏移+offset, size)`
（语义从规则用法反推：返回 EP 相对偏移处的 hex 字符串）。这会产生上游
无法产生的检测结果（over-detection 方向的有意偏差，同 Bug 1 的处理原则）。

---

## Bug 2：`archive_Resources.6.sg` 循环条件逻辑错误

**严重程度**：低（被上游 `getAddressOfEntryPoint` 的返回值语义掩盖）

**上游源码位置**：`db_extra/PE/archive_Resources.6.sg`

**规则代码**：
```javascript
function detect() {
    if (PE.getAddressOfEntryPoint() == 0) {
        bDetected = true;
        for (var i = 0; i <= PE.nLastSection && !bDetected; i++) {
            // IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE
            if (PE.section[i].Characteristics & 0x20000020) {
                bDetected = false;
            }
        }
    }
    return result();
}
```

**Bug**：循环条件 `!bDetected` 在 `bDetected = true` 时立即为 `false`，
循环体**从不执行**。因此只要 `EP == 0`，就会检测到 "Resources"，
不管有没有可执行代码段——这违背了规则的意图（只检测纯资源 DLL）。

**被掩盖的原因**：上游 `PE.getAddressOfEntryPoint()` 返回
`ImageBase + AddressOfEntryPoint`（虚拟地址），不是 RVA。当 EP RVA = 0 时，
返回值 = ImageBase（非 0），所以 `== 0` 条件为 false，规则不触发。
bug 被返回值语义"意外掩盖"。

**diec-rust 处理策略**：diec-rust 正确实现了 `getAddressOfEntryPoint` 返回
`ImageBase + RVA`，因此同样不触发此 bug。如果未来有人"修复" `getAddressOfEntryPoint`
返回纯 RVA，此 bug 会暴露，导致所有 EP=0 的 PE 文件被误检为 "Resources"。

---

## Bug 3：`format_bin.Nintendo-certified-file.1.sg` `const` 重声明

**严重程度**：低（仅影响一个规则，且只在特定文件格式触发）

**上游源码位置**：`db/Binary/format_bin.Nintendo-certified-file.1.sg`

**规则代码**（简化）：
```javascript
const attr = X.U16(8, e), tp = X.U16(0xA, e), ...;
switch (tp) {
case 1:
    const eexhdsz = X.U64(p, e);       // ← const 重声明
    const progidhdp = X.U64(p+8, e), ...;  // ← const 重声明
    ...
case 2:
    const ...;  // ← 同一 switch 块内多次 const 声明
```

**Bug**：在 `switch` 的 `case` 分支中使用 `const` 声明变量，但 `const` 是
块级作用域，在 `switch` 块内同一作用域中重复声明 `const` 会导致
`SyntaxError: Identifier 'eexhdsz' has already been declared`。

**上游表现**：Qt Script（基于旧 ECMAScript）不严格检查 `const` 重声明，
所以上游能正常执行。但 rquickjs（基于 ES2020）严格检查，导致加载失败。

**diec-rust 处理策略**：在规则加载时对 `const` → `var` 做预处理，
匹配 Qt Script 的宽松行为。这是**有意偏离标准**——为了兼容上游规则的
非标准用法。

---

## Bug 4：上游引擎静默忽略规则异常

**严重程度**：中（掩盖规则执行失败）

**上游源码位置**：`XScanEngine` 的规则执行循环

**表现**：当规则抛 `TypeError`/`ReferenceError` 等异常时，上游引擎将异常
信息打印到 stderr（`Last error: ...`），但**不中断扫描**，继续执行下一个规则。
最终输出结果中不包含失败规则的检测。

**影响**：
- Bug 1 的 5 个 `isNET` 规则全部异常但被静默忽略
- 用户看到 "Last error" 消息但不知道哪些规则失败了
- 差分测试中，上游的"无检测"可能是因为规则异常，而非文件确实无特征

**diec-rust 处理策略**：diec-rust 同样静默忽略规则异常（记录到
`structured_diagnostics`），但通过 `corpus_differential.rs` 的
"零脚本异常"硬断言确保 diec-rust 的规则不抛异常。这是**比上游更严格**
的行为——上游允许规则异常，diec-rust 不允许。

---

## Bug 5：上游输出 "Invalid signature: "（空签名）

**严重程度**：低（不影响检测结果）

**上游源码位置**：`Formats/xbinary.cpp:11433` 和 `22465`

**表现**：上游 diec 控制台输出 `Last error: Invalid signature: `（末尾为空），
说明某个规则调用了 `compare("")` 或 `compareEP("")` 传入空签名字符串。

**根因**：某些规则动态构造签名，在特定条件下签名字符串为空。
`XBinary::compareSignature` 检测到空签名后设置错误字符串
`"Invalid signature: " + sOrigin`，其中 `sOrigin` 为空。

**diec-rust 处理策略**：diec-rust 的 `parse_signature` 对空字符串返回
空元素列表，`match_signature` 对空元素列表返回 `true`（匹配空签名 = 匹配
任何位置）。这与上游行为可能不同，但不影响差分测试结果（空签名规则
在上游也因 "Invalid signature" 错误而不产生检测）。

---

## 总结

| Bug | 类型 | 影响规则数 | diec-rust 策略 |
|-----|------|-----------|---------------|
| 1 | `isNET` 未定义 | 5→0 | 上游已删除 `isNET` 并更新规则；别名同步移除 |
| 2 | 循环条件逻辑错误 | 1 | 正确实现掩盖 bug |
| 3 | `const` 重声明 | 1 | `const`→`var` 预处理 |
| 4 | 静默忽略异常 | 全局 | 更严格：零异常断言 |
| 5 | 空签名错误 | 未知 | 不影响检测结果 |
| 6 | `getEPSignature` 未定义 | 1 | 有意超集实现，CipherWall 可检测 |

**原则**：diec-rust 的目标是"与上游输出一致"，而非"复制上游 bug"。
对于影响检测结果的 bug（Bug 1），diec-rust 选择修复而非复制。
对于不影响结果的 bug（Bug 2/3/5），diec-rust 保持兼容行为。
对于行为规范（Bug 4），diec-rust 选择更严格的标准。
