import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";
import {
  AnnotationsPanel,
  loadAnnotations,
  type AnnotationsDto,
} from "./AnnotationsPanel";

interface Instruction {
  address: string;
  bytes: string;
  mnemonic: string;
  label: string | null;
  comment: string | null;
  jump_target: string | null;
}

interface DisassemblyResult {
  start_address: number;
  instruction_count: number;
  instructions: Instruction[];
}

type Syntax = "intel" | "gas" | "nasm";
type Arch =
  | "x86"
  | "x64"
  | "arm"
  | "arm64"
  | "mips32le"
  | "mips32be"
  | "mips64le"
  | "mips64be"
  | "ppc32le"
  | "ppc32be"
  | "ppc64le"
  | "ppc64be"
  | "riscv32"
  | "riscv64"
  | "riscvc"
  | "armbe"
  | "aarch64le"
  | "aarch64be"
  | "cortexm"
  | "thumble"
  | "thumbbe"
  | "sparc"
  | "sparcv9"
  | "s390x"
  | "xcore"
  | "m68k"
  | "m68k00"
  | "m68k10"
  | "m68k20"
  | "m68k30"
  | "m68k40"
  | "m68k60"
  | "tms320c64x"
  | "m6800"
  | "m6801"
  | "m6805"
  | "m6808"
  | "m6809"
  | "m6811"
  | "cpu12"
  | "hd6301"
  | "hd6309"
  | "hcs08"
  | "evm"
  | "mos65xx"
  | "wasm"
  | "bpfle"
  | "bpfbe";

export function Disassembler({
  path,
  initialOffset,
  onFollowInHex,
}: {
  path: string;
  initialOffset?: number | null;
  onFollowInHex?: (offset: number) => void;
}) {
  const { t } = useTranslation();
  const [result, setResult] = useState<DisassemblyResult | null>(null);
  const [offset, setOffset] = useState(initialOffset ?? 0);
  const [arch, setArch] = useState<Arch>("x64");
  const [maxBytes, setMaxBytes] = useState(4096);
  const [syntax, setSyntax] = useState<Syntax>("intel");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [annotations, setAnnotations] = useState<AnnotationsDto | null>(null);

  // Load the file's annotation store (shared with the hex view).
  useEffect(() => {
    setAnnotations(null);
    loadAnnotations(path).then(setAnnotations).catch(() => setAnnotations(null));
  }, [path]);

  // When initialOffset changes (e.g. from HexViewer "Follow in Disasm"),
  // update offset and auto-disassemble.
  useEffect(() => {
    if (initialOffset != null && initialOffset !== offset) {
      setOffset(initialOffset);
      // Auto-disassemble when jumped from HexViewer.
      setTimeout(() => doDisasm(initialOffset, maxBytes), 0);
    }
  }, [initialOffset]);

  async function doDisasm(off: number, max: number) {
    if (!path) return;
    setLoading(true);
    setError(null);
    try {
      const res = await invoke<DisassemblyResult>("disassemble", {
        path,
        offset: off,
        maxBytes: max,
        syntax,
        arch,
      });
      setResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function disasm() {
    await doDisasm(offset, maxBytes);
  }

  /** Analyze All: disassemble a larger range (16KB) from the current offset. */
  async function analyzeAll() {
    const largeMax = 65536;
    setMaxBytes(largeMax);
    await doDisasm(offset, largeMax);
  }

  /** Find all instructions that reference the given target address. */
  function findXrefs(targetAddr: string): Instruction[] {
    if (!result) return [];
    return result.instructions.filter(
      (i) => i.jump_target === targetAddr,
    );
  }

  /** Jump to a target address (click on a jump/call instruction). */
  async function jumpToTarget(target: string) {
    const off = parseInt(target, 16);
    if (!isNaN(off)) {
      setOffset(off);
      await doDisasm(off, maxBytes);
    }
  }

  if (!path) return null;

  return (
    <div className="border border-border rounded p-3 mt-3">
      {/* Toolbar */}
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <h3 className="text-sm font-medium">{t("disasm.title")}</h3>
        <div className="flex-1" />

        {/* Architecture selector */}
        <span className="text-xs text-fg-muted">{t("disasm.arch")}</span>
        <select
          value={arch}
          onChange={(e) => setArch(e.target.value as Arch)}
          className="text-xs border border-border rounded px-1 py-0.5"
        >
          <option value="x86">x86</option>
          <option value="x64">x86-64</option>
          <option value="arm">ARM</option>
          <option value="arm64">ARM64</option>
          <option value="mips32le">MIPS32 LE</option>
          <option value="mips32be">MIPS32 BE</option>
          <option value="mips64le">MIPS64 LE</option>
          <option value="mips64be">MIPS64 BE</option>
          <option value="ppc32le">PPC32 LE</option>
          <option value="ppc32be">PPC32 BE</option>
          <option value="ppc64le">PPC64 LE</option>
          <option value="ppc64be">PPC64 BE</option>
          <option value="riscv32">RISKV32</option>
          <option value="riscv64">RISKV64</option>
          <option value="riscvc">RISKVC</option>
          <option value="armbe">ARM BE</option>
          <option value="aarch64le">AArch64</option>
          <option value="aarch64be">AArch64 BE</option>
          <option value="cortexm">CORTEXM</option>
          <option value="thumble">THUMB</option>
          <option value="thumbbe">THUMB BE</option>
          <option value="sparc">Sparc</option>
          <option value="sparcv9">Sparc V9</option>
          <option value="s390x">S390X</option>
          <option value="xcore">XCORE</option>
          <option value="m68k">M68K</option>
          <option value="m68k00">M68K00</option>
          <option value="m68k10">M68K10</option>
          <option value="m68k20">M68K20</option>
          <option value="m68k30">M68K30</option>
          <option value="m68k40">M68K40</option>
          <option value="m68k60">M68K60</option>
          <option value="tms320c64x">TMS320C64X</option>
          <option value="m6800">M6800</option>
          <option value="m6801">M6801</option>
          <option value="m6805">M6805</option>
          <option value="m6808">M6808</option>
          <option value="m6809">M6809</option>
          <option value="m6811">M6811</option>
          <option value="cpu12">CPU12</option>
          <option value="hd6301">HD6301</option>
          <option value="hd6309">HD6309</option>
          <option value="hcs08">HCS08</option>
          <option value="evm">EVM</option>
          <option value="mos65xx">MOS65XX</option>
          <option value="wasm">WASM</option>
          <option value="bpfle">BPF LE</option>
          <option value="bpfbe">BPF BE</option>
        </select>

        {/* Syntax selector (x86/x64 only) */}
        {(arch === "x86" || arch === "x64") && (
          <select
            value={syntax}
            onChange={(e) => setSyntax(e.target.value as Syntax)}
            className="text-xs border border-border rounded px-1 py-0.5"
          >
            <option value="intel">{t("disasm.intel")}</option>
            <option value="gas">{t("disasm.gas")}</option>
            <option value="nasm">{t("disasm.nasm")}</option>
          </select>
        )}

        {/* Max bytes */}
        <select
          value={maxBytes}
          onChange={(e) => setMaxBytes(Number(e.target.value))}
          className="text-xs border border-border rounded px-1 py-0.5"
        >
          <option value={256}>256B</option>
          <option value={1024}>1KB</option>
          <option value={4096}>4KB</option>
          <option value={16384}>16KB</option>
          <option value={65536}>64KB</option>
        </select>

        {/* Offset input */}
        <input
          type="text"
          value={offset.toString(16)}
          onChange={(e) => setOffset(parseInt(e.target.value, 16) || 0)}
          placeholder="0x0"
          className="w-20 text-xs border border-border rounded px-1 py-0.5 font-mono"
        />

        <button
          onClick={disasm}
          disabled={loading}
          className="px-2 py-0.5 text-xs bg-primary text-background rounded disabled:opacity-50"
        >
          {t("disasm.disassemble")}
        </button>

        {/* Analyze All button — disassemble a larger range */}
        <button
          onClick={analyzeAll}
          disabled={loading}
          className="px-2 py-0.5 text-xs border border-border rounded disabled:opacity-50"
          title={t("disasm.analyzeAllTip")}
        >
          {t("disasm.analyzeAll")}
        </button>

        {/* Follow in Hex button — jump to hex view at current offset */}
        {onFollowInHex && (
          <button
            onClick={() => onFollowInHex(offset)}
            className="px-2 py-0.5 text-xs border border-border rounded"
            title={t("disasm.followInHexTip")}
          >
            {t("disasm.followInHex")}
          </button>
        )}
      </div>

      {error && <div className="text-xs text-red-600 mb-2">{error}</div>}

      {/* Instruction count */}
      {result && (
        <div className="text-xs text-fg-muted mb-1">
          {result.instruction_count} {t("disasm.instructions")}
        </div>
      )}

      {/* Disassembly listing with label, address, bytes, mnemonic, comment columns */}
      {result && (
        <>
        <div
          className="mono text-xs bg-muted/30 rounded overflow-y-auto"
          style={{ maxHeight: "320px", overflowY: "auto" }}
        >
          {/* Header */}
          <div className="flex gap-2 px-2 py-1 border-b border-border-c text-fg-secondary font-medium sticky top-0 bg-muted/80">
            <span className="w-24">{t("disasm.label")}</span>
            <span className="w-32">{t("disasm.address")}</span>
            <span className="w-48">{t("disasm.bytes")}</span>
            <span className="flex-1">{t("disasm.mnemonic")}</span>
            <span className="w-40">{t("disasm.comment")}</span>
          </div>

          {/* Instructions */}
          {result.instructions.map((instr, i) => (
            <div
              key={i}
              className={`flex gap-2 px-2 hover:bg-accent-blue/10 ${instr.label ? "border-t border-border-c/30" : ""}`}
              style={{ lineHeight: "18px" }}
            >
              <span className="w-24 text-orange-400 truncate">
                {instr.label ?? ""}
              </span>
              <span className="w-32 text-fg-muted">{instr.address}</span>
              <span className="w-48 text-blue-400 truncate">{instr.bytes}</span>
              <span className="flex-1 text-fg-primary">{instr.mnemonic}</span>
              <span className="w-40 text-fg-muted truncate">
                {instr.comment ? (
                  <span
                    className="cursor-pointer hover:text-accent-blue"
                    onClick={() => instr.jump_target && jumpToTarget(instr.jump_target)}
                    title={t("disasm.followJump")}
                  >
                    {instr.comment}
                  </span>
                ) : (
                  ""
                )}
              </span>
            </div>
          ))}
        </div>

        {/* Cross-reference summary: show xref counts for labeled addresses */}
        {result.instructions.some((i) => i.label) && (
          <div className="mt-2 text-xs text-fg-muted">
            <span className="font-medium">{t("disasm.xrefs")}: </span>
            {result.instructions
              .filter((i) => i.label)
              .map((i) => {
                const count = findXrefs(i.address).length;
                return count > 0 ? (
                  <span key={i.address} className="mr-2">
                    <span className="text-orange-400">{i.label}</span>
                    {" ← "}
                    <span className="text-fg-secondary">{count}</span>
                  </span>
                ) : null;
              })}
          </div>
        )}
        </>
      )}

      {/* File annotations (shared with the hex view) */}
      <AnnotationsPanel
        path={path}
        annotations={annotations}
        onChanged={setAnnotations}
        onJump={(o) => {
          setOffset(o);
          void doDisasm(o, maxBytes);
        }}
      />
    </div>
  );
}
