import { useState } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";

// Mode list mirrors upstream `XDemangleWidget` combobox order
// (subset implemented; see crates/die-gui/src/demangle.rs).
const MODES: { value: string; label: string }[] = [
  { value: "auto", label: "Auto" },
  { value: "msvc", label: "MSVC" },
  { value: "msvc32", label: "MSVC x86" },
  { value: "msvc64", label: "MSVC x64" },
  { value: "msvcarm32", label: "MSVC ARM32" },
  { value: "msvcarm64", label: "MSVC ARM64" },
  { value: "gnuv3", label: "C++ (Itanium)" },
  { value: "gccwin", label: "C++ GCC/Win" },
  { value: "gccmac", label: "C++ GCC/Mac" },
  { value: "borland32", label: "Borland x86" },
  { value: "borland64", label: "Borland x64" },
  { value: "watcom", label: "Watcom" },
  { value: "rust", label: "Rust" },
  { value: "dlang", label: "D" },
  { value: "java", label: "Java" },
];

export function DemangleTool() {
  const { t } = useTranslation();
  const [symbol, setSymbol] = useState("");
  const [compiler, setCompiler] = useState("auto");
  const [result, setResult] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function doDemangle() {
    if (!symbol) return;
    setError(null);
    try {
      const demangled = await invoke<string>("demangle", {
        symbol,
        compiler,
      });
      setResult(demangled);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="border border-border rounded p-3 mt-3">
      <h3 className="text-sm font-medium mb-2">{t("demangle.title")}</h3>
      <div className="flex items-center gap-2 mb-2">
        <input
          type="text"
          value={symbol}
          onChange={(e) => setSymbol(e.target.value)}
          placeholder="_ZN3foo3barEv or _R..."
          className="flex-1 text-xs font-mono border border-border rounded px-2 py-1"
        />
        <select
          value={compiler}
          onChange={(e) => setCompiler(e.target.value)}
          className="text-xs border border-border rounded px-1 py-1"
        >
          {MODES.map((m) => (
            <option key={m.value} value={m.value}>
              {m.label}
            </option>
          ))}
        </select>
        <button
          onClick={doDemangle}
          disabled={!symbol}
          className="px-3 py-1 text-xs bg-primary text-background rounded disabled:opacity-50"
        >
          {t("demangle.button")}
        </button>
      </div>
      {error && <div className="text-xs text-red-600">{error}</div>}
      {result && (
        <pre className="text-xs font-mono bg-muted p-2 rounded break-all whitespace-pre-wrap">
          {result}
        </pre>
      )}
    </div>
  );
}
