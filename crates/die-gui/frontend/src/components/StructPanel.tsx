import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";

/** Struct node tree returned by evaluate_struct. */
interface StructNode {
  name: string;
  value: string | null;
  children: StructNode[];
}

/** Entropy info returned by get_entropy_info. */
interface EntropyInfo {
  file_size: number;
  entropy: number;
}

/** Scan info returned by get_scan_info. */
interface ScanInfo {
  file_size: number;
  md5: string;
  sha256: string;
}

/** Available struct methods. */
const STRUCT_METHODS = [
  "Info",
  "Hash#MD5",
  "Hash#SHA1",
  "Hash#SHA256",
  "Entropy",
  "Check format",
  "PE#Imports",
  "PE#Exports",
  "PE#Resources",
  "PE#Overlay",
  "PE#Rich",
  "PE#Directories",
  "ELF#Header",
  "ELF#Sections",
  "Mach-O#Header",
  "Mach-O#Segments",
  "DEX#Header",
];

/** Mode selector: struct, entropy, or info. */
type StructMode = "struct" | "entropy" | "info";

/** Struct/Entropy/Info panel — GUI equivalent of CLI --struct/--entropy/--info. */
export function StructPanel({ path }: { path: string }) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<StructMode>("struct");
  const [selector, setSelector] = useState("Info");
  const [structResult, setStructResult] = useState<StructNode | null>(null);
  const [entropyResult, setEntropyResult] = useState<EntropyInfo | null>(null);
  const [infoResult, setInfoResult] = useState<ScanInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-run when mode or selector changes and path is set.
  useEffect(() => {
    if (!path) return;
    runQuery();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, mode, selector]);

  async function runQuery() {
    if (!path) return;
    setLoading(true);
    setError(null);
    try {
      if (mode === "struct") {
        const result = await invoke<StructNode | null>("evaluate_struct", {
          path,
          selector,
        });
        setStructResult(result);
      } else if (mode === "entropy") {
        const result = await invoke<EntropyInfo>("get_entropy_info", { path });
        setEntropyResult(result);
      } else if (mode === "info") {
        const result = await invoke<ScanInfo>("get_scan_info", { path });
        setInfoResult(result);
      }
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col h-full overflow-auto p-3 gap-3 text-xs">
      {/* Mode selector + struct method picker */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex gap-1">
          {(["struct", "entropy", "info"] as StructMode[]).map((m) => (
            <button
              key={m}
              className={`px-2 py-1 rounded ${
                mode === m
                  ? "bg-blue-600 text-white"
                  : "bg-bg-secondary text-fg-secondary hover:bg-hover"
              }`}
              onClick={() => setMode(m)}
            >
              {t(`structPanel.${m}`)}
            </button>
          ))}
        </div>

        {mode === "struct" && (
          <select
            className="input py-0.5 px-1.5"
            value={selector}
            onChange={(e) => setSelector(e.target.value)}
          >
            {STRUCT_METHODS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        )}

        <button
          className="px-2 py-0.5 rounded bg-bg-secondary hover:bg-hover text-fg-secondary"
          onClick={runQuery}
          disabled={loading || !path}
        >
          {loading ? t("structPanel.loading") : t("structPanel.refresh")}
        </button>
      </div>

      {/* Error display */}
      {error && (
        <div className="text-red-400 p-2 bg-red-900/20 rounded">{error}</div>
      )}

      {/* Results */}
      {mode === "struct" && structResult && (
        <StructTreeView node={structResult} depth={0} />
      )}
      {mode === "struct" && !structResult && !loading && !error && (
        <div className="text-fg-muted">{t("structPanel.noResult")}</div>
      )}

      {mode === "entropy" && entropyResult && (
        <div className="flex flex-col gap-1">
          <div className="flex justify-between">
            <span className="text-fg-muted">{t("structPanel.fileSize")}</span>
            <span>{entropyResult.file_size.toLocaleString()} bytes</span>
          </div>
          <div className="flex justify-between">
            <span className="text-fg-muted">{t("structPanel.entropyValue")}</span>
            <span
              className={
                entropyResult.entropy > 7.5
                  ? "text-orange-400 font-medium"
                  : entropyResult.entropy > 6.0
                    ? "text-yellow-400"
                    : ""
              }
            >
              {entropyResult.entropy.toFixed(4)} bits/byte
            </span>
          </div>
          {/* Entropy bar visualization */}
          <div className="mt-2">
            <div className="w-full h-4 bg-bg-secondary rounded overflow-hidden">
              <div
                className="h-full transition-all"
                style={{
                  width: `${(entropyResult.entropy / 8) * 100}%`,
                  background:
                    entropyResult.entropy > 7.5
                      ? "linear-gradient(90deg, #f59e0b, #ef4444)"
                      : entropyResult.entropy > 6.0
                        ? "linear-gradient(90deg, #eab308, #f59e0b)"
                        : "linear-gradient(90deg, #3b82f6, #6366f1)",
                }}
              />
            </div>
            <div className="flex justify-between text-fg-muted mt-0.5">
              <span>0.0</span>
              <span>4.0</span>
              <span>8.0</span>
            </div>
          </div>
        </div>
      )}

      {mode === "info" && infoResult && (
        <div className="flex flex-col gap-1">
          <div className="flex justify-between">
            <span className="text-fg-muted">{t("structPanel.fileSize")}</span>
            <span>{infoResult.file_size.toLocaleString()} bytes</span>
          </div>
          <div className="flex justify-between">
            <span className="text-fg-muted">MD5</span>
            <span className="font-mono text-fg-primary">{infoResult.md5}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-fg-muted">SHA-256</span>
            <span className="font-mono text-fg-primary break-all">{infoResult.sha256}</span>
          </div>
        </div>
      )}
    </div>
  );
}

/** Recursively render a struct node tree. */
function StructTreeView({ node, depth }: { node: StructNode; depth: number }) {
  const [expanded, setExpanded] = useState(depth < 2);

  const hasChildren = node.children.length > 0;
  const isLeaf = node.value !== null;

  return (
    <div className="flex flex-col">
      <div
        className="flex items-start gap-1 cursor-pointer hover:bg-hover rounded px-1"
        style={{ paddingLeft: `${depth * 16 + 4}px` }}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {hasChildren ? (
          <span className="text-fg-muted select-none w-3">
            {expanded ? "▼" : "▶"}
          </span>
        ) : (
          <span className="w-3" />
        )}
        <span className="text-fg-primary font-medium">{node.name}</span>
        {isLeaf && (
          <span className="text-fg-muted ml-2 font-mono break-all">
            {node.value}
          </span>
        )}
      </div>
      {hasChildren && expanded && (
        <div className="flex flex-col">
          {node.children.map((child, i) => (
            <StructTreeView key={i} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}
