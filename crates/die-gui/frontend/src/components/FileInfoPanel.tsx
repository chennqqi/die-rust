import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";
import {
  FileText,
  Hash,
  Layers,
  Code2,
  Activity,
  Copy,
  Check,
  GitBranch,
  Package,
} from "lucide-react";
import { FileHeaderTree, type HeaderField } from "./FileHeaderTree";
import PeViewPanel from "./PeViewPanel";
import { ElfViewPanel } from "./ElfViewPanel";
import { MachoViewPanel } from "./MachoViewPanel";
import StringExtractor from "./StringExtractor";
import SectionVisualizer from "./SectionVisualizer";

interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
}

interface SectionInfo {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_offset: number;
  raw_size: number;
  entropy: number;
}

interface SymbolInfo {
  name: string;
  address: number;
  size: number;
  kind: string;
}

interface FileInfo {
  path: string;
  file_name: string;
  size: number;
  size_human: string;
  entropy: number;
  hashes: FileHashes;
  format: string;
  sections: SectionInfo[];
  symbols: SymbolInfo[];
  header_tree: HeaderField[];
  mime_type?: string;
}

type SubTab = "info" | "headers" | "sections" | "symbols" | "entropy" | "pe" | "elf" | "macho" | "strings" | "visual";

export function FileInfoPanel({ path }: { path: string }) {
  const { t } = useTranslation();
  const [info, setInfo] = useState<FileInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [subTab, setSubTab] = useState<SubTab>("info");
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (!path) return;
    setLoading(true);
    setError(null);
    invoke<FileInfo>("get_file_info", { path })
      .then(setInfo)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [path]);

  const copyHash = (hash: string, label: string) => {
    navigator.clipboard.writeText(hash);
    setCopied(label);
    setTimeout(() => setCopied(null), 1500);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-fg-secondary text-xs">
        <div className="w-4 h-4 border-2 border-accent-blue border-t-transparent rounded-full animate-spin mr-2" />
        {t("fileInfo.title")}...
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-3 text-xs text-accent-red selectable">{error}</div>
    );
  }

  if (!info) {
    return (
      <div className="flex items-center justify-center h-full text-fg-muted text-xs">
        {t("scan.openToBegin")}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Sub-tab bar */}
      <div
        className="flex items-center gap-0 px-1 border-b border-border-c"
        style={{ background: "rgb(var(--bg-panel))" }}
      >
        <SubTabButton active={subTab === "info"} onClick={() => setSubTab("info")} icon={FileText} label={t("fileInfo.title")} />
        <SubTabButton active={subTab === "headers"} onClick={() => setSubTab("headers")} icon={GitBranch} label={t("fileInfo.headers", "Headers")} />
        <SubTabButton active={subTab === "sections"} onClick={() => setSubTab("sections")} icon={Layers} label={`${t("fileInfo.sections")} (${info.sections.length})`} />
        <SubTabButton active={subTab === "symbols"} onClick={() => setSubTab("symbols")} icon={Code2} label={`${t("fileInfo.symbols")} (${info.symbols.length})`} />
        <SubTabButton active={subTab === "entropy"} onClick={() => setSubTab("entropy")} icon={Activity} label={t("fileInfo.entropy")} />
        {(info.format === "PE32" || info.format === "PE32+" || info.format === "PE") && (
          <SubTabButton active={subTab === "pe"} onClick={() => setSubTab("pe")} icon={GitBranch} label="PE View" />
        )}
        {(info.format === "ELF32" || info.format === "ELF64" || info.format === "ELF") && (
          <SubTabButton active={subTab === "elf"} onClick={() => setSubTab("elf")} icon={GitBranch} label="ELF View" />
        )}
        {(info.format === "Mach-O 32" || info.format === "Mach-O 64" || info.format === "Mach-O FAT") && (
          <SubTabButton active={subTab === "macho"} onClick={() => setSubTab("macho")} icon={GitBranch} label="Mach-O View" />
        )}
        <SubTabButton active={subTab === "strings"} onClick={() => setSubTab("strings")} icon={Code2} label="Strings" />
        <SubTabButton active={subTab === "visual"} onClick={() => setSubTab("visual")} icon={Activity} label="Visual" />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-3 selectable">
        {subTab === "info" && (
          <div className="space-y-3 text-xs">
            <InfoRow label={t("fileInfo.name")} value={info.file_name} />
            <InfoRow label={t("fileInfo.title")} value={info.path} mono />
            <InfoRow label={t("fileInfo.size")} value={`${info.size_human} (${info.size.toLocaleString()} bytes)`} />
            <InfoRow label={t("fileInfo.format")} value={info.format} />
            {info.mime_type && (
              <InfoRow label="MIME Type" value={info.mime_type} mono />
            )}
            <InfoRow
              label={t("fileInfo.entropy")}
              value={`${info.entropy.toFixed(4)} ${entropyLabel(info.entropy)}`}
            />

            <div className="pt-2 border-t border-border-c">
              <div className="flex items-center gap-1.5 mb-2 text-fg-secondary">
                <Hash size={13} />
                <span className="font-medium">{t("fileInfo.hashes")}</span>
              </div>
              <HashRow
                label="MD5"
                value={info.hashes.md5}
                copied={copied === "md5"}
                onCopy={() => copyHash(info.hashes.md5, "md5")}
              />
              <HashRow
                label="SHA-1"
                value={info.hashes.sha1}
                copied={copied === "sha1"}
                onCopy={() => copyHash(info.hashes.sha1, "sha1")}
              />
              <HashRow
                label="SHA-256"
                value={info.hashes.sha256}
                copied={copied === "sha256"}
                onCopy={() => copyHash(info.hashes.sha256, "sha256")}
              />
              <ExtraHashes path={info.path} copied={copied} copyHash={copyHash} />
            </div>

            <UpxUnpackSection path={info.path} />
          </div>
        )}

        {subTab === "headers" && (
          <FileHeaderTree fields={info.header_tree ?? []} />
        )}

        {subTab === "sections" && (
          <div className="text-xs">
            {info.sections.length === 0 ? (
              <p className="text-fg-muted">{t("fileInfo.sections")} — N/A</p>
            ) : (
              <table className="w-full mono">
                <thead>
                  <tr className="text-left text-fg-secondary border-b border-border-c">
                    <th className="py-1 pr-3">{t("fileInfo.name")}</th>
                    <th className="py-1 pr-3">{t("fileInfo.vaddr")}</th>
                    <th className="py-1 pr-3">{t("fileInfo.vsize")}</th>
                    <th className="py-1 pr-3">{t("fileInfo.rawOff")}</th>
                    <th className="py-1 pr-3">{t("fileInfo.rawSize")}</th>
                    <th className="py-1">{t("fileInfo.entropy")}</th>
                  </tr>
                </thead>
                <tbody>
                  {info.sections.map((s, i) => (
                    <tr key={i} className="border-b border-border-c hover:bg-hover">
                      <td className="py-0.5 pr-3 text-accent-blue">{s.name}</td>
                      <td className="py-0.5 pr-3 text-fg-secondary">0x{s.virtual_address.toString(16).padStart(8, "0")}</td>
                      <td className="py-0.5 pr-3 text-fg-secondary">0x{s.virtual_size.toString(16)}</td>
                      <td className="py-0.5 pr-3 text-fg-muted">0x{s.raw_offset.toString(16)}</td>
                      <td className="py-0.5 pr-3 text-fg-muted">0x{s.raw_size.toString(16)}</td>
                      <td className="py-0.5">
                        <span className={entropyColor(s.entropy)}>
                          {s.entropy.toFixed(3)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {subTab === "symbols" && (
          <div className="text-xs">
            {info.symbols.length === 0 ? (
              <p className="text-fg-muted">{t("fileInfo.symbols")} — N/A</p>
            ) : (
              <>
                <p className="text-fg-muted mb-1">{info.symbols.length} {t("fileInfo.symbols")}</p>
                <div style={{ maxHeight: "400px", overflowY: "auto" }}>
                  <table className="w-full mono">
                    <thead className="sticky top-0 bg-bg-panel">
                      <tr className="text-left text-fg-secondary border-b border-border-c">
                        <th className="py-1 pr-3">{t("fileInfo.address")}</th>
                        <th className="py-1 pr-3">{t("fileInfo.kind")}</th>
                        <th className="py-1 pr-3">{t("fileInfo.size")}</th>
                        <th className="py-1">{t("fileInfo.name")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {info.symbols.map((s, i) => (
                        <tr key={i} className="border-b border-border-c hover:bg-hover">
                          <td className="py-0.5 pr-3 text-fg-muted">0x{s.address.toString(16).padStart(8, "0")}</td>
                          <td className="py-0.5 pr-3 text-fg-secondary">{s.kind}</td>
                          <td className="py-0.5 pr-3 text-fg-muted">{s.size > 0 ? `0x${s.size.toString(16)}` : "-"}</td>
                          <td className="py-0.5 text-fg-primary">{s.name}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        )}

        {subTab === "entropy" && (
          <EntropyView path={path} overall={info.entropy} />
        )}

        {subTab === "pe" && (
          <PeViewPanel filePath={path} />
        )}

        {subTab === "elf" && (
          <ElfViewPanel filePath={path} />
        )}

        {subTab === "macho" && (
          <MachoViewPanel filePath={path} />
        )}

        {subTab === "strings" && (
          <StringExtractor filePath={path} />
        )}

        {subTab === "visual" && (
          <SectionVisualizer filePath={path} />
        )}
      </div>
    </div>
  );
}

function SubTabButton({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: typeof FileText;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 px-3 py-1.5 text-xs ${
        active ? "tab-active" : "tab-inactive"
      }`}
    >
      <Icon size={13} />
      {label}
    </button>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="text-fg-secondary w-20 flex-shrink-0">{label}</span>
      <span className={`text-fg-primary ${mono ? "mono" : ""} break-all`}>{value}</span>
    </div>
  );
}

function HashRow({
  label,
  value,
  copied,
  onCopy,
}: {
  label: string;
  value: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="flex items-center gap-2 py-0.5 group">
      <span className="text-fg-secondary w-16 flex-shrink-0">{label}</span>
      <span className="mono text-fg-primary flex-1 break-all">{value}</span>
      <button
        onClick={onCopy}
        className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-hover rounded"
        title="Copy"
      >
        {copied ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
      </button>
    </div>
  );
}

interface HashResult {
  algorithm: string;
  value: string;
}

/** Extended hash panel — checkable algorithm list mirroring upstream
 *  XHashWidget. Computes on demand via `compute_hash`. */
function ExtraHashes({
  path,
  copied,
  copyHash,
}: {
  path: string;
  copied: string | null;
  copyHash: (hash: string, label: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [algos, setAlgos] = useState<string[]>([]);
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(["MD4", "SHA224", "SHA384", "SHA512", "SHA3_256", "BLAKE3", "CRC64"]),
  );
  const [results, setResults] = useState<HashResult[] | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    invoke<string[]>("list_hash_algorithms")
      .then(setAlgos)
      .catch(() => setAlgos([]));
  }, []);

  const toggle = (a: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(a)) next.delete(a);
      else next.add(a);
      return next;
    });
    setResults(null);
  };

  const compute = async () => {
    setBusy(true);
    try {
      const r = await invoke<HashResult[]>("compute_hash", {
        path,
        algorithms: Array.from(selected),
      });
      setResults(r);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mt-1">
      <button
        onClick={() => setOpen(!open)}
        className="text-fg-muted hover:text-fg-secondary text-[11px]"
      >
        {open ? "▾" : "▸"} More hashes
      </button>
      {open && (
        <div className="mt-1 pl-1">
          <div className="flex flex-wrap gap-x-3 gap-y-0.5 mb-1">
            {algos.map((a) => (
              <label key={a} className="flex items-center gap-1 text-fg-secondary">
                <input
                  type="checkbox"
                  checked={selected.has(a)}
                  onChange={() => toggle(a)}
                />
                {a}
              </label>
            ))}
          </div>
          <button
            onClick={compute}
            disabled={busy || selected.size === 0}
            className="px-2 py-0.5 bg-primary text-background rounded disabled:opacity-50"
          >
            {busy ? "Computing..." : "Compute"}
          </button>
          {results &&
            results.map((r) => (
              <HashRow
                key={r.algorithm}
                label={r.algorithm}
                value={r.value}
                copied={copied === r.algorithm}
                onCopy={() => copyHash(r.value, r.algorithm)}
              />
            ))}
        </div>
      )}
    </div>
  );
}

function entropyLabel(e: number): string {
  if (e < 1) return "(very low — likely text/data)";
  if (e < 4) return "(low — structured data)";
  if (e < 6) return "(medium — mixed content)";
  if (e < 7.5) return "(high — possibly compressed/encrypted)";
  return "(very high — likely encrypted/compressed)";
}

function entropyColor(e: number): string {
  if (e < 4) return "text-accent-green";
  if (e < 6) return "text-accent-yellow";
  return "text-accent-red";
}

/** Entropy graph view — renders a simple bar chart of block-level entropy. */
function EntropyView({ path, overall }: { path: string; overall: number }) {
  const [graph, setGraph] = useState<{ blocks: number[]; block_size: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [blockSize, setBlockSize] = useState(256);

  useEffect(() => {
    invoke<{ blocks: number[]; block_size: number; overall: number }>(
      "get_entropy_graph",
      { path, blockSize }
    )
      .then(setGraph)
      .catch((e) => setError(String(e)));
  }, [path, blockSize]);

  if (error) return <p className="text-accent-red text-xs">{error}</p>;
  if (!graph) return <p className="text-fg-muted text-xs">Computing entropy graph...</p>;

  const maxBlocks = 200;
  const displayBlocks =
    graph.blocks.length > maxBlocks
      ? graph.blocks.filter((_, i) => i % Math.ceil(graph.blocks.length / maxBlocks) === 0)
      : graph.blocks;

  return (
    <div className="text-xs">
      <div className="mb-3">
        <div className="flex justify-between mb-1">
          <span className="text-fg-secondary">Overall entropy: <span className={entropyColor(overall)}>{overall.toFixed(4)}</span></span>
          <span className="text-fg-muted">{graph.blocks.length} blocks × {graph.block_size} bytes</span>
          <select
            value={blockSize}
            onChange={(e) => setBlockSize(Number(e.target.value))}
            className="text-xs border border-border rounded px-1 py-0.5"
          >
            <option value={64}>64B</option>
            <option value={128}>128B</option>
            <option value={256}>256B</option>
            <option value={512}>512B</option>
            <option value={1024}>1KB</option>
            <option value={4096}>4KB</option>
          </select>
        </div>
      </div>
      {/* Simple bar chart */}
      <div className="flex items-end gap-px h-32 bg-input rounded p-1">
        {displayBlocks.map((e, i) => (
          <div
            key={i}
            className="flex-1 rounded-t"
            style={{
              height: `${(e / 8) * 100}%`,
              background: e < 4
                ? "rgb(var(--accent-green))"
                : e < 6
                ? "rgb(var(--accent-yellow))"
                : "rgb(var(--accent-red))",
              minHeight: "1px",
            }}
            title={`Block ${i}: ${e.toFixed(3)}`}
          />
        ))}
      </div>
      <div className="flex justify-between mt-1 text-fg-muted">
        <span>0</span>
        <span>{graph.blocks.length}</span>
      </div>
      <div className="mt-3 flex gap-4 text-fg-secondary">
        <span className="flex items-center gap-1">
          <div className="w-3 h-3 rounded" style={{ background: "rgb(var(--accent-green))" }} />
          &lt; 4.0 (low)
        </span>
        <span className="flex items-center gap-1">
          <div className="w-3 h-3 rounded" style={{ background: "rgb(var(--accent-yellow))" }} />
          4.0–6.0 (medium)
        </span>
        <span className="flex items-center gap-1">
          <div className="w-3 h-3 rounded" style={{ background: "rgb(var(--accent-red))" }} />
          &gt; 6.0 (high)
        </span>
      </div>
    </div>
  );
}

interface UpxInfoDto {
  version: number;
  format: number;
  methodName: string;
  level: number;
  filter: number;
  compressedSize: number;
  uncompressedSize: number;
  originalFileSize: number;
}

/** UPX detection banner + one-click static unpack (Phase 20). */
function UpxUnpackSection({ path }: { path: string }) {
  const { t } = useTranslation();
  const [upx, setUpx] = useState<UpxInfoDto | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setUpx(null);
    setResult(null);
    setErr(null);
    invoke<UpxInfoDto | null>("detect_upx", { path })
      .then(setUpx)
      .catch(() => setUpx(null));
  }, [path]);

  if (!upx) return null;

  const doUnpack = async () => {
    setBusy(true);
    setErr(null);
    try {
      const out = await invoke<string>("unpack_file", { path, outputPath: null });
      setResult(out);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="pt-2 border-t border-border-c">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5 text-fg-secondary">
          <Package size={13} />
          <span className="font-medium">{t("upx.title", "UPX packed")}</span>
        </div>
        <button
          onClick={doUnpack}
          disabled={busy}
          className="px-2 py-0.5 text-xs rounded bg-accent-blue text-white hover:opacity-90 disabled:opacity-50"
        >
          {busy ? t("upx.unpacking", "Unpacking…") : t("upx.unpack", "Unpack")}
        </button>
      </div>
      <div className="text-fg-muted mono">
        {t("upx.method", "Method")}: {upx.methodName} · {t("upx.level", "Level")}: {upx.level}
        {upx.filter !== 0 && <> · {t("upx.filter", "Filter")}: 0x{upx.filter.toString(16)}</>}
      </div>
      <div className="text-fg-muted mono">
        {upx.compressedSize.toLocaleString()} → {upx.uncompressedSize.toLocaleString()} bytes
      </div>
      {result && <div className="text-accent-green mt-1 selectable">{t("upx.saved", "Saved")}: {result}</div>}
      {err && <div className="text-accent-red mt-1">{err}</div>}
    </div>
  );
}
