import { useState, useEffect, useMemo, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";
import {
  Search,
  Play,
  Bug,
  Save,
  Clock,
  FileText,
  ChevronRight,
  ChevronDown,
} from "lucide-react";
import { SignatureHighlighter } from "./SignatureHighlighter";

interface SignatureInfoDto {
  name: string;
  file_path: string;
}

interface SignatureGroupDto {
  file_type: string;
  signatures: SignatureInfoDto[];
}

interface SignatureSourceDto {
  source: string;
  file_path: string;
}

interface ScanDetectionDto {
  file_type: string;
  type_name: string;
  name: string;
  version: string | null;
  options: string | null;
  signature_path: string | null;
}

interface RunSignatureResultDto {
  detections: ScanDetectionDto[];
  diagnostics: string[];
  elapsed_ms: number;
  signature_path: string;
}

export function SignatureBrowser() {
  const { t } = useTranslation();
  const [groups, setGroups] = useState<SignatureGroupDto[]>([]);
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [selectedSig, setSelectedSig] = useState<string | null>(null);
  const [source, setSource] = useState<SignatureSourceDto | null>(null);
  const [editedSource, setEditedSource] = useState<string>("");
  const [isDirty, setIsDirty] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [runResult, setRunResult] = useState<RunSignatureResultDto | null>(null);
  const [running, setRunning] = useState(false);
  const [targetFile, setTargetFile] = useState("");
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [showDiagnostics, setShowDiagnostics] = useState(false);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const result = await invoke<SignatureGroupDto[]>("list_signatures");
        setGroups(result);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const loadSource = useCallback(async (fileType: string, name: string) => {
    setSelectedSig(name);
    setError(null);
    setRunResult(null);
    try {
      const result = await invoke<SignatureSourceDto>("get_signature_source", {
        fileType,
        name,
      });
      setSource(result);
      setEditedSource(result.source);
      setIsDirty(false);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const toggleGroup = (fileType: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(fileType)) next.delete(fileType);
      else next.add(fileType);
      return next;
    });
    setSelectedType(fileType);
  };

  const runSignature = async (debug: boolean) => {
    if (!selectedType || !selectedSig || !targetFile) return;
    setRunning(true);
    setError(null);
    setShowDiagnostics(debug);
    try {
      const result = await invoke<RunSignatureResultDto>("run_signature", {
        filePath: targetFile,
        fileType: selectedType,
        signatureName: selectedSig,
        debug,
      });
      setRunResult(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  };

  const saveSource = async () => {
    if (!selectedType || !selectedSig || !isDirty) return;
    setError(null);
    try {
      await invoke("save_signature_source", {
        fileType: selectedType,
        name: selectedSig,
        source: editedSource,
      });
      setSource({ ...source!, source: editedSource });
      setIsDirty(false);
    } catch (e) {
      setError(String(e));
    }
  };

  // Filter signatures by search query.
  const filteredGroups = useMemo(() => {
    if (!searchQuery) return groups;
    const q = searchQuery.toLowerCase();
    return groups
      .map((g) => ({
        ...g,
        signatures: g.signatures.filter(
          (s) =>
            s.name.toLowerCase().includes(q) ||
            g.file_type.toLowerCase().includes(q),
        ),
      }))
      .filter((g) => g.signatures.length > 0);
  }, [groups, searchQuery]);

  const totalSigs = useMemo(
    () => filteredGroups.reduce((sum, g) => sum + g.signatures.length, 0),
    [filteredGroups],
  );

  return (
    <div className="flex flex-col h-full p-3">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium">{t("sigBrowser.title")}</h3>
        <span className="text-xs text-fg-muted">{totalSigs} {t("sigBrowser.signatures")}</span>
      </div>

      {error && (
        <div
          className="text-xs px-2 py-1 mb-2 rounded"
          style={{ background: "rgba(var(--accent-red), 0.1)", color: "rgb(var(--accent-red))" }}
        >
          {error}
        </div>
      )}

      {/* Search bar */}
      <div className="flex items-center gap-2 mb-2">
        <div className="flex-1 relative">
          <Search
            size={12}
            className="absolute left-2 top-1/2 -translate-y-1/2 text-fg-muted"
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t("sigBrowser.search")}
            className="input pl-7 py-1 text-xs w-full"
          />
        </div>
      </div>

      {/* Target file input for Run/Debug */}
      <div className="flex items-center gap-2 mb-2">
        <input
          type="text"
          value={targetFile}
          onChange={(e) => setTargetFile(e.target.value)}
          placeholder={t("sigBrowser.targetFile")}
          className="input flex-1 py-1 text-xs"
        />
        <button
          onClick={() => runSignature(false)}
          disabled={!selectedSig || !targetFile || running}
          className="btn btn-primary text-xs py-1"
          title={t("sigBrowser.runTip")}
        >
          <Play size={12} /> {t("sigBrowser.run")}
        </button>
        <button
          onClick={() => runSignature(true)}
          disabled={!selectedSig || !targetFile || running}
          className="btn text-xs py-1"
          title={t("sigBrowser.debug")}
        >
          <Bug size={12} /> {t("sigBrowser.debug")}
        </button>
      </div>

      {/* Main split: tree + source */}
      <div className="flex gap-2 flex-1 overflow-hidden">
        {/* Signature tree */}
        <div className="w-48 overflow-y-auto border-r border-border-c pr-1 flex-shrink-0">
          {loading && (
            <div className="text-xs text-fg-secondary p-2">{t("common.loading")}</div>
          )}
          {filteredGroups.map((g) => {
            const expanded = expandedGroups.has(g.file_type);
            return (
              <div key={g.file_type} className="mb-0.5">
                <button
                  onClick={() => toggleGroup(g.file_type)}
                  className="text-xs font-medium w-full text-left px-1 py-0.5 rounded hover:bg-hover flex items-center gap-1"
                >
                  {expanded ? (
                    <ChevronDown size={12} />
                  ) : (
                    <ChevronRight size={12} />
                  )}
                  <span className="text-accent-blue">{g.file_type}</span>
                  <span className="text-fg-muted">({g.signatures.length})</span>
                </button>
                {expanded && (
                  <div className="ml-3 mt-0.5">
                    {g.signatures.map((s) => (
                      <button
                        key={s.name}
                        onClick={() => loadSource(g.file_type, s.name)}
                        className={`text-xs block w-full text-left px-1 py-0.5 rounded truncate ${
                          selectedSig === s.name
                            ? "bg-accent-blue/20 border-l-2 border-accent-blue"
                            : "hover:bg-hover"
                        }`}
                        title={s.name}
                      >
                        {s.name}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
          {!loading && filteredGroups.length === 0 && (
            <div className="text-xs text-fg-muted p-2">
              {searchQuery ? t("sigBrowser.noDetections") : t("sigBrowser.selectSig")}
            </div>
          )}
        </div>

        {/* Source view + edit */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {source ? (
            <>
              {/* Source header */}
              <div className="flex items-center justify-between px-2 py-1 border-b border-border-c flex-shrink-0">
                <div className="flex items-center gap-2 text-xs">
                  <FileText size={12} className="text-accent-blue" />
                  <span className="font-medium text-fg-primary">{selectedSig}</span>
                  <span className="text-fg-muted">{source.file_path}</span>
                  {isDirty && (
                    <span className="text-accent-yellow">● {t("sigBrowser.unsaved")}</span>
                  )}
                </div>
                <button
                  onClick={saveSource}
                  disabled={!isDirty}
                  className="btn text-xs py-0.5"
                  title={t("sigBrowser.save")}
                >
                  <Save size={11} /> {t("sigBrowser.save")}
                </button>
              </div>

              {/* Source content — editable textarea overlay + highlighted view */}
              <div className="flex-1 overflow-auto relative">
                <textarea
                  value={editedSource}
                  onChange={(e) => {
                    setEditedSource(e.target.value);
                    setIsDirty(e.target.value !== source.source);
                  }}
                  className="absolute inset-0 w-full h-full p-3 mono text-xs bg-transparent text-transparent caret-fg-primary resize-none outline-none"
                  style={{ caretColor: "rgb(var(--fg-primary))" }}
                  spellCheck={false}
                />
                <div className="absolute inset-0 pointer-events-none overflow-auto">
                  <SignatureHighlighter source={editedSource} />
                </div>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-full text-xs text-fg-muted">
              {t("sigBrowser.selectSig")}
            </div>
          )}
        </div>
      </div>

      {/* Run/Debug results panel */}
      {runResult && (
        <div
          className="mt-2 border border-border-c rounded p-2 max-h-40 overflow-auto flex-shrink-0"
          style={{ background: "rgb(var(--bg-panel))" }}
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-medium flex items-center gap-1">
              <Clock size={11} className="text-fg-muted" />
              {runResult.elapsed_ms} ms
              <span className="text-fg-muted ml-2">
                {runResult.detections.length} {t("sigBrowser.detections")}
              </span>
            </span>
            <span className="text-xs text-fg-muted mono">{runResult.signature_path}</span>
          </div>
          {runResult.detections.length > 0 && (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-fg-muted border-b border-border-c">
                  <th className="text-left py-0.5">{t("scan.type")}</th>
                  <th className="text-left py-0.5">{t("common.name")}</th>
                  <th className="text-left py-0.5">{t("scan.version")}</th>
                  <th className="text-left py-0.5">{t("scan.options")}</th>
                </tr>
              </thead>
              <tbody>
                {runResult.detections.map((d, i) => (
                  <tr key={i} className="border-b border-border-c/50">
                    <td className="py-0.5 text-accent-blue">{d.type_name}</td>
                    <td className="py-0.5">{d.name}</td>
                    <td className="py-0.5 text-fg-muted">{d.version ?? ""}</td>
                    <td className="py-0.5 text-fg-muted">{d.options ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {showDiagnostics && runResult.diagnostics.length > 0 && (
            <div className="mt-1 pt-1 border-t border-border-c">
              <div className="text-xs font-medium text-accent-yellow mb-0.5">
                {t("sigBrowser.diagnostics")}
              </div>
              {runResult.diagnostics.map((d, i) => (
                <div key={i} className="text-xs text-fg-secondary mono selectable">
                  {d}
                </div>
              ))}
            </div>
          )}
          {runResult.detections.length === 0 && (
            <div className="text-xs text-fg-muted">
              {t("sigBrowser.noDetections")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
