import { useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";
import { Play } from "lucide-react";

/** Mirrors `ScanDetectionDto` in commands.rs (camelCase Tauri output). */
interface NfdDetection {
  file_type: string;
  type_name: string;
  name: string;
  version: string | null;
  options: string | null;
  is_heuristic: boolean | null;
  engine: string | null;
}

/**
 * Dedicated NFD/SpecAbstract view (upstream DIE has a standalone NFD
 * panel that shows the engine's own record list, independent of the
 * merged DIE result list). Records come from the `nfd_scan` command.
 */
export function NfdPanel({ path }: { path: string }) {
  const { t } = useTranslation();
  const [deep, setDeep] = useState(true);
  const [heuristic, setHeuristic] = useState(true);
  const [verbose, setVerbose] = useState(false);
  const [records, setRecords] = useState<NfdDetection[] | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runScan = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      const result = await invoke<NfdDetection[]>("nfd_scan", {
        path,
        deep,
        heuristic,
        verbose,
      });
      setRecords(result);
    } catch (e) {
      setError(String(e));
      setRecords(null);
    } finally {
      setRunning(false);
    }
  }, [path, deep, heuristic, verbose]);

  return (
    <div className="border border-border rounded p-3 mt-3">
      {/* Toolbar */}
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <h3 className="text-sm font-medium">{t("nfd.title")}</h3>
        <div className="flex-1" />
        <label className="flex items-center gap-1 text-xs text-fg-muted">
          <input
            type="checkbox"
            checked={deep}
            onChange={(e) => setDeep(e.target.checked)}
          />
          {t("nfd.deep")}
        </label>
        <label className="flex items-center gap-1 text-xs text-fg-muted">
          <input
            type="checkbox"
            checked={heuristic}
            onChange={(e) => setHeuristic(e.target.checked)}
          />
          {t("nfd.heuristic")}
        </label>
        <label className="flex items-center gap-1 text-xs text-fg-muted">
          <input
            type="checkbox"
            checked={verbose}
            onChange={(e) => setVerbose(e.target.checked)}
          />
          {t("nfd.verbose")}
        </label>
        <button
          onClick={runScan}
          disabled={running}
          className="flex items-center gap-1 px-3 py-0.5 text-xs bg-primary text-background rounded disabled:opacity-50"
        >
          <Play size={11} />
          {running ? t("nfd.running") : t("nfd.run")}
        </button>
      </div>

      {error && <div className="text-xs text-red-600 mb-2">{error}</div>}

      {/* Results */}
      {records && (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-muted-foreground border-b border-border">
              <th className="py-1">{t("nfd.fileType")}</th>
              <th className="py-1">{t("nfd.type")}</th>
              <th className="py-1">{t("nfd.name")}</th>
              <th className="py-1">{t("nfd.version")}</th>
              <th className="py-1">{t("nfd.info")}</th>
            </tr>
          </thead>
          <tbody>
            {records.length === 0 && (
              <tr>
                <td colSpan={5} className="py-2 text-fg-muted">
                  {t("nfd.noRecords")}
                </td>
              </tr>
            )}
            {records.map((r, i) => (
              <tr key={i} className="border-b border-border/50">
                <td className="py-0.5 pr-2 text-fg-muted">{r.file_type}</td>
                <td className="py-0.5 pr-2">
                  {r.type_name}
                  {r.is_heuristic && (
                    <span className="ml-1 text-accent-yellow">(h)</span>
                  )}
                </td>
                <td className="py-0.5 pr-2">{r.name}</td>
                <td className="py-0.5 pr-2 text-fg-muted">{r.version ?? ""}</td>
                <td className="py-0.5 text-fg-muted">{r.options ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
