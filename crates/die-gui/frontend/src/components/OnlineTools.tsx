import { useState, useEffect, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";

/**
 * Online analysis tools — VirusTotal + auxiliary services.
 *
 * Upstream behavior (formatswidget.cpp:1133-1152):
 * - If VirusTotal API key is configured → show full VT panel with API query results
 * - If no API key → compute MD5 and open browser to VT website
 * - Hash type is always **MD5** (not SHA-256)
 */

interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
  crc32: string;
}

interface FileInfo {
  path: string;
  file_name: string;
  size: number;
  size_human: string;
  entropy: number;
  hashes: FileHashes;
  format: string;
}

interface VtScanResult {
  engine_name: string;
  engine_version: string;
  engine_update: string;
  result: string;
  category: string;
  method: string;
}

interface VtScanInfo {
  found: boolean;
  first_submission_date: number | null;
  last_analysis_date: number | null;
  detects: number;
  total: number;
  status: string;
  results: VtScanResult[];
  error: string | null;
}

interface AppSettings {
  view: { theme: string; language: string; stay_on_top: boolean; advanced: boolean };
  file: { last_directory: string; recent_files: string[]; save_backup: boolean };
  scan: {
    scan_after_open: boolean;
    hide_unknown: boolean;
    sort: boolean;
    log_profiling: boolean;
    flags: Record<string, boolean>;
  };
  database: {
    main_path: string;
    extra_path: string;
    custom_path: string;
    extra_enabled: boolean;
    custom_enabled: boolean;
  };
  engine: {
    die_enabled: boolean;
    nfd_enabled: boolean;
    peid_enabled: boolean;
    yara_enabled: boolean;
  };
  online_tools: { virustotal_apikey: string };
  shortcuts: Record<string, string>;
}

/** Auxiliary online services that accept a hash (MD5 preferred). */
const auxiliaryServices: { name: string; url: (md5: string) => string }[] = [
  {
    name: "Hybrid Analysis",
    url: (h) => `https://hybrid-analysis.com/search?query=${h}`,
  },
  {
    name: "MalwareBazaar",
    url: (h) => `https://bazaar.abuse.ch/browse.php?search=md5:${h}`,
  },
  {
    name: "MalShare",
    url: (h) => `https://malshare.com/sample.php?action=detail&hash=${h}`,
  },
];

function formatDate(posix: number | null): string {
  if (!posix) return "—";
  return new Date(posix * 1000).toLocaleString();
}

export function OnlineTools({ filePath }: { filePath: string }) {
  const { t } = useTranslation();
  const [md5, setMd5] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [vtInfo, setVtInfo] = useState<VtScanInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [querying, setQuerying] = useState(false);
  const [showDetectedOnly, setShowDetectedOnly] = useState(false);

  // Fetch file MD5 and settings when filePath changes.
  const fetchData = useCallback(async () => {
    if (!filePath) {
      setMd5("");
      return;
    }
    setLoading(true);
    try {
      const info = await invoke<FileInfo>("get_file_info", { path: filePath });
      setMd5(info.hashes.md5);
    } catch {
      setMd5("");
    } finally {
      setLoading(false);
    }
  }, [filePath]);

  // Fetch API key from settings.
  useEffect(() => {
    invoke<AppSettings>("get_settings")
      .then((s) => setApiKey(s.online_tools?.virustotal_apikey ?? ""))
      .catch(() => setApiKey(""));
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Auto-query VT when we have both MD5 and API key.
  useEffect(() => {
    if (md5 && apiKey) {
      queryVt();
    } else {
      setVtInfo(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [md5, apiKey]);

  const queryVt = async () => {
    if (!filePath || !apiKey) return;
    setQuerying(true);
    try {
      const info = await invoke<VtScanInfo>("virustotal_query", {
        path: filePath,
        apiKey,
      });
      setVtInfo(info);
    } catch (e) {
      setVtInfo({
        found: false,
        first_submission_date: null,
        last_analysis_date: null,
        detects: 0,
        total: 0,
        status: "",
        results: [],
        error: String(e),
      });
    } finally {
      setQuerying(false);
    }
  };

  const openVtWebsite = async () => {
    if (!filePath) return;
    try {
      await invoke("virustotal_open_browser", { path: filePath });
    } catch {
      // Fallback: open URL directly from known MD5.
      if (md5) {
        window.open(`https://www.virustotal.com/gui/file/${md5}`, "_blank");
      }
    }
  };

  const filteredResults = vtInfo
    ? showDetectedOnly
      ? vtInfo.results.filter((r) => r.result !== "")
      : vtInfo.results
    : [];

  if (!filePath) {
    return (
      <div className="border border-border rounded p-3 mt-3">
        <h3 className="text-sm font-medium mb-2">{t("online.title")}</h3>
        <p className="text-xs text-muted-foreground">{t("online.hint")}</p>
      </div>
    );
  }

  return (
    <div className="border border-border rounded p-3 mt-3 space-y-3">
      <h3 className="text-sm font-medium">{t("online.title")}</h3>

      {/* File hash display */}
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">MD5</label>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={md5}
            readOnly
            className="flex-1 text-xs font-mono border border-border rounded px-2 py-1 bg-muted/30"
          />
          {loading && (
            <span className="text-xs text-muted-foreground">Loading...</span>
          )}
        </div>
      </div>

      {/* VirusTotal section */}
      <div className="border border-border rounded p-2 space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium">VirusTotal</span>
          <div className="flex items-center gap-1">
            <button
              onClick={openVtWebsite}
              className="px-2 py-1 text-xs border border-border rounded hover:bg-muted"
              title="Open VirusTotal website"
            >
              Website
            </button>
            {apiKey && (
              <button
                onClick={queryVt}
                disabled={querying || !md5}
                className="px-2 py-1 text-xs border border-border rounded hover:bg-muted disabled:opacity-50"
                title="Reload scan info"
              >
                {querying ? "Querying..." : "Reload"}
              </button>
            )}
          </div>
        </div>

        {!apiKey && (
          <p className="text-xs text-muted-foreground">
            No API key configured. Click "Website" to open VirusTotal in your
            browser with the file's MD5 hash. Add an API key in Settings →
            Online Tools to enable in-app scan results.
          </p>
        )}

        {apiKey && querying && (
          <p className="text-xs text-muted-foreground">Querying VirusTotal...</p>
        )}

        {apiKey && vtInfo && !querying && (
          <div className="space-y-2">
            {vtInfo.error && (
              <p className="text-xs text-red-500">Error: {vtInfo.error}</p>
            )}

            {!vtInfo.error && !vtInfo.found && (
              <p className="text-xs text-muted-foreground">
                File not found on VirusTotal. You can upload it via the
                website.
              </p>
            )}

            {!vtInfo.error && vtInfo.found && (
              <>
                <div className="flex items-center gap-4 text-xs">
                  <span>
                    <strong>Status:</strong> {vtInfo.status}
                  </span>
                  <span>
                    <strong>First seen:</strong>{" "}
                    {formatDate(vtInfo.first_submission_date)}
                  </span>
                  <span>
                    <strong>Last scan:</strong>{" "}
                    {formatDate(vtInfo.last_analysis_date)}
                  </span>
                </div>

                <label className="flex items-center gap-1 text-xs">
                  <input
                    type="checkbox"
                    checked={showDetectedOnly}
                    onChange={(e) => setShowDetectedOnly(e.target.checked)}
                  />
                  Show detects only
                </label>

                <div className="max-h-64 overflow-auto border border-border rounded">
                  <table className="w-full text-xs">
                    <thead className="bg-muted/50 sticky top-0">
                      <tr>
                        <th className="text-left px-2 py-1">Engine</th>
                        <th className="text-left px-2 py-1">Version</th>
                        <th className="text-left px-2 py-1">Date</th>
                        <th className="text-left px-2 py-1">Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredResults.map((r, i) => (
                        <tr
                          key={i}
                          className={r.result ? "bg-red-500/10" : ""}
                        >
                          <td className="px-2 py-0.5">{r.engine_name}</td>
                          <td className="px-2 py-0.5">{r.engine_version}</td>
                          <td className="px-2 py-0.5">{r.engine_update}</td>
                          <td className="px-2 py-0.5">{r.result || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* Auxiliary services */}
      <div className="space-y-1">
        <span className="text-xs font-medium">Other services</span>
        <div className="grid grid-cols-3 gap-1">
          {auxiliaryServices.map((svc) => (
            <a
              key={svc.name}
              href={svc.url(md5)}
              target="_blank"
              rel="noopener noreferrer"
              className="px-2 py-1 text-xs border border-border rounded hover:bg-muted text-center"
            >
              {svc.name}
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
