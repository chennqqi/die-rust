import { useState, useEffect, useRef, useCallback, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { invoke, Channel } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  FileSearch,
  FolderOpen,
  Play,
  FolderSearch,
  Square,
  Settings as SettingsIcon,
  ChevronRight,
  ChevronDown,
  FileText,
  Binary,
  Code2,
  Tags,
  Shield,
  ScanSearch,
  Globe,
  Info,
  AlertCircle,
  Clock,
  CheckCircle2,
  XCircle,
  FileSearch as FileSearchIcon,
  Maximize2,
  Minimize2,
  Copy,
  Trash2,
  Save,
  History,
  Database,
  Map,
  Archive,
  Repeat,
  Grid3x3,
  Scissors,
} from "lucide-react";
import { HexViewer } from "./components/HexViewer";
import { Disassembler } from "./components/Disassembler";
import { DemangleTool } from "./components/DemangleTool";
import { SignatureBrowser } from "./components/SignatureBrowser";
import { YaraScanner } from "./components/YaraScanner";
import { PeidScanner } from "./components/PeidScanner";
import { OnlineTools } from "./components/OnlineTools";
import { FileInfoPanel } from "./components/FileInfoPanel";
import { SplitPane } from "./components/SplitPane";
import { SignatureHighlighter } from "./components/SignatureHighlighter";
import { MemoryMapViewer } from "./components/MemoryMapViewer";
import { ArchiveViewer } from "./components/ArchiveViewer";
import { DataConverter } from "./components/DataConverter";
import VisualizationPanel from "./components/VisualizationPanel";
import ExtractorPanel from "./components/ExtractorPanel";
import StringExtractor from "./components/StringExtractor";
import MiscViewPanel from "./components/MiscViewPanel";
import SearchPanel from "./components/SearchPanel";
import SettingsModal from "./components/SettingsModal";

interface ScanDetectionDto {
  file_type: string;
  type_name: string;
  name: string;
  version: string | null;
  options: string | null;
  signature_path: string | null;
  id: string | null;
  parent_id: string | null;
  file_part: string | null;
  offset: number | null;
  size: number | null;
  is_heuristic: boolean | null;
  is_a_heuristic: boolean | null;
  original_name: string | null;
}

interface StructuredDiagnosticDto {
  file: string;
  line: number | null;
  message: string;
  kind: string;
}

interface SignatureProfileDto {
  file: string;
  elapsed_ms: number;
}

interface ScanResultDto {
  path: string;
  detections: ScanDetectionDto[];
  diagnostics: string[];
  structured_diagnostics: StructuredDiagnosticDto[];
  profiling: SignatureProfileDto[];
  scan_time_ms: number;
  scan_log?: string[];
}

/** Database path info from list_database_paths IPC command. */
interface DatabasePathInfo {
  key: string;
  path: string;
  exists: boolean;
}

/**
 * Resolve database paths for the scan_file command.
 * When selection is "auto" or "all", returns null to let the backend
 * auto-detect all available databases. When a specific database is
 * selected, returns only that database's path.
 */
async function resolveDatabasePaths(selection: string): Promise<string[] | null> {
  if (selection === "auto" || selection === "all") return null;
  try {
    const infos = await invoke<DatabasePathInfo[]>("list_database_paths");
    const info = infos.find((i) => i.key === selection);
    if (info && info.exists) return [info.path];
  } catch {
    // Fall back to auto-detection.
  }
  return null;
}

interface GuiError {
  code: string;
  message: string;
}

interface ScanFlagsDto {
  recursive: boolean;
  deep: boolean;
  heuristic: boolean;
  verbose: boolean;
  aggressive: boolean;
  alltypes: boolean;
  overlay: boolean;
  resources: boolean;
  archives: boolean;
  first_wrapper_only: boolean;
  hide_unknown: boolean;
  no_dedup: boolean;
  /** Optional file type override. When set, only rules for this type are run. */
  file_type?: string | null;
}

interface AppSettings {
  view: { theme: string; language: string; stay_on_top: boolean; advanced: boolean };
  file: { last_directory: string; recent_files: string[]; save_backup: boolean };
  scan: {
    scan_after_open: boolean;
    hide_unknown: boolean;
    sort: boolean;
    log_profiling: boolean;
    flags: ScanFlagsDto;
  };
  database: {
    main_path: string;
    extra_path: string;
    custom_path: string;
    extra_enabled: boolean;
    custom_enabled: boolean;
  };
  engine: { die_enabled: boolean; nfd_enabled: boolean; peid_enabled: boolean; yara_enabled: boolean };
}

interface DirectoryScanProgress {
  event: string;
  data: { total_files?: number; index?: number; file_path?: string; result?: ScanResultDto; total?: number; message?: string };
}

const defaultFlags: ScanFlagsDto = {
  recursive: true,
  deep: false,
  heuristic: false,
  verbose: false,
  aggressive: false,
  alltypes: false,
  overlay: true,
  resources: true,
  archives: true,
  first_wrapper_only: false,
  hide_unknown: false,
  no_dedup: false,
};

const defaultSettings: AppSettings = {
  view: { theme: "system", language: "en", stay_on_top: false, advanced: false },
  file: { last_directory: "", recent_files: [], save_backup: true },
  scan: { scan_after_open: true, hide_unknown: false, sort: false, log_profiling: false, flags: defaultFlags },
  database: { main_path: "", extra_path: "", custom_path: "", extra_enabled: false, custom_enabled: false },
  engine: { die_enabled: true, nfd_enabled: false, peid_enabled: false, yara_enabled: false },
};

type TabId = "scan" | "info" | "hex" | "disasm" | "demangle" | "sigs" | "yara" | "peid" | "online" | "memmap" | "archive" | "converter" | "visualization" | "extractor" | "misc" | "search" | "strings";

const TAB_KEYS: { id: TabId; labelKey: string; icon: typeof FileSearch; advanced?: boolean }[] = [
  { id: "scan", labelKey: "tabs.scan", icon: ScanSearch },
  { id: "info", labelKey: "tabs.info", icon: FileSearchIcon },
  { id: "online", labelKey: "tabs.online", icon: Globe },
  // Advanced tabs (only shown when Advanced mode is enabled)
  { id: "hex", labelKey: "tabs.hex", icon: Binary, advanced: true },
  { id: "disasm", labelKey: "tabs.disasm", icon: Code2, advanced: true },
  { id: "demangle", labelKey: "tabs.demangle", icon: FileText, advanced: true },
  { id: "sigs", labelKey: "tabs.signatures", icon: Tags, advanced: true },
  { id: "yara", labelKey: "tabs.yara", icon: Shield, advanced: true },
  { id: "peid", labelKey: "tabs.peid", icon: ScanSearch, advanced: true },
  { id: "memmap", labelKey: "tabs.memmap", icon: Map, advanced: true },
  { id: "archive", labelKey: "tabs.archive", icon: Archive, advanced: true },
  { id: "converter", labelKey: "tabs.converter", icon: Repeat, advanced: true },
  { id: "visualization", labelKey: "tabs.visualization", icon: Grid3x3, advanced: true },
  { id: "extractor", labelKey: "tabs.extractor", icon: Scissors, advanced: true },
  { id: "misc", labelKey: "tabs.misc", icon: FileText, advanced: true },
  { id: "search", labelKey: "tabs.search", icon: ScanSearch, advanced: true },
  { id: "strings", labelKey: "tabs.strings", icon: FileText, advanced: true },
];

export default function App() {
  const { t, i18n } = useTranslation();
  const [filePath, setFilePath] = useState<string>("");
  const [result, setResult] = useState<ScanResultDto | null>(null);
  const [dirResults, setDirResults] = useState<ScanResultDto[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanPhase, setScanPhase] = useState<string>("");
  const [dragOver, setDragOver] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [advancedMode, setAdvancedMode] = useState(false);
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [flags, setFlags] = useState<ScanFlagsDto>(defaultFlags);
  const [selectedDatabase, setSelectedDatabase] = useState<string>("main");
  const [dirProgress, setDirProgress] = useState<{ current: number; total: number } | null>(null);
  const [fileInfo, setFileInfo] = useState<{ format: string; base_address: string; entry_point: string; format_count: number } | null>(null);
  const [ctxMenuStatus, setCtxMenuStatus] = useState<"installed" | "not_installed" | "checking" | "unsupported">("checking");
  const [ctxMenuMsg, setCtxMenuMsg] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("scan");
  const [disasmJumpOffset, setDisasmJumpOffset] = useState<number | null>(null);
  const [hexJumpOffset, setHexJumpOffset] = useState<number | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [selectedDetection, setSelectedDetection] = useState<ScanDetectionDto | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showRecent, setShowRecent] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; detection: ScanDetectionDto } | null>(null);
  const [copyFeedback, setCopyFeedback] = useState(false);
  const dragCounter = useRef(0);

  // Load settings on mount.
  useEffect(() => {
    invoke<AppSettings>("get_settings")
      .then((s) => {
        setSettings(s);
        setFlags(s.scan.flags);
        // Apply saved advanced mode.
        setAdvancedMode(s.view.advanced);
        // Apply saved language to i18n.
        if (s.view.language) {
          i18n.changeLanguage(s.view.language);
        }
      })
      .catch(() => {});
  }, [i18n]);

  // Fetch file info (format, base address, entry point) when file path changes.
  useEffect(() => {
    if (!filePath) {
      setFileInfo(null);
      return;
    }
    invoke<{ format: string; base_address: string; entry_point: string; format_count: number }>("get_file_info", { path: filePath })
      .then((info) => setFileInfo(info))
      .catch(() => setFileInfo(null));
  }, [filePath]);

  // Listen for scan progress events from the backend.
  useEffect(() => {
    const unlisten = listen<{ phase: string; path?: string; elapsed_ms?: number }>(
      "scan_progress",
      (e) => {
        setScanPhase(e.payload.phase);
      },
    );
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // React to language setting changes.
  useEffect(() => {
    if (settings.view.language && settings.view.language !== i18n.language) {
      i18n.changeLanguage(settings.view.language);
    }
  }, [settings.view.language, i18n]);

  // Check context menu integration status when settings panel opens.
  useEffect(() => {
    if (!showSettings) return;
    setCtxMenuStatus("checking");
    setCtxMenuMsg(null);
    invoke<{ installed: boolean; exe_path: string; platform: string }>("get_context_menu_status")
      .then((res) => {
        if (res.platform === "windows") {
          setCtxMenuStatus(res.installed ? "installed" : "not_installed");
        } else {
          setCtxMenuStatus("unsupported");
        }
      })
      .catch(() => setCtxMenuStatus("unsupported"));
  }, [showSettings]);

  // Add context menu integration.
  const addContextMenu = useCallback(async () => {
    setCtxMenuMsg(null);
    try {
      await invoke("add_context_menu");
      setCtxMenuStatus("installed");
      setCtxMenuMsg(t("settings.contextMenuAddSuccess"));
    } catch (e) {
      const err = e as GuiError;
      setCtxMenuMsg(t("settings.contextMenuError", { error: err.message ?? String(e) }));
    }
  }, [t]);

  // Remove context menu integration.
  const removeContextMenu = useCallback(async () => {
    setCtxMenuMsg(null);
    try {
      await invoke("remove_context_menu");
      setCtxMenuStatus("not_installed");
      setCtxMenuMsg(t("settings.contextMenuRemoveSuccess"));
    } catch (e) {
      const err = e as GuiError;
      setCtxMenuMsg(t("settings.contextMenuError", { error: err.message ?? String(e) }));
    }
  }, [t]);

  // Register drag-drop event listener (Tauri only; silently ignored in browser).
  useEffect(() => {
    const webview = getCurrentWebview();
    const unlisten = webview.onDragDropEvent((event: { payload: { type: string; paths?: string[] } }) => {
      if (event.payload.type === "over") {
        setDragOver(true);
      } else if (event.payload.type === "drop") {
        setDragOver(false);
        const paths = event.payload.paths;
        if (paths && paths.length > 0) {
          setFilePath(paths[0]);
          setResult(null);
          setDirResults([]);
          setError(null);
        }
      } else if (event.payload.type === "leave") {
        setDragOver(false);
      }
    }).catch(() => {
      // Not in Tauri environment (e.g. browser dev mode) — drag-drop disabled.
    });
    return () => {
      unlisten.then((fn) => { if (typeof fn === "function") fn(); }).catch(() => {});
    };
  }, []);

  // Listen for context-menu-file event (launched from Explorer right-click).
  useEffect(() => {
    const unlisten = listen<string>("context-menu-file", (event) => {
      const path = event.payload;
      if (path) {
        setFilePath(path);
        setResult(null);
        setDirResults([]);
        setError(null);
      }
    }).catch(() => {
      // Not in Tauri environment — event listener disabled.
    });
    return () => {
      unlisten.then((fn) => { if (typeof fn === "function") fn(); }).catch(() => {});
    };
  }, []);

  // Also handle native HTML drag-over for visual feedback.
  useEffect(() => {
    const handleDragEnter = (e: DragEvent) => {
      e.preventDefault();
      dragCounter.current++;
      setDragOver(true);
    };
    const handleDragLeave = (e: DragEvent) => {
      e.preventDefault();
      dragCounter.current--;
      if (dragCounter.current === 0) setDragOver(false);
    };
    const handleDragOver = (e: DragEvent) => {
      e.preventDefault();
    };
    const handleDrop = (e: DragEvent) => {
      e.preventDefault();
      dragCounter.current = 0;
      setDragOver(false);
    };
    window.addEventListener("dragenter", handleDragEnter);
    window.addEventListener("dragleave", handleDragLeave);
    window.addEventListener("dragover", handleDragOver);
    window.addEventListener("drop", handleDrop);
    return () => {
      window.removeEventListener("dragenter", handleDragEnter);
      window.removeEventListener("dragleave", handleDragLeave);
      window.removeEventListener("dragover", handleDragOver);
      window.removeEventListener("drop", handleDrop);
    };
  }, []);

  // Add a file path to recent files list (max 10, deduplicated).
  const addToRecent = useCallback((path: string) => {
    setSettings((prev) => {
      const recent = [path, ...prev.file.recent_files.filter((p) => p !== path)].slice(0, 10);
      return { ...prev, file: { ...prev.file, recent_files: recent } };
    });
  }, []);

  const fileName = filePath.split(/[\\/]/).pop() || filePath;

  const pickFile = useCallback(async () => {
    try {
      const selected = await openDialog({ multiple: false });
      if (typeof selected === "string") {
        setFilePath(selected);
        setResult(null);
        setDirResults([]);
        setError(null);
        addToRecent(selected);
      }
    } catch (e) {
      setError(String(e));
    }
  }, [addToRecent]);

  const pickDirectory = useCallback(async () => {
    try {
      const selected = await openDialog({ directory: true, multiple: false });
      if (typeof selected === "string") {
        setFilePath(selected);
        setResult(null);
        setDirResults([]);
        setError(null);
        addToRecent(selected);
      }
    } catch (e) {
      setError(String(e));
    }
  }, [addToRecent]);

  const scan = useCallback(async () => {
    if (!filePath) return;
    setScanning(true);
    setError(null);
    setResult(null);
    setDirResults([]);
    try {
      // Build database paths from selectedDatabase. When "auto", pass null
      // to let the backend auto-detect (db + db_extra + db_custom).
      const dbPaths = await resolveDatabasePaths(selectedDatabase);
      // Build flags with file_type override (null when "Auto").
      const flagsWithFileType: ScanFlagsDto = {
        ...flags,
        file_type: flags.file_type && flags.file_type !== "Auto" ? flags.file_type : null,
      };
      const res = await invoke<ScanResultDto>("scan_file", {
        path: filePath,
        flags: flagsWithFileType,
        databasePaths: dbPaths,
      });
      setResult(res);
      // Auto-expand all group nodes.
      const groupMap: Record<string, ScanDetectionDto[]> = {};
      for (const d of res.detections) {
        if (!groupMap[d.file_type]) groupMap[d.file_type] = [];
        groupMap[d.file_type].push(d);
      }
      setExpandedNodes(new Set(Object.keys(groupMap).map((_, i) => `group-${i}`)));
    } catch (e) {
      const err = e as GuiError;
      setError(err.message ?? String(e));
    } finally {
      setScanning(false);
    }
  }, [filePath, flags]);

  const scanDirectory = useCallback(async () => {
    if (!filePath) return;
    setScanning(true);
    setError(null);
    setResult(null);
    setDirResults([]);
    setDirProgress({ current: 0, total: 0 });
    try {
      const channel = new Channel<DirectoryScanProgress>();
      channel.onmessage = (msg) => {
        if (msg.event === "started" && msg.data.total_files !== undefined) {
          setDirProgress({ current: 0, total: msg.data.total_files });
        } else if (msg.event === "file_scanned") {
          if (msg.data.result) {
            setDirResults((prev) => [...prev, msg.data.result!]);
          }
          setDirProgress({
            current: (msg.data.index ?? 0) + 1,
            total: dirProgress?.total ?? 0,
          });
        } else if (msg.event === "finished") {
          setDirProgress(null);
        } else if (msg.event === "error") {
          setError(msg.data.message ?? "Unknown error");
        }
      };
      const results = await invoke<ScanResultDto[]>("scan_directory", {
        dir: filePath,
        flags,
        subdirectories: flags.recursive,
        onProgress: channel,
      });
      setDirResults(results);
    } catch (e) {
      const err = e as GuiError;
      setError(err.message ?? String(e));
    } finally {
      setScanning(false);
      setDirProgress(null);
    }
  }, [filePath, flags, selectedDatabase, dirProgress]);

  const stopScan = useCallback(async () => {
    try {
      await invoke("stop_scan");
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const saveSettings = useCallback(async () => {
    const newSettings = { ...settings, scan: { ...settings.scan, flags } };
    setSettings(newSettings);
    try {
      await invoke("save_settings", { settings: newSettings });
      setShowSettings(false);
    } catch (e) {
      const err = e as GuiError;
      setError(err.message ?? String(e));
    }
  }, [settings, flags]);

  // Toggle fullscreen mode.
  const toggleFullscreen = useCallback(async () => {
    try {
      const win = getCurrentWindow();
      const newFs = !isFullscreen;
      await win.setFullscreen(newFs);
      setIsFullscreen(newFs);
    } catch {
      setIsFullscreen(!isFullscreen);
    }
  }, [isFullscreen]);

  // Open a file from recent files list.
  const openRecent = useCallback((path: string) => {
    setFilePath(path);
    setResult(null);
    setDirResults([]);
    setError(null);
    setShowRecent(false);
  }, []);

  // Copy scan results as text to clipboard.
  const copyResults = useCallback(() => {
    if (!result) return;
    const lines: string[] = [`File: ${result.path}`, `Time: ${result.scan_time_ms} ms`, ""];
    for (const d of result.detections) {
      const parts = [d.type_name, d.name, d.version ?? "", d.options ?? ""].filter(Boolean);
      lines.push(parts.join(" | "));
    }
    navigator.clipboard.writeText(lines.join("\n"));
    setCopyFeedback(true);
    setTimeout(() => setCopyFeedback(false), 1500);
  }, [result]);

  // Clear all results.
  const clearResults = useCallback(() => {
    setResult(null);
    setDirResults([]);
    setError(null);
    setSelectedDetection(null);
  }, []);

  // Save results to file (via Tauri dialog).
  const saveResults = useCallback(async () => {
    if (!result) return;
    try {
      const savePath = await openDialog({ save: true, defaultPath: `${fileName}_results.txt` });
      if (typeof savePath === "string") {
        const lines: string[] = [`File: ${result.path}`, `Time: ${result.scan_time_ms} ms`, ""];
        for (const d of result.detections) {
          const parts = [d.type_name, d.name, d.version ?? "", d.options ?? ""].filter(Boolean);
          lines.push(parts.join(" | "));
        }
        await invoke("write_text_file", { path: savePath, content: lines.join("\n") });
      }
    } catch (e) {
      setError(String(e));
    }
  }, [result, fileName]);

  // Close context menu on click anywhere.
  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [contextMenu]);

  // Global keyboard shortcuts.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Ctrl+O: Open file.
      if (e.ctrlKey && e.key === "o" && !e.shiftKey) {
        e.preventDefault();
        pickFile();
      }
      // Ctrl+Shift+O: Open directory.
      if (e.ctrlKey && e.shiftKey && e.key === "O") {
        e.preventDefault();
        pickDirectory();
      }
      // F11: Toggle fullscreen.
      if (e.key === "F11") {
        e.preventDefault();
        toggleFullscreen();
      }
      // Ctrl+Enter: Scan.
      if (e.ctrlKey && e.key === "Enter") {
        e.preventDefault();
        if (filePath && !scanning) scan();
      }
      // Escape: Close settings/recent/context menu.
      if (e.key === "Escape") {
        setShowSettings(false);
        setShowRecent(false);
        setContextMenu(null);
      }
      // Ctrl+C (when no text selected): Copy results.
      if (e.ctrlKey && e.key === "c" && !window.getSelection()?.toString()) {
        if (result) copyResults();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [pickFile, pickDirectory, toggleFullscreen, filePath, scanning, scan, result, copyResults]);

  // Apply theme to document root.
  useEffect(() => {
    const applyTheme = (theme: string) => {
      if (theme === "light") {
        document.documentElement.classList.remove("dark");
        document.documentElement.classList.add("light");
      } else if (theme === "dark") {
        document.documentElement.classList.remove("light");
        document.documentElement.classList.add("dark");
      }
      // "system" theme: detect OS preference.
      if (theme === "system") {
        const mq = window.matchMedia("(prefers-color-scheme: dark)");
        if (mq.matches) {
          document.documentElement.classList.remove("light");
          document.documentElement.classList.add("dark");
        } else {
          document.documentElement.classList.remove("dark");
          document.documentElement.classList.add("light");
        }
      }
    };
    applyTheme(settings.view.theme);
    // Listen for OS theme changes when in system mode.
    if (settings.view.theme === "system") {
      const mq = window.matchMedia("(prefers-color-scheme: dark)");
      const onChange = (e: MediaQueryListEvent) => {
        if (e.matches) {
          document.documentElement.classList.remove("light");
          document.documentElement.classList.add("dark");
        } else {
          document.documentElement.classList.remove("dark");
          document.documentElement.classList.add("light");
        }
      };
      mq.addEventListener("change", onChange);
      return () => mq.removeEventListener("change", onChange);
    }
  }, [settings.view.theme]);

  const toggleNode = (id: string) => {
    setExpandedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const totalDetections = result?.detections.length ?? 0;
  const totalDiags = result?.diagnostics.length ?? 0;

  return (
    <div
      className="h-screen flex flex-col bg-window text-fg-primary"
      style={{ background: "rgb(var(--bg-window))" }}
    >
      {/* Drag overlay */}
      {dragOver && (
        <div className="absolute inset-0 z-50 flex items-center justify-center bg-blue-900/30 border-2 border-dashed border-accent-blue rounded">
          <div className="text-center">
            <FileSearch size={48} className="mx-auto mb-2 text-accent-blue" />
            <p className="text-lg text-accent-blue">Drop file here to scan</p>
          </div>
        </div>
      )}

      {/* Toolbar — file input + scan controls */}
      <div
        className="flex items-center gap-1 px-2 py-1.5 border-b border-border-c"
        style={{ background: "rgb(var(--bg-panel))" }}
      >
        <input
          type="text"
          value={filePath}
          onChange={(e) => setFilePath(e.target.value)}
          placeholder={t("scan.select")}
          className="input flex-1 selectable"
        />
        <button onClick={pickFile} className="btn" title={t("toolbar.file")}>
          <FileSearch size={14} /> {t("toolbar.file")}
        </button>
        <button onClick={pickDirectory} className="btn" title={t("toolbar.dir")}>
          <FolderOpen size={14} /> {t("toolbar.dir")}
        </button>
        <div className="w-px h-5 bg-border-c mx-1" />
        <button
          onClick={scan}
          disabled={!filePath || scanning}
          className="btn btn-primary"
          title={t("toolbar.scan")}
        >
          <Play size={14} /> {scanning ? t("toolbar.scanning") : t("toolbar.scan")}
        </button>
        <button
          onClick={scanDirectory}
          disabled={!filePath || scanning}
          className="btn"
          title={t("toolbar.scanDir")}
        >
          <FolderSearch size={14} /> {t("toolbar.scanDir")}
        </button>
        <button
          onClick={stopScan}
          disabled={!scanning}
          className="btn btn-danger"
          title={t("toolbar.stop")}
        >
          <Square size={14} /> {t("toolbar.stop")}
        </button>
        <div className="w-px h-5 bg-border-c mx-1" />
        <button
          onClick={copyResults}
          disabled={!result}
          className="btn"
          title={t("toolbar.copyResults") + " (Ctrl+C)"}
        >
          {copyFeedback ? <CheckCircle2 size={14} className="text-accent-green" /> : <Copy size={14} />}
        </button>
        <button
          onClick={clearResults}
          disabled={!result && dirResults.length === 0}
          className="btn"
          title={t("toolbar.clearResults")}
        >
          <Trash2 size={14} />
        </button>
        <button
          onClick={saveResults}
          disabled={!result}
          className="btn"
          title={t("toolbar.saveResults")}
        >
          <Save size={14} />
        </button>
        <div className="flex-1" />
        <div className="relative">
          <button
            onClick={() => setShowRecent(!showRecent)}
            className="btn"
            title={t("toolbar.recentFiles")}
            disabled={settings.file.recent_files.length === 0}
          >
            <History size={14} />
          </button>
          {showRecent && (
            <div
              className="absolute right-0 top-full mt-1 panel z-50 min-w-64 max-h-80 overflow-auto"
              style={{ background: "rgb(var(--bg-panel))" }}
            >
              <div className="text-xs font-medium text-fg-secondary px-3 py-1.5 border-b border-border-c">
                {t("recent.title")}
              </div>
              {settings.file.recent_files.map((p, i) => {
                const name = p.split(/[\\/]/).pop() || p;
                return (
                  <button
                    key={i}
                    onClick={() => openRecent(p)}
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-hover flex items-center gap-2"
                  >
                    <FileText size={12} className="text-fg-muted flex-shrink-0" />
                    <div className="flex-1 overflow-hidden">
                      <div className="text-fg-primary truncate">{name}</div>
                      <div className="text-fg-muted truncate mono" style={{ fontSize: "10px" }}>{p}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
        <button
          onClick={toggleFullscreen}
          className="btn"
          title={t("toolbar.fullscreen") + " (F11)"}
        >
          {isFullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
        </button>
        <button
          onClick={() => setShowSettings(!showSettings)}
          className="btn"
          title={t("toolbar.settings")}
        >
          <SettingsIcon size={14} />
        </button>
      </div>

      {/* Settings panel (collapsible) */}
      {showSettings && (
        <div
          className="px-3 py-2 border-b border-border-c space-y-2"
          style={{ background: "rgb(var(--bg-panel))" }}
        >
          <div className="text-xs font-medium text-fg-secondary">{t("settings.scanFlags")}</div>
          <div className="grid grid-cols-4 gap-1.5 text-xs">
            {(Object.keys(flags) as (keyof ScanFlagsDto)[]).map((key) => (
              <label key={key} className="flex items-center gap-1.5 cursor-pointer hover:text-fg-primary">
                <input
                  type="checkbox"
                  checked={Boolean(flags[key])}
                  onChange={(e) => setFlags({ ...flags, [key]: e.target.checked })}
                  className="accent-blue-500"
                />
                {key}
              </label>
            ))}
          </div>
          <div className="border-t border-border-c pt-2 space-y-1.5">
            <div className="text-xs font-medium text-fg-secondary">{t("settings.viewOptions")}</div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-fg-muted">{t("settings.theme")}:</span>
              <select
                className="input py-0.5 px-1.5"
                value={settings.view.theme}
                onChange={(e) => setSettings({ ...settings, view: { ...settings.view, theme: e.target.value } })}
                style={{ width: "100px" }}
              >
                <option value="system">{t("settings.system")}</option>
                <option value="dark">{t("settings.dark")}</option>
                <option value="light">{t("settings.light")}</option>
              </select>
              <select
                className="input py-0.5 px-1.5"
                value={settings.view.language}
                onChange={(e) => setSettings({ ...settings, view: { ...settings.view, language: e.target.value } })}
                style={{ width: "100px" }}
              >
                <option value="en">English</option>
                <option value="zh-CN">中文</option>
                <option value="ru">Русский</option>
                <option value="de">Deutsch</option>
                <option value="fr">Français</option>
              </select>
            </div>
            <label className="flex items-center gap-1.5 cursor-pointer text-xs hover:text-fg-primary">
              <input
                type="checkbox"
                checked={settings.view.advanced}
                onChange={(e) => setSettings({ ...settings, view: { ...settings.view, advanced: e.target.checked } })}
                className="accent-blue-500"
              />
              {t("settings.advanced")}
            </label>
          </div>
          {/* Context menu integration */}
          <div className="border-t border-border-c pt-2 space-y-1.5">
            <div className="text-xs font-medium text-fg-secondary">{t("settings.contextMenu")}</div>
            {ctxMenuStatus === "unsupported" ? (
              <p className="text-xs text-fg-muted">{t("settings.contextMenuUnsupported")}</p>
            ) : (
              <>
                <p className="text-xs text-fg-muted">{t("settings.contextMenuDesc")}</p>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-fg-muted">
                    {ctxMenuStatus === "checking" && t("settings.contextMenuChecking")}
                    {ctxMenuStatus === "installed" && `✓ ${t("settings.contextMenuInstalled")}`}
                    {ctxMenuStatus === "not_installed" && t("settings.contextMenuNotInstalled")}
                  </span>
                  <div className="flex-1" />
                  {ctxMenuStatus === "installed" ? (
                    <button
                      onClick={removeContextMenu}
                      className="px-2 py-0.5 text-xs border border-border-c rounded hover:bg-hover"
                    >
                      {t("settings.contextMenuRemove")}
                    </button>
                  ) : (
                    <button
                      onClick={addContextMenu}
                      disabled={ctxMenuStatus === "checking"}
                      className="px-2 py-0.5 text-xs bg-primary text-background rounded disabled:opacity-50"
                    >
                      {t("settings.contextMenuAdd")}
                    </button>
                  )}
                </div>
                {ctxMenuMsg && (
                  <p className={`text-xs ${ctxMenuMsg.includes("失败") || ctxMenuMsg.includes("Failed") ? "text-accent-red" : "text-accent-green"}`}>
                    {ctxMenuMsg}
                  </p>
                )}
              </>
            )}
          </div>
          <div className="flex gap-2 pt-1">
            <button onClick={saveSettings} className="btn btn-primary">{t("settings.save")}</button>
            <button onClick={() => setShowSettings(false)} className="btn">{t("settings.cancel")}</button>
          </div>
        </div>
      )}

      {/* Tab bar */}
      <div
        className="flex items-center gap-0 px-1 border-b border-border-c"
        style={{ background: "rgb(var(--bg-panel))" }}
      >
        {TAB_KEYS.filter((tab) => advancedMode || !tab.advanced).map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs ${
                activeTab === tab.id ? "tab-active" : "tab-inactive"
              }`}
            >
              <Icon size={13} />
              {t(tab.labelKey)}
            </button>
          );
        })}
        {/* Advanced mode toggle */}
        <button
          onClick={() => {
            const newMode = !advancedMode;
            setAdvancedMode(newMode);
            // Persist to settings.
            const newSettings = { ...settings, view: { ...settings.view, advanced: newMode } };
            setSettings(newSettings);
            invoke("save_settings", { settings: newSettings }).catch(() => {});
            // If switching to basic mode and current tab is advanced, switch to scan
            if (!newMode && TAB_KEYS.find((tab) => tab.id === activeTab)?.advanced) {
              setActiveTab("scan");
            }
          }}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs ml-auto ${
            advancedMode ? "tab-active" : "tab-inactive"
          }`}
          title={advancedMode ? "Switch to Basic mode" : "Switch to Advanced mode"}
        >
          <SettingsIcon size={13} />
          {advancedMode ? "Basic" : "Advanced"}
        </button>
      </div>

      {/* Main content area */}
      <div className="flex-1 overflow-auto" style={{ background: "rgb(var(--bg-window))" }}>
        {/* Error banner */}
        {error && (
          <div
            className="flex items-center gap-2 px-3 py-2 mx-2 mt-2 rounded text-xs"
            style={{ background: "rgba(var(--accent-red), 0.1)", border: "1px solid rgb(var(--accent-red))" }}
          >
            <AlertCircle size={14} className="text-accent-red" />
            <span className="text-accent-red selectable">{error}</span>
          </div>
        )}

        {/* Scan tab */}
        {activeTab === "scan" && (
          <div className="flex flex-col h-full">
            {/* File info bar */}
            {filePath && (
              <div
                className="flex items-center gap-3 px-3 py-1.5 border-b border-border-c text-xs"
                style={{ background: "rgb(var(--bg-panel))" }}
              >
                <Info size={13} className="text-fg-muted" />
                <span className="selectable text-fg-secondary">{fileName}</span>
                {result && (
                  <>
                    <div className="w-px h-3 bg-border-c" />
                    <span className="text-fg-muted">{totalDetections} {t("scan.detections")}</span>
                    {totalDiags > 0 && (
                      <span className="text-accent-yellow">{totalDiags} {t("scan.diagnostics")}</span>
                    )}
                    <div className="flex-1" />
                    <span className="flex items-center gap-1 text-fg-muted">
                      <Clock size={11} /> {result.scan_time_ms} ms
                    </span>
                  </>
                )}
                <div className="w-px h-3 bg-border-c" />
                <div className="flex items-center gap-1 text-fg-muted">
                  <Database size={11} />
                  <select
                    className="input py-0 px-1"
                    style={{ width: "80px", fontSize: "11px" }}
                    value={selectedDatabase}
                    onChange={(e) => setSelectedDatabase(e.target.value)}
                    title="Database selection"
                  >
                    <option value="auto">Auto</option>
                    <option value="main">Main</option>
                    <option value="extra">Extra</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
              </div>
            )}

            {/* Advanced mode: Type/Flags toolbar (mirrors upstream comboBoxType/comboBoxFlags) */}
            {settings.view.advanced && filePath && (
              <AdvancedToolbar flags={flags} onFlagsChange={setFlags} />
            )}

            {/* Format info bar: shows file type, base address, entry point, format count */}
            {filePath && fileInfo && (
              <div
                className="flex items-center gap-3 px-3 py-1 border-b border-border-c text-xs text-fg-muted"
                style={{ background: "rgb(var(--bg-panel))" }}
              >
                <span>Format: <span className="text-fg-secondary font-mono">{fileInfo.format}</span></span>
                {fileInfo.base_address !== "0" && (
                  <span>Base: <span className="text-fg-secondary font-mono">0x{BigInt(fileInfo.base_address).toString(16)}</span></span>
                )}
                {fileInfo.entry_point !== "0" && (
                  <span>Entry: <span className="text-fg-secondary font-mono">0x{BigInt(fileInfo.entry_point).toString(16)}</span></span>
                )}
                {fileInfo.format_count > 0 && (
                  <span>Sections: <span className="text-fg-secondary font-mono">{fileInfo.format_count}</span></span>
                )}
              </div>
            )}

            {/* Progress bar during directory scan */}
            {dirProgress && (
              <div className="px-3 py-1.5">
                <div className="flex justify-between text-xs text-fg-secondary mb-1">
                  <span>Scanning directory...</span>
                  <span>{dirProgress.current} / {dirProgress.total}</span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-bar-fill"
                    style={{
                      width: dirProgress.total > 0
                        ? `${(dirProgress.current / dirProgress.total) * 100}%`
                        : "0%",
                    }}
                  />
                </div>
              </div>
            )}

            {/* Scanning indicator */}
            {scanning && !dirProgress && (
              <div className="px-3 py-2 text-xs text-fg-secondary flex items-center gap-2">
                <div className="w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
                {scanPhase === "loading_database"
                  ? t("scan.phaseLoadingDb")
                  : scanPhase === "scanning"
                    ? t("scan.phaseScanning")
                    : scanPhase === "complete"
                      ? t("scan.phaseComplete")
                      : t("scan.ready")}
              </div>
            )}

            {/* Results: TreeView for single file, list for directory */}
            {result && (
              <SplitPane
                showBottom={settings.view.advanced && !!selectedDetection}
                top={
                  <DetectionTreeView
                    result={result}
                    expandedNodes={expandedNodes}
                    onToggle={toggleNode}
                    selectedDetection={selectedDetection}
                    onSelect={setSelectedDetection}
                    onContextMenu={(x, y, d) => setContextMenu({ x, y, detection: d })}
                  />
                }
                bottom={
                  selectedDetection ? (
                    <SignatureSourcePanel detection={selectedDetection} />
                  ) : null
                }
              />
            )}

            {dirResults.length > 0 && (
              <DirectoryResultsView results={dirResults} />
            )}

            {/* Empty state */}
            {!result && dirResults.length === 0 && !scanning && !error && (
              <div className="flex flex-col items-center justify-center h-full text-fg-muted">
                <FileSearch size={48} className="mb-3 opacity-40" />
                <p className="text-sm">{t("scan.openToBegin")}</p>
              </div>
            )}
          </div>
        )}

        {activeTab === "info" && filePath && <FileInfoPanel path={filePath} />}
        {activeTab === "hex" && filePath && (
          <HexViewer
            path={filePath}
            initialOffset={hexJumpOffset}
            onFollowInDisasm={(off) => {
              setDisasmJumpOffset(off);
              setActiveTab("disasm");
            }}
          />
        )}
        {activeTab === "disasm" && filePath && (
          <Disassembler
            path={filePath}
            initialOffset={disasmJumpOffset}
            onFollowInHex={(off) => {
              setHexJumpOffset(off);
              setActiveTab("hex");
            }}
          />
        )}
        {activeTab === "demangle" && <DemangleTool />}
        {activeTab === "sigs" && <SignatureBrowser />}
        {activeTab === "yara" && filePath && <YaraScanner path={filePath} />}
        {activeTab === "peid" && filePath && <PeidScanner path={filePath} />}
        {activeTab === "online" && <OnlineTools filePath={filePath} />}

        {/* Memory map tab */}
        {activeTab === "memmap" && <MemoryMapViewer filePath={filePath} />}

        {/* Archive viewer tab */}
        {activeTab === "archive" && <ArchiveViewer filePath={filePath} />}

        {/* Data converter tab */}
        {activeTab === "converter" && <DataConverter />}

        {/* Visualization tab */}
        {activeTab === "visualization" && <VisualizationPanel filePath={filePath} />}

        {/* Extractor tab */}
        {activeTab === "extractor" && <ExtractorPanel filePath={filePath} />}

        {/* Strings tab */}
        {activeTab === "strings" && (
          <StringExtractor
            filePath={filePath}
            onHexJump={(offset) => {
              setFilePath(filePath);
              setActiveTab("hex");
              // Hex viewer should pick up the offset from state or event.
              console.log("Jump to hex at", offset);
            }}
            onDisasmJump={(offset) => {
              setFilePath(filePath);
              setActiveTab("disasm");
              console.log("Jump to disasm at", offset);
            }}
          />
        )}

        {/* Misc formats tab (DEX/MSDOS/NE/LE) */}
        {activeTab === "misc" && <MiscViewPanel filePath={filePath} />}

        {/* Search tab (signature/value search + packer detection) */}
        {activeTab === "search" && <SearchPanel filePath={filePath} />}
      </div>

      {/* Context menu for detection items */}
      {contextMenu && (
        <div
          className="fixed z-50 panel py-1 min-w-48"
          style={{ left: contextMenu.x, top: contextMenu.y, background: "rgb(var(--bg-panel))" }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            className="w-full text-left px-3 py-1.5 text-xs hover:bg-hover flex items-center gap-2"
            onClick={() => {
              const d = contextMenu.detection;
              const text = [d.type_name, d.name, d.version ?? "", d.options ?? ""].filter(Boolean).join(" | ");
              navigator.clipboard.writeText(text);
              setContextMenu(null);
            }}
          >
            <Copy size={12} /> Copy detection
          </button>
          <button
            className="w-full text-left px-3 py-1.5 text-xs hover:bg-hover flex items-center gap-2"
            onClick={() => {
              setSelectedDetection(contextMenu.detection);
              setContextMenu(null);
            }}
          >
            <Code2 size={12} /> View signature source
          </button>
          <button
            className="w-full text-left px-3 py-1.5 text-xs hover:bg-hover flex items-center gap-2"
            onClick={() => {
              const d = contextMenu.detection;
              const text = `${d.file_type}/${d.type_name}/${d.name}`;
              navigator.clipboard.writeText(text);
              setContextMenu(null);
            }}
          >
            <FileText size={12} /> Copy as path
          </button>
        </div>
      )}

      {/* Status bar */}
      <div className="statusbar">
        {scanning ? (
          <>
            <div className="w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
            <span>Scanning...</span>
          </>
        ) : result ? (
          <>
            <CheckCircle2 size={12} className="text-accent-green" />
            <span>{t("scan.ready")} — {totalDetections} {t("scan.detections")}</span>
          </>
        ) : error ? (
          <>
            <XCircle size={12} className="text-accent-red" />
            <span>{t("scan.error")}</span>
          </>
        ) : (
          <>
            <div className="w-2 h-2 rounded-full bg-fg-muted" />
            <span>{t("scan.ready")}</span>
          </>
        )}
        {result && <span className="text-fg-muted">| {result.scan_time_ms} ms</span>}
        {filePath && <span className="text-fg-muted selectable">| {fileName}</span>}
        <div className="flex-1" />
        <span className="text-fg-muted">DIE v0.4.7</span>
      </div>

      {/* Settings modal dialog */}
      <SettingsModal open={showSettings} onClose={() => setShowSettings(false)} />
    </div>
  );
}

/** Tree view for detection results — mirrors upstream DIE's 3-column TreeView. */
function DetectionTreeView({
  result,
  expandedNodes,
  onToggle,
  selectedDetection,
  onSelect,
  onContextMenu,
}: {
  result: ScanResultDto;
  expandedNodes: Set<string>;
  onToggle: (id: string) => void;
  selectedDetection: ScanDetectionDto | null;
  onSelect: (d: ScanDetectionDto) => void;
  onContextMenu: (x: number, y: number, d: ScanDetectionDto) => void;
}) {
  const { t } = useTranslation();
  if (result.detections.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-fg-muted">
        <Info size={32} className="mb-2 opacity-40" />
        <p className="text-sm">{t("scan.noDetections")}</p>
      </div>
    );
  }

  // Group detections by file_type (upstream groups by type in tree).
  const groupMap: Record<string, ScanDetectionDto[]> = {};
  for (const d of result.detections) {
    if (!groupMap[d.file_type]) groupMap[d.file_type] = [];
    groupMap[d.file_type].push(d);
  }
  const groupEntries = Object.entries(groupMap);

  // Build a map of id → children for nested tree support.
  // Detections with parent_id are rendered as children of their parent.
  const childrenMap: Record<string, ScanDetectionDto[]> = {};
  for (const d of result.detections) {
    if (d.parent_id && d.id) {
      if (!childrenMap[d.parent_id]) childrenMap[d.parent_id] = [];
      childrenMap[d.parent_id].push(d);
    }
  }

  /** Format heuristic marker prefix for a detection. */
  function heuristicPrefix(d: ScanDetectionDto): string {
    if (d.is_a_heuristic) return "(A-Heur) ";
    if (d.is_heuristic) return "(Heur) ";
    return "";
  }

  /** Format file part / offset / size suffix for a detection. */
  function partInfo(d: ScanDetectionDto): string {
    const parts: string[] = [];
    if (d.file_part) parts.push(d.file_part);
    if (d.offset != null) parts.push(`@0x${d.offset.toString(16)}`);
    if (d.size != null) parts.push(`size=0x${d.size.toString(16)}`);
    return parts.length > 0 ? ` [${parts.join(" ")}]` : "";
  }

  /** Render a detection row and its nested children recursively. */
  function renderDetection(d: ScanDetectionDto, di: number, parentId: string, depth: number): ReactNode {
    const nodeId = `${parentId}-${di}`;
    const nodeExpanded = expandedNodes.has(nodeId);
    const hasOptions = d.options && d.options.length > 0;
    const hasChildren = d.id != null && (childrenMap[d.id]?.length ?? 0) > 0;
    const isSelected =
      selectedDetection?.name === d.name &&
      selectedDetection?.type_name === d.type_name &&
      selectedDetection?.file_type === d.file_type;
    const indent = 20 + depth * 16;
    return (
      <div key={nodeId}>
        <div
          className={`tree-row text-xs ${isSelected ? "bg-accent-blue/20 border-l-2 border-accent-blue" : ""}`}
          style={{ marginLeft: indent }}
          onClick={() => {
            onSelect(d);
            if (hasOptions || hasChildren) onToggle(nodeId);
          }}
          onContextMenu={(e) => {
            e.preventDefault();
            onContextMenu(e.clientX, e.clientY, d);
          }}
        >
          <span className="w-6 flex justify-center">
            {hasOptions || hasChildren ? (
              nodeExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />
            ) : (
              <div className="w-3" />
            )}
          </span>
          <span className="flex-1" title={`${heuristicPrefix(d)}${d.name}${partInfo(d)}`}>
            <span className="text-fg-secondary">{d.type_name}: </span>
            {d.is_a_heuristic && <span className="text-orange-400 font-medium">(A-Heur) </span>}
            {d.is_heuristic && !d.is_a_heuristic && <span className="text-yellow-400 font-medium">(Heur) </span>}
            <span className="text-fg-primary">{d.name}</span>
            {d.file_part && <span className="text-fg-muted text-[10px] ml-1">[{d.file_part}]</span>}
            {d.offset != null && (
              <span className="text-fg-muted text-[10px] ml-1">@0x{d.offset.toString(16)}</span>
            )}
          </span>
          <span className="w-20 text-center text-fg-muted">{d.type_name}</span>
          <span className="w-24 text-fg-secondary">{d.version ?? ""}</span>
          <span className="w-32 text-fg-muted truncate" title={d.options ?? ""}>
            {d.options ?? ""}
          </span>
        </div>
        {nodeExpanded && hasOptions && (
          <div className="tree-children mono text-xs text-fg-secondary">
            {d.options!.split(",").map((opt, oi) => (
              <div key={oi} className="tree-row">
                <span className="w-6" />
                <span className="flex-1">{opt.trim()}</span>
              </div>
            ))}
          </div>
        )}
        {nodeExpanded && hasChildren && (
          <div className="tree-children">
            {childrenMap[d.id!].map((child, ci) => renderDetection(child, ci, nodeId, depth + 1))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="selectable p-1">
      {/* Header row */}
      <div
        className="flex items-center gap-2 px-2 py-1 text-xs font-medium text-fg-secondary border-b border-border-c"
      >
        <span className="w-6" />
        <span className="flex-1">String</span>
        <span className="w-20 text-center">Type</span>
        <span className="w-24">Version</span>
        <span className="w-32">Options</span>
      </div>

      {/* Tree rows */}
      {groupEntries.map(([fileType, dets], gi) => {
        const groupId = `group-${gi}`;
        const expanded = expandedNodes.has(groupId);
        // Filter out detections that have a parent_id — they are rendered as
        // children of their parent, not at the top level.
        const topLevelDets = dets.filter((d) => !d.parent_id);
        return (
          <div key={groupId}>
            <div
              className="tree-row text-xs"
              onClick={() => onToggle(groupId)}
            >
              <span className="w-6 flex justify-center">
                {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </span>
              <span className="flex-1 font-medium text-accent-blue">{fileType}</span>
              <span className="w-20 text-center text-fg-muted">({dets.length})</span>
              <span className="w-24" />
              <span className="w-32" />
            </div>
            {expanded &&
              topLevelDets.map((d, di) => renderDetection(d, di, groupId, 0))}
          </div>
        );
      })}

      {/* Structured Diagnostics */}
      {result.structured_diagnostics && result.structured_diagnostics.length > 0 ? (
        <details className="mt-3 mx-2">
          <summary className="cursor-pointer text-xs text-accent-yellow flex items-center gap-1">
            <AlertCircle size={12} /> {t("scan.diagnostics")} ({result.structured_diagnostics.length})
          </summary>
          <div className="mt-1 rounded overflow-y-auto" style={{ maxHeight: "200px", overflowY: "auto" }}>
            <table className="w-full mono text-xs">
              <thead className="sticky top-0 bg-bg-panel">
                <tr className="text-left text-fg-secondary border-b border-border-c">
                  <th className="py-1 px-2">{t("scan.file")}</th>
                  <th className="py-1 px-2">{t("scan.kind")}</th>
                  <th className="py-1 px-2">{t("scan.line")}</th>
                  <th className="py-1 px-2">{t("scan.message")}</th>
                </tr>
              </thead>
              <tbody>
                {result.structured_diagnostics.map((d, i) => (
                  <tr key={i} className="border-b border-border-c">
                    <td className="py-0.5 px-2 text-fg-muted truncate" style={{ maxWidth: "200px" }}>{d.file}</td>
                    <td className={`py-0.5 px-2 ${d.kind === "error" ? "text-red-400" : "text-yellow-400"}`}>{d.kind}</td>
                    <td className="py-0.5 px-2 text-fg-muted">{d.line ?? "-"}</td>
                    <td className="py-0.5 px-2 text-fg-secondary">{d.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      ) : result.diagnostics.length > 0 && (
        <details className="mt-3 mx-2">
          <summary className="cursor-pointer text-xs text-accent-yellow flex items-center gap-1">
            <AlertCircle size={12} /> {t("scan.diagnostics")} ({result.diagnostics.length})
          </summary>
          <pre
            className="mt-1 p-2 rounded mono text-xs text-fg-secondary overflow-x-auto"
            style={{ background: "rgb(var(--bg-input))" }}
          >
            {result.diagnostics.join("\n")}
          </pre>
        </details>
      )}

      {/* Profiling data */}
      {result.profiling && result.profiling.length > 0 && (
        <details className="mt-1 mx-2">
          <summary className="cursor-pointer text-xs text-fg-muted flex items-center gap-1">
            <Clock size={12} /> {t("scan.profiling")} ({result.profiling.length})
          </summary>
          <div className="mt-1 rounded overflow-y-auto" style={{ maxHeight: "200px", overflowY: "auto" }}>
            <table className="w-full mono text-xs">
              <thead className="sticky top-0 bg-bg-panel">
                <tr className="text-left text-fg-secondary border-b border-border-c">
                  <th className="py-1 px-2">{t("scan.file")}</th>
                  <th className="py-1 px-2 text-right">{t("scan.elapsedMs")}</th>
                </tr>
              </thead>
              <tbody>
                {result.profiling.map((p, i) => (
                  <tr key={i} className="border-b border-border-c">
                    <td className="py-0.5 px-2 text-fg-muted truncate" style={{ maxWidth: "300px" }}>{p.file}</td>
                    <td className="py-0.5 px-2 text-right text-fg-secondary">{p.elapsed_ms}ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}

      {/* Scan log */}
      {result.scan_log && result.scan_log.length > 0 && (
        <details className="mt-1">
          <summary className="cursor-pointer text-xs text-fg-secondary hover:text-fg flex items-center gap-1">
            <FileText size={12} /> Scan Log ({result.scan_log.length})
          </summary>
          <div className="mt-1 border border-border-c rounded p-2 bg-bg-secondary max-h-48 overflow-auto">
            <pre className="text-[10px] text-fg-muted whitespace-pre-wrap font-mono">
              {result.scan_log.join("\n")}
            </pre>
          </div>
        </details>
      )}
    </div>
  );
}

/** Directory scan results — compact list view. */
function DirectoryResultsView({ results }: { results: ScanResultDto[] }) {
  const { t } = useTranslation();
  return (
    <div className="p-2 space-y-1 selectable">
      <div className="text-xs font-medium text-fg-secondary mb-2">
        Directory Results ({results.length} files)
      </div>
      {results.map((r, i) => {
        const fileName = r.path.split(/[\\/]/).pop() || r.path;
        return (
          <div
            key={i}
            className="panel p-2"
          >
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="mono text-fg-primary">{fileName}</span>
              <div className="flex items-center gap-2 text-fg-muted">
                <span className="flex items-center gap-1">
                  <CheckCircle2 size={11} className="text-accent-green" />
                  {r.detections.length}
                </span>
                <span className="flex items-center gap-1">
                  <Clock size={11} />
                  {r.scan_time_ms} ms
                </span>
              </div>
            </div>
            {r.detections.length > 0 && (
              <div className="text-xs text-fg-secondary ml-2">
                {r.detections.slice(0, 5).map((d, j) => (
                  <span key={j}>
                    {j > 0 && ", "}
                    <span className="text-accent-blue">{d.type_name}</span>: {d.name}
                  </span>
                ))}
                {r.detections.length > 5 && (
                  <span className="text-fg-muted"> +{r.detections.length - 5} {t("scan.more")}</span>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/** Advanced mode: signature source code panel for the selected detection. */
function SignatureSourcePanel({ detection }: { detection: ScanDetectionDto }) {
  const { t } = useTranslation();
  const [source, setSource] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!detection.signature_path) {
      setSource(null);
      setError(t("sigSource.noPath"));
      return;
    }
    setLoading(true);
    setError(null);
    invoke<{ source: string; file_path: string }>("get_signature_source", {
      fileType: detection.file_type,
      name: detection.signature_path.split("/").pop() ?? detection.signature_path,
    })
      .then((res) => setSource(res.source))
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [detection]);

  // Build extra info rows from detection metadata.
  const extraInfoRows: [string, string][] = [];
  if (detection.version) extraInfoRows.push(["Version", detection.version]);
  if (detection.options) extraInfoRows.push(["Options", detection.options]);
  if (detection.offset != null) extraInfoRows.push(["Offset", `0x${detection.offset.toString(16)}`]);
  if (detection.size != null) extraInfoRows.push(["Size", String(detection.size)]);
  if (detection.file_part) extraInfoRows.push(["File Part", detection.file_part]);
  if (detection.is_heuristic) extraInfoRows.push(["Heuristic", "Yes"]);
  if (detection.is_a_heuristic) extraInfoRows.push(["A-Heuristic", "Yes"]);
  if (detection.original_name) extraInfoRows.push(["Original Name", detection.original_name]);
  if (detection.id) extraInfoRows.push(["ID", detection.id]);
  if (detection.parent_id) extraInfoRows.push(["Parent ID", detection.parent_id]);

  return (
    <div className="flex flex-col h-full" style={{ background: "rgb(var(--bg-panel))" }}>
      {/* Panel header */}
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-border-c flex-shrink-0">
        <div className="flex items-center gap-2 text-xs">
          <Code2 size={13} className="text-accent-blue" />
          <span className="font-medium text-fg-primary">Signature Source</span>
          <span className="text-fg-muted">
            {detection.file_type} / {detection.name}
          </span>
        </div>
        {detection.signature_path && (
          <span className="text-xs text-fg-muted mono selectable">{detection.signature_path}</span>
        )}
      </div>

      {/* Extra info bar */}
      {extraInfoRows.length > 0 && (
        <div className="flex items-center gap-3 px-3 py-1 border-b border-border-c text-xs text-fg-muted flex-wrap">
          {extraInfoRows.map(([k, v], i) => (
            <span key={i}>{k}: <span className="text-fg-secondary font-mono">{v}</span></span>
          ))}
        </div>
      )}

      {/* Source content with syntax highlighting */}
      <div className="flex-1 overflow-auto">
        {loading && (
          <div className="flex items-center justify-center h-full text-xs text-fg-secondary">
            <div className="w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin mr-2" />
            Loading signature source...
          </div>
        )}
        {error && !loading && (
          <div className="p-3 text-xs text-accent-yellow selectable">{error}</div>
        )}
        {source && !loading && (
          <SignatureHighlighter source={source} />
        )}
      </div>
    </div>
  );
}

/** Advanced mode toolbar with Type and Flags dropdowns.
 *  Mirrors upstream DIEWidgetAdvanced's comboBoxType + comboBoxFlags. */
function AdvancedToolbar({
  flags,
  onFlagsChange,
}: {
  flags: ScanFlagsDto;
  onFlagsChange: (f: ScanFlagsDto) => void;
}) {
  const { t } = useTranslation();
  // Preset flag combinations matching upstream comboBoxFlags items.
  const flagPresets: { labelKey: string; apply: Partial<ScanFlagsDto> }[] = [
    { labelKey: "advancedToolbar.default", apply: {} },
    { labelKey: "advancedToolbar.deep", apply: { deep: true, heuristic: false, aggressive: false } },
    { labelKey: "advancedToolbar.heuristic", apply: { deep: false, heuristic: true, aggressive: false } },
    { labelKey: "advancedToolbar.aggressive", apply: { deep: true, heuristic: true, aggressive: true } },
    { labelKey: "advancedToolbar.allTypes", apply: { alltypes: true } },
  ];

  // File type options matching upstream comboBoxType.
  const typeOptions = [
    { key: "advancedToolbar.auto", value: "Auto" },
    { value: "PE" },
    { value: "ELF" },
    { value: "Mach-O" },
    { value: "Archive" },
    { value: "Image" },
    { value: "Text" },
  ];

  return (
    <div
      className="flex items-center gap-2 px-3 py-1 border-b border-border-c text-xs"
      style={{ background: "rgb(var(--bg-panel))" }}
    >
      <span className="text-fg-muted">{t("advancedToolbar.type")}</span>
      <select
        className="input py-0.5 px-1.5"
        value={flags.file_type ?? "Auto"}
        onChange={(e) => onFlagsChange({ ...flags, file_type: e.target.value })}
        style={{ width: "90px" }}
      >
        {typeOptions.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.key ? t(opt.key) : opt.value}
          </option>
        ))}
      </select>

      <div className="w-px h-3 bg-border-c" />

      <span className="text-fg-muted">{t("advancedToolbar.flags")}</span>
      <select
        className="input py-0.5 px-1.5"
        defaultValue={t("advancedToolbar.default")}
        style={{ width: "100px" }}
        onChange={(e) => {
          const preset = flagPresets.find((p) => t(p.labelKey) === e.target.value);
          if (preset) onFlagsChange({ ...flags, ...preset.apply });
        }}
      >
        {flagPresets.map((p) => (
          <option key={p.labelKey} value={t(p.labelKey)}>{t(p.labelKey)}</option>
        ))}
      </select>

      <div className="w-px h-3 bg-border-c" />

      {/* Quick flag toggles */}
      <label className="flex items-center gap-1 cursor-pointer hover:text-fg-primary">
        <input
          type="checkbox"
          checked={flags.deep}
          onChange={(e) => onFlagsChange({ ...flags, deep: e.target.checked })}
          className="accent-blue-500"
        />
        {t("advancedToolbar.deep")}
      </label>
      <label className="flex items-center gap-1 cursor-pointer hover:text-fg-primary">
        <input
          type="checkbox"
          checked={flags.heuristic}
          onChange={(e) => onFlagsChange({ ...flags, heuristic: e.target.checked })}
          className="accent-blue-500"
        />
        {t("advancedToolbar.heuristic")}
      </label>
      <label className="flex items-center gap-1 cursor-pointer hover:text-fg-primary">
        <input
          type="checkbox"
          checked={flags.alltypes}
          onChange={(e) => onFlagsChange({ ...flags, alltypes: e.target.checked })}
          className="accent-blue-500"
        />
        {t("advancedToolbar.allTypes")}
      </label>
      <label className="flex items-center gap-1 cursor-pointer hover:text-fg-primary">
        <input
          type="checkbox"
          checked={flags.no_dedup}
          onChange={(e) => onFlagsChange({ ...flags, no_dedup: e.target.checked })}
          className="accent-blue-500"
        />
        {t("advancedToolbar.noDedup")}
      </label>
    </div>
  );
}
