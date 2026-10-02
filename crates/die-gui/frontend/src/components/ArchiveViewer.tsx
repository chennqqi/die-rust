import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { Archive, AlertCircle, FileText, ChevronRight, ChevronDown, Download } from "lucide-react";

interface ArchiveEntry {
  name: string;
  size: number;
  compressed_size: number;
  is_directory: boolean;
  modified: string | null;
}

interface ArchiveResult {
  entries: ArchiveEntry[];
  format: string;
  total_entries: number;
}

/** Archive viewer — displays contents of archive files (ZIP, RAR, 7Z, TAR, etc.).
 *  Mirrors upstream XArchive widget showing file list with sizes. */
export function ArchiveViewer({ filePath }: { filePath: string }) {
  const { t } = useTranslation();
  const [result, setResult] = useState<ArchiveResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedDirs, setExpandedDirs] = useState<Set<string>>(new Set());
  const [extractMsg, setExtractMsg] = useState<string | null>(null);

  // Extract one member via `extract_archive_member` (ZIP/7Z/RAR).
  const extractMember = async (name: string) => {
    if (!filePath) return;
    const outputDir = await openDialog({
      directory: true,
      multiple: false,
      title: "Select output directory",
    });
    if (!outputDir || typeof outputDir !== "string") return;
    setExtractMsg(null);
    try {
      const out = await invoke<string>("extract_archive_member", {
        path: filePath,
        memberName: name,
        outputDir,
      });
      setExtractMsg(out);
    } catch (e) {
      setExtractMsg(String(e));
    }
  };

  useEffect(() => {
    if (!filePath) {
      setResult(null);
      return;
    }
    setLoading(true);
    setError(null);
    invoke<ArchiveResult>("list_archive", { path: filePath })
      .then((res) => setResult(res))
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [filePath]);

  const toggleDir = (path: string) => {
    setExpandedDirs((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const formatSize = (bytes: number): string => {
    if (bytes === 0) return "-";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  };

  if (!filePath) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-fg-muted">
        <Archive size={48} className="mb-3 opacity-40" />
        <p className="text-sm">{t("archive.openArchive")}</p>
        <p className="text-xs mt-1">{t("archive.supports")}</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-fg-secondary">
        <div className="w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin mr-2" />
        Reading archive...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 p-3 text-xs text-accent-red">
        <AlertCircle size={14} />
        {error}
      </div>
    );
  }

  if (!result || result.entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-fg-muted">
        <Archive size={48} className="mb-3 opacity-40" />
        <p className="text-sm">{t("archive.noEntries")}</p>
        <p className="text-xs mt-1">{t("archive.noEntriesHint")}</p>
      </div>
    );
  }

  // Build a tree from flat entry list.
  const tree = buildTree(result.entries);

  return (
    <div className="p-3 overflow-auto h-full">
      <div className="flex items-center gap-2 mb-3">
        <Archive size={16} className="text-accent-blue" />
        <h3 className="text-sm font-medium">{t("archive.title")}</h3>
        <span className="text-xs text-fg-muted">
          {result.format} — {result.total_entries} {t("archive.entries")}
        </span>
      </div>

      <table className="w-full text-xs selectable">
        <thead>
          <tr className="text-fg-muted border-b border-border-c">
            <th className="text-left py-1 px-2">{t("archive.name")}</th>
            <th className="text-right py-1 px-2">{t("archive.size")}</th>
            <th className="text-right py-1 px-2">{t("archive.compressed")}</th>
            <th className="text-left py-1 px-2">{t("archive.modified")}</th>
          </tr>
        </thead>
        <tbody>
          {renderTree(tree, "", expandedDirs, toggleDir, formatSize, extractMember, 0)}
        </tbody>
      </table>
      {extractMsg && (
        <p className="text-xs text-fg-muted mt-2 break-all">{extractMsg}</p>
      )}
    </div>
  );
}

interface TreeNode {
  name: string;
  isDir: boolean;
  size: number;
  compressed: number;
  modified: string | null;
  children: Map<string, TreeNode>;
}

function buildTree(entries: ArchiveEntry[]): TreeNode {
  const root: TreeNode = {
    name: "",
    isDir: true,
    size: 0,
    compressed: 0,
    modified: null,
    children: new Map(),
  };

  for (const entry of entries) {
    const parts = entry.name.split("/").filter(Boolean);
    let node = root;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isLast = i === parts.length - 1;
      if (!node.children.has(part)) {
        node.children.set(part, {
          name: part,
          isDir: !isLast || entry.is_directory,
          size: isLast ? entry.size : 0,
          compressed: isLast ? entry.compressed_size : 0,
          modified: isLast ? entry.modified : null,
          children: new Map(),
        });
      }
      node = node.children.get(part)!;
    }
  }

  return root;
}

function renderTree(
  node: TreeNode,
  prefix: string,
  expandedDirs: Set<string>,
  toggleDir: (path: string) => void,
  formatSize: (n: number) => string,
  onExtract: (name: string) => void,
  depth: number,
): React.ReactNode[] {
  const result: React.ReactNode[] = [];
  const entries = Array.from(node.children.values()).sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  for (const child of entries) {
    const fullPath = prefix ? `${prefix}/${child.name}` : child.name;
    const isExpanded = expandedDirs.has(fullPath);

    result.push(
      <tr key={fullPath} className="border-b border-border-c/50 hover:bg-hover">
        <td className="py-1 px-2" style={{ paddingLeft: `${8 + depth * 16}px` }}>
          {child.isDir ? (
            <button
              onClick={() => toggleDir(fullPath)}
              className="flex items-center gap-1 text-fg-primary"
            >
              {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              <span className="font-medium">{child.name}/</span>
            </button>
          ) : (
            <span className="flex items-center gap-1 text-fg-secondary">
              <FileText size={12} className="text-fg-muted" />
              {child.name}
              <button
                onClick={() => onExtract(fullPath)}
                className="text-fg-muted hover:text-accent-blue"
                title="Extract member"
              >
                <Download size={11} />
              </button>
            </span>
          )}
        </td>
        <td className="py-1 px-2 text-right mono text-fg-muted">
          {child.isDir ? "" : formatSize(child.size)}
        </td>
        <td className="py-1 px-2 text-right mono text-fg-muted">
          {child.isDir ? "" : formatSize(child.compressed)}
        </td>
        <td className="py-1 px-2 text-fg-muted">
          {child.modified ?? ""}
        </td>
      </tr>,
    );

    if (child.isDir && isExpanded) {
      result.push(
        ...renderTree(child, fullPath, expandedDirs, toggleDir, formatSize, onExtract, depth + 1),
      );
    }
  }

  return result;
}
