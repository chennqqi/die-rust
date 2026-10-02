import { useState, useEffect, useCallback, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";
import { Search, ArrowRight, Copy, Check, Code, Bookmark, MessageSquare } from "lucide-react";
import {
  AnnotationsPanel,
  loadAnnotations,
  upsertAnnotation,
  type AnnotationsDto,
} from "./AnnotationsPanel";

interface HexLine {
  offset: string;
  hex: string;
  ascii: string;
}

interface HexDump {
  file_size: number;
  start_offset: number;
  lines: HexLine[];
}

interface SearchHit {
  offset: number;
}

interface SearchResult {
  file_size: number;
  hits: SearchHit[];
}

const LINE_BYTES = 16;
const LINE_HEIGHT = 20;
const VISIBLE_LINES = 30;
const CHUNK_BYTES = LINE_BYTES * VISIBLE_LINES; // 480 bytes per chunk

export function HexViewer({
  path,
  initialOffset,
  onFollowInDisasm,
}: {
  path: string;
  initialOffset?: number | null;
  onFollowInDisasm?: (offset: number) => void;
}) {
  const { t } = useTranslation();
  const [fileSize, setFileSize] = useState(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [chunks, setChunks] = useState<Map<number, HexLine[]>>(new Map());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchPattern, setSearchPattern] = useState("");
  const [searchResults, setSearchResults] = useState<SearchHit[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [jumpOffset, setJumpOffset] = useState("");
  const [copied, setCopied] = useState(false);
  const [selectedLine, setSelectedLine] = useState<number | null>(null);
  const [elementMode, setElementMode] = useState<"byte" | "word" | "dword" | "qword">("byte");
  const [selectedByteOffset, setSelectedByteOffset] = useState<number | null>(null);
  const [inspectorBytes, setInspectorBytes] = useState<Uint8Array>(new Uint8Array(0));
  const [editMsg, setEditMsg] = useState<string | null>(null);
  const [annotations, setAnnotations] = useState<AnnotationsDto | null>(null);

  // Annotated offsets for row markers (bookmarks + comments).
  const annotatedOffsets = useMemo(() => {
    const s = new Set<number>();
    annotations?.bookmarks.forEach((e) => s.add(e.offset));
    annotations?.comments.forEach((e) => s.add(e.offset));
    return s;
  }, [annotations]);

  /** Scroll the view to `offset` (annotation jump target). */
  const scrollToOffset = useCallback(
    (offset: number) => {
      if (offset < 0 || offset >= fileSize) return;
      const lineIndex = Math.floor(offset / LINE_BYTES);
      setScrollTop(lineIndex * LINE_HEIGHT);
      setSelectedLine(lineIndex);
      setSelectedByteOffset(offset);
    },
    [fileSize],
  );

  /** Add a bookmark/comment at the selected byte via a prompt. */
  const addAnnotation = useCallback(
    async (kind: "bookmark" | "comment") => {
      if (selectedByteOffset == null) return;
      const input = window.prompt(
        kind === "bookmark"
          ? `Bookmark name at 0x${selectedByteOffset.toString(16)}`
          : `Comment at 0x${selectedByteOffset.toString(16)}`,
      );
      if (input == null || input.trim() === "") return;
      try {
        setAnnotations(await upsertAnnotation(path, kind, selectedByteOffset, input.trim()));
        setEditMsg(null);
      } catch (e) {
        setEditMsg(String(e));
      }
    },
    [path, selectedByteOffset],
  );

  // Byte edit entry: prompt for hex bytes, write via backend (creates .bak),
  // then drop cached chunks so the view reloads fresh bytes.
  const editAtSelection = useCallback(async () => {
    if (selectedByteOffset == null) return;
    const input = window.prompt(
      `Enter hex bytes to write at 0x${selectedByteOffset.toString(16)} (e.g. "90 90 CC")`,
    );
    if (input == null) return;
    const cleaned = input.replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "");
    if (cleaned.length === 0 || cleaned.length % 2 !== 0) {
      setEditMsg("Invalid hex input");
      return;
    }
    const bytes: number[] = [];
    for (let i = 0; i < cleaned.length; i += 2) {
      bytes.push(parseInt(cleaned.slice(i, i + 2), 16));
    }
    try {
      await invoke("edit_bytes_at_offset", { path, offset: selectedByteOffset, bytes });
      setChunks(new Map());
      setEditMsg(`Wrote ${bytes.length} byte(s) at 0x${selectedByteOffset.toString(16)}`);
    } catch (e) {
      setEditMsg(String(e));
    }
  }, [path, selectedByteOffset]);

  // Total number of lines in the file (for virtual scroll height).
  const totalLines = useMemo(() => Math.ceil(fileSize / LINE_BYTES), [fileSize]);

  // First visible line index based on scroll position.
  const firstVisibleLine = Math.floor(scrollTop / LINE_HEIGHT);
  const visibleStart = Math.max(0, firstVisibleLine - 5);
  const visibleEnd = Math.min(totalLines, firstVisibleLine + VISIBLE_LINES + 5);

  // Load file size on path change.
  useEffect(() => {
    if (!path) return;
    setChunks(new Map());
    setScrollTop(0);
    setSearchResults(null);
    setSelectedLine(null);
    setLoading(true);
    setError(null);
    invoke<HexDump>("read_hex", { path, offset: 0, maxBytes: 16 })
      .then((d) => {
        setFileSize(d.file_size);
        setLoading(false);
      })
      .catch((e) => {
        setError(String(e));
        setLoading(false);
      });
    setAnnotations(null);
    loadAnnotations(path).then(setAnnotations).catch(() => setAnnotations(null));
  }, [path]);

  // Scroll to initialOffset when it changes (e.g. from Disassembler "Follow in Hex").
  useEffect(() => {
    if (initialOffset != null && fileSize > 0 && initialOffset < fileSize) {
      const lineIndex = Math.floor(initialOffset / LINE_BYTES);
      setScrollTop(lineIndex * LINE_HEIGHT);
      setSelectedLine(lineIndex);
    }
  }, [initialOffset, fileSize]);

  // Load visible chunks on demand.
  const loadChunk = useCallback(
    async (chunkIndex: number) => {
      if (!path || chunks.has(chunkIndex)) return;
      const offset = chunkIndex * CHUNK_BYTES;
      if (offset >= fileSize) return;
      try {
        const dump = await invoke<HexDump>("read_hex", {
          path,
          offset,
          maxBytes: CHUNK_BYTES,
        });
        setChunks((prev) => {
          const next = new Map(prev);
          next.set(chunkIndex, dump.lines);
          return next;
        });
      } catch (e) {
        setError(String(e));
      }
    },
    [path, chunks, fileSize],
  );

  // Load all visible chunks.
  useEffect(() => {
    if (!path || fileSize === 0) return;
    const startChunk = Math.floor(visibleStart / (CHUNK_BYTES / LINE_BYTES));
    const endChunk = Math.ceil(visibleEnd / (CHUNK_BYTES / LINE_BYTES));
    for (let c = startChunk; c <= endChunk; c++) {
      loadChunk(c);
    }
  }, [path, fileSize, visibleStart, visibleEnd, loadChunk]);

  // Clean up old chunks to save memory (keep only visible ± 10 chunks).
  useEffect(() => {
    if (chunks.size < 20) return;
    const startChunk = Math.floor(visibleStart / (CHUNK_BYTES / LINE_BYTES));
    const endChunk = Math.ceil(visibleEnd / (CHUNK_BYTES / LINE_BYTES));
    setChunks((prev) => {
      const next = new Map();
      for (let c = startChunk - 10; c <= endChunk + 10; c++) {
        if (prev.has(c)) next.set(c, prev.get(c)!);
      }
      return next;
    });
  }, [visibleStart, visibleEnd, chunks.size]);

  // Get a line from the chunk cache.
  function getLine(lineIndex: number): HexLine | null {
    const chunkIndex = Math.floor(lineIndex / (CHUNK_BYTES / LINE_BYTES));
    const lineInChunk = lineIndex % (CHUNK_BYTES / LINE_BYTES);
    const chunk = chunks.get(chunkIndex);
    if (!chunk || lineInChunk >= chunk.length) return null;
    return chunk[lineInChunk];
  }

  // Handle search.
  async function handleSearch() {
    if (!path || !searchPattern.trim()) return;
    setSearching(true);
    setError(null);
    try {
      const result = await invoke<SearchResult>("search_hex", {
        path,
        pattern: searchPattern,
        startOffset: 0,
        maxHits: 1000,
      });
      setSearchResults(result.hits);
    } catch (e) {
      setError(String(e));
    } finally {
      setSearching(false);
    }
  }

  // Handle jump to offset.
  function handleJump() {
    const off = jumpOffset.trim();
    if (!off) return;
    // Parse as hex (with or without 0x prefix) or decimal.
    const num = off.startsWith("0x") || off.startsWith("0X")
      ? parseInt(off.slice(2), 16)
      : /^[0-9a-fA-F]+$/.test(off) && off.length > 3
        ? parseInt(off, 16)
        : parseInt(off, 10);
    if (isNaN(num) || num < 0 || num >= fileSize) {
      setError(t("hex.invalidOffset"));
      return;
    }
    const lineIndex = Math.floor(num / LINE_BYTES);
    setScrollTop(lineIndex * LINE_HEIGHT);
    setSelectedLine(lineIndex);
    setError(null);
  }

  // Jump to a search hit.
  function jumpToHit(offset: number) {
    const lineIndex = Math.floor(offset / LINE_BYTES);
    setScrollTop(lineIndex * LINE_HEIGHT);
    setSelectedLine(lineIndex);
  }

  // Copy selected line to clipboard.
  async function copyLine(line: HexLine) {
    const text = `${line.offset}  ${line.hex}  ${line.ascii}`;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard not available.
    }
  }

  // Load bytes at a given offset for the data inspector (32 bytes).
  async function loadInspectorData(offset: number) {
    if (!path || offset >= fileSize) {
      setInspectorBytes(new Uint8Array(0));
      return;
    }
    const len = Math.min(32, fileSize - offset);
    try {
      const dump = await invoke<HexDump>("read_hex", { path, offset, maxBytes: len });
      // Parse the hex bytes from the lines.
      const bytes: number[] = [];
      for (const line of dump.lines) {
        for (const h of line.hex.split(" ")) {
          bytes.push(parseInt(h, 16));
        }
      }
      setInspectorBytes(new Uint8Array(bytes));
    } catch {
      setInspectorBytes(new Uint8Array(0));
    }
  }

  // Handle line click: select line, copy, and load inspector data.
  async function handleLineClick(lineIndex: number, line: HexLine) {
    setSelectedLine(lineIndex);
    const byteOffset = lineIndex * LINE_BYTES;
    setSelectedByteOffset(byteOffset);
    await copyLine(line);
    await loadInspectorData(byteOffset);
  }

  if (!path) return null;

  // Render visible lines.
  const renderedLines: React.ReactNode[] = [];
  for (let i = visibleStart; i < visibleEnd; i++) {
    const line = getLine(i);
    if (!line) {
      renderedLines.push(
        <div
          key={i}
          style={{ height: LINE_HEIGHT, lineHeight: `${LINE_HEIGHT}px` }}
          className="text-fg-muted"
        >
          {" ".repeat(8)}  {"—".repeat(47)}  {"—".repeat(16)}
        </div>,
      );
    } else {
      // Check if this line contains a search hit.
      const lineStartOffset = i * LINE_BYTES;
      const lineEndOffset = lineStartOffset + LINE_BYTES;
      const hasHit = searchResults?.some(
        (h) => h.offset >= lineStartOffset && h.offset < lineEndOffset,
      );
      const hasAnnotation = [...annotatedOffsets].some(
        (o) => o >= lineStartOffset && o < lineEndOffset,
      );
      renderedLines.push(
        <div
          key={i}
          style={{ height: LINE_HEIGHT, lineHeight: `${LINE_HEIGHT}px` }}
          className={`flex gap-2 cursor-pointer hover:bg-accent-blue/10 ${selectedLine === i ? "bg-accent-blue/20" : ""} ${hasHit ? "bg-yellow-500/20" : ""}`}
          onClick={() => handleLineClick(i, line)}
        >
          <span className="text-fg-muted w-24">
            {hasAnnotation && <span className="text-accent-blue">● </span>}
            {line.offset}
          </span>
          <span className="text-fg-primary w-[360px]">{formatHexByMode(line.hex, elementMode)}</span>
          <span className="text-fg-muted">{line.ascii}</span>
        </div>,
      );
    }
  }

  return (
    <div className="border border-border rounded p-3 mt-3">
      {/* Toolbar */}
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <h3 className="text-sm font-medium">{t("hex.title")}</h3>
        <span className="text-xs text-fg-muted">
          {fileSize > 0 && `${fileSize.toLocaleString()} bytes`}
        </span>
        <div className="flex-1" />

        {/* Search */}
        <div className="flex items-center gap-1">
          <Search size={12} className="text-fg-muted" />
          <input
            type="text"
            value={searchPattern}
            onChange={(e) => setSearchPattern(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder={t("hex.searchPlaceholder")}
            className="input py-0.5 px-2 text-xs"
            style={{ width: "160px" }}
          />
          <button
            onClick={handleSearch}
            disabled={searching || !searchPattern.trim()}
            className="px-2 py-0.5 text-xs border border-border rounded disabled:opacity-50"
          >
            {searching ? "..." : t("hex.search")}
          </button>
        </div>

        {/* Jump */}
        <div className="flex items-center gap-1">
          <ArrowRight size={12} className="text-fg-muted" />
          <input
            type="text"
            value={jumpOffset}
            onChange={(e) => setJumpOffset(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleJump()}
            placeholder="0x00000000"
            className="input py-0.5 px-2 text-xs"
            style={{ width: "100px" }}
          />
          <button
            onClick={handleJump}
            className="px-2 py-0.5 text-xs border border-border rounded"
          >
            {t("hex.jump")}
          </button>
        </div>

        {/* Copy indicator */}
        {copied && (
          <span className="text-xs text-green-500 flex items-center gap-1">
            <Check size={12} /> {t("hex.copied")}
          </span>
        )}

        {/* Element mode selector */}
        <select
          value={elementMode}
          onChange={(e) => setElementMode(e.target.value as "byte" | "word" | "dword" | "qword")}
          className="text-xs border border-border rounded px-1 py-0.5"
          title={t("hex.elementMode")}
        >
          <option value="byte">Byte</option>
          <option value="word">Word (16-bit)</option>
          <option value="dword">DWord (32-bit)</option>
          <option value="qword">QWord (64-bit)</option>
        </select>
      </div>

      {/* Search results */}
      {searchResults && (
        <div className="mb-2 text-xs text-fg-muted">
          {searchResults.length > 0 ? (
            <span>
              {searchResults.length} {t("hex.hits")}{" "}
              <select
                className="input py-0 px-1 ml-1"
                onChange={(e) => {
                  if (e.target.value) jumpToHit(parseInt(e.target.value, 10));
                }}
                defaultValue=""
              >
                <option value="">{t("hex.jumpToHit")}</option>
                {searchResults.slice(0, 50).map((h, i) => (
                  <option key={i} value={h.offset}>
                    0x{h.offset.toString(16).toUpperCase()}
                  </option>
                ))}
              </select>
            </span>
          ) : (
            <span>{t("hex.noHits")}</span>
          )}
        </div>
      )}

      {error && <div className="text-xs text-red-600 mb-2">{error}</div>}
      {loading && <div className="text-xs text-fg-muted mb-2">{t("hex.loading")}</div>}

      {/* Virtual scroll hex dump */}
      <div
        className="mono text-xs bg-muted/30 rounded overflow-y-auto"
        style={{ height: VISIBLE_LINES * LINE_HEIGHT + 20, overflowY: "auto" }}
        onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
      >
        {/* Spacer for virtual scrolling */}
        <div style={{ height: visibleStart * LINE_HEIGHT }} />
        {renderedLines}
        <div style={{ height: (totalLines - visibleEnd) * LINE_HEIGHT }} />
      </div>

      {/* Status bar */}
      <div className="flex items-center gap-3 mt-1 text-xs text-fg-muted">
        <span>
          {t("hex.offset")}: 0x{Math.floor(scrollTop / LINE_HEIGHT * LINE_BYTES).toString(16).toUpperCase()}
        </span>
        <Copy size={10} />
        <span>{t("hex.clickToCopy")}</span>
        {editMsg && <span className="text-accent-yellow">{editMsg}</span>}
        {selectedByteOffset != null && (
          <>
            <button
              onClick={() => addAnnotation("bookmark")}
              className="ml-auto flex items-center gap-1 px-2 py-0.5 text-xs border border-border rounded hover:bg-hover"
              title={t("ann.addBookmark")}
            >
              <Bookmark size={11} />
            </button>
            <button
              onClick={() => addAnnotation("comment")}
              className="flex items-center gap-1 px-2 py-0.5 text-xs border border-border rounded hover:bg-hover"
              title={t("ann.addComment")}
            >
              <MessageSquare size={11} />
            </button>
            <button
              onClick={editAtSelection}
              className="flex items-center gap-1 px-2 py-0.5 text-xs border border-border rounded hover:bg-hover"
            >
              Edit
            </button>
          </>
        )}
        {selectedByteOffset != null && onFollowInDisasm && (
          <button
            onClick={() => onFollowInDisasm(selectedByteOffset)}
            className="flex items-center gap-1 px-2 py-0.5 text-xs border border-border rounded hover:bg-hover"
          >
            <Code size={11} />
            {t("hex.followInDisasm")}
          </button>
        )}
      </div>

      {/* Annotations (XInfoDB parity) */}
      <AnnotationsPanel
        path={path}
        annotations={annotations}
        onChanged={setAnnotations}
        onJump={scrollToOffset}
      />

      {/* Data inspector — shows multiple interpretations of selected bytes */}
      {selectedByteOffset != null && inspectorBytes.length > 0 && (
        <div className="mt-2 border border-border rounded p-2 text-xs">
          <div className="text-fg-secondary font-medium mb-1">
            {t("hex.inspector")} @ 0x{selectedByteOffset.toString(16).toUpperCase()}
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 mono">
            <InspectorRow label="uint8" value={inspectorBytes[0]?.toString() ?? "-"} />
            <InspectorRow
              label="int8"
              value={
                inspectorBytes[0] != null
                  ? (inspectorBytes[0] > 127 ? inspectorBytes[0] - 256 : inspectorBytes[0]).toString()
                  : "-"
              }
            />
            <InspectorRow
              label="uint16 LE"
              value={
                inspectorBytes.length >= 2
                  ? "0x" + (inspectorBytes[0] | (inspectorBytes[1] << 8)).toString(16).toUpperCase()
                  : "-"
              }
            />
            <InspectorRow
              label="uint16 BE"
              value={
                inspectorBytes.length >= 2
                  ? "0x" + ((inspectorBytes[0] << 8) | inspectorBytes[1]).toString(16).toUpperCase()
                  : "-"
              }
            />
            <InspectorRow
              label="uint32 LE"
              value={
                inspectorBytes.length >= 4
                  ? "0x" + readUint32LE(inspectorBytes).toString(16).toUpperCase()
                  : "-"
              }
            />
            <InspectorRow
              label="uint32 BE"
              value={
                inspectorBytes.length >= 4
                  ? "0x" + readUint32BE(inspectorBytes).toString(16).toUpperCase()
                  : "-"
              }
            />
            <InspectorRow
              label="uint64 LE"
              value={
                inspectorBytes.length >= 8
                  ? "0x" + readUint64LE(inspectorBytes).toString(16).toUpperCase()
                  : "-"
              }
            />
            <InspectorRow
              label="uint64 BE"
              value={
                inspectorBytes.length >= 8
                  ? "0x" + readUint64BE(inspectorBytes).toString(16).toUpperCase()
                  : "-"
              }
            />
            <InspectorRow
              label="float32 LE"
              value={
                inspectorBytes.length >= 4
                  ? readFloat32LE(inspectorBytes).toFixed(6)
                  : "-"
              }
            />
            <InspectorRow
              label="float64 LE"
              value={
                inspectorBytes.length >= 8
                  ? readFloat64LE(inspectorBytes).toFixed(6)
                  : "-"
              }
            />
            <InspectorRow
              label="ASCII"
              value={
                Array.from(inspectorBytes.slice(0, 16))
                  .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
                  .join("")
              }
            />
          </div>
        </div>
      )}
    </div>
  );
}

/** Reformat space-separated hex bytes into grouped elements (word/dword/qword). */
function formatHexByMode(
  hexStr: string,
  mode: "byte" | "word" | "dword" | "qword",
): string {
  if (mode === "byte") return hexStr;
  const bytes = hexStr.split(" ");
  const groupSize = mode === "word" ? 2 : mode === "dword" ? 4 : 8;
  const groups: string[] = [];
  for (let i = 0; i < bytes.length; i += groupSize) {
    const group = bytes.slice(i, i + groupSize);
    // Reverse for little-endian display within each group.
    groups.push(group.reverse().join(""));
  }
  return groups.join(" ");
}

/** Inspector row: label + value. */
function InspectorRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-fg-muted w-20">{label}</span>
      <span className="text-fg-primary">{value}</span>
    </div>
  );
}

/** Read a little-endian uint32 from a Uint8Array. */
function readUint32LE(bytes: Uint8Array): number {
  return (
    bytes[0] |
    (bytes[1] << 8) |
    (bytes[2] << 16) |
    (bytes[3] << 24)
  ) >>> 0;
}

/** Read a big-endian uint32 from a Uint8Array. */
function readUint32BE(bytes: Uint8Array): number {
  return (
    (bytes[0] << 24) |
    (bytes[1] << 16) |
    (bytes[2] << 8) |
    bytes[3]
  ) >>> 0;
}

/** Read a little-endian uint64 from a Uint8Array (as BigInt). */
function readUint64LE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 7; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/** Read a big-endian uint64 from a Uint8Array (as BigInt). */
function readUint64BE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < 8; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/** Read a little-endian float32 from a Uint8Array. */
function readFloat32LE(bytes: Uint8Array): number {
  const buf = new ArrayBuffer(4);
  const view = new DataView(buf);
  for (let i = 0; i < 4; i++) view.setUint8(i, bytes[i]);
  return view.getFloat32(0, true);
}

/** Read a little-endian float64 from a Uint8Array. */
function readFloat64LE(bytes: Uint8Array): number {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  for (let i = 0; i < 8; i++) view.setUint8(i, bytes[i]);
  return view.getFloat64(0, true);
}
