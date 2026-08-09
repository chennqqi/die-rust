import { useState, useCallback, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { save } from '@tauri-apps/plugin-dialog';

interface StringEntry {
  offset: number;
  text: string;
  encoding: 'ascii' | 'utf16_le';
}

type MapMode = 'file' | 'virtual' | 'physical';
type FileType = 'auto' | 'pe' | 'elf' | 'macho' | 'dex' | 'raw';

interface StringExtractParams {
  min_length: number;
  extract_ascii: boolean;
  extract_utf16: boolean;
  filter: string | null;
  max_results: number;
  null_terminated_only: boolean;
  filter_mode: 'substring' | 'regexp' | 'links';
  map_mode: MapMode;
  file_type: FileType;
}

interface StringExtractorProps {
  filePath: string | null;
  onHexJump?: (offset: number) => void;
  onDisasmJump?: (offset: number) => void;
}

export default function StringExtractor({ filePath, onHexJump, onDisasmJump }: StringExtractorProps) {
  const [strings, setStrings] = useState<StringEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [minLength, setMinLength] = useState(5);
  const [extractAscii, setExtractAscii] = useState(true);
  const [extractUtf16, setExtractUtf16] = useState(true);
  const [filter, setFilter] = useState('');
  const [maxResults, setMaxResults] = useState(10000);
  const [nullTerminatedOnly, setNullTerminatedOnly] = useState(false);
  const [filterMode, setFilterMode] = useState<'substring' | 'regexp' | 'links'>('substring');
  const [mapMode, setMapMode] = useState<MapMode>('file');
  const [fileType, setFileType] = useState<FileType>('auto');
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; entry: StringEntry } | null>(null);
  const [editDialog, setEditDialog] = useState<{ entry: StringEntry; newValue: string } | null>(null);
  const [editStatus, setEditStatus] = useState<string | null>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);

  const fetchStrings = useCallback(async () => {
    if (!filePath) {
      setStrings([]);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const params: StringExtractParams = {
        min_length: minLength,
        extract_ascii: extractAscii,
        extract_utf16: extractUtf16,
        filter: filter || null,
        max_results: maxResults,
        null_terminated_only: nullTerminatedOnly,
        filter_mode: filterMode,
        map_mode: mapMode,
        file_type: fileType,
      };
      const result = await invoke<StringEntry[]>('extract_strings', {
        path: filePath,
        params,
      });
      setStrings(result);
    } catch (e) {
      setError(String(e));
      setStrings([]);
    } finally {
      setLoading(false);
    }
  }, [filePath, minLength, extractAscii, extractUtf16, filter, maxResults, nullTerminatedOnly, filterMode, mapMode, fileType]);

  // Auto-extract on file change.
  useEffect(() => {
    if (filePath) {
      fetchStrings();
    }
  }, [filePath]); // eslint-disable-line react-hooks/exhaustive-deps

  // Debounced filter search.
  useEffect(() => {
    if (!filePath) return;
    const timer = setTimeout(() => {
      fetchStrings();
    }, 300);
    return () => clearTimeout(timer);
  }, [filter, minLength, extractAscii, extractUtf16, maxResults, nullTerminatedOnly, filterMode, mapMode, fileType, fetchStrings]);

  // Close context menu on outside click.
  useEffect(() => {
    const handler = () => setContextMenu(null);
    if (contextMenu) {
      document.addEventListener('click', handler);
      return () => document.removeEventListener('click', handler);
    }
  }, [contextMenu]);

  const handleContextMenu = (e: React.MouseEvent, entry: StringEntry) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, entry });
  };

  const handleDemangle = async (entry: StringEntry) => {
    try {
      const result = await invoke<string>('demangle_symbol', { symbol: entry.text });
      alert(`Demangled: ${result}`);
    } catch {
      alert('Demangle failed or not available for this string.');
    }
  };

  const handleEditString = async () => {
    if (!editDialog || !filePath) return;
    setEditStatus('Saving...');
    try {
      const isUtf16 = editDialog.entry.encoding === 'utf16_le';
      await invoke('edit_string_at_offset', {
        path: filePath,
        offset: editDialog.entry.offset,
        newValue: editDialog.newValue,
        isUtf16,
      });
      setEditStatus('String edited successfully (.bak backup created).');
      setEditDialog(null);
      fetchStrings();
    } catch (e) {
      setEditStatus(`Error: ${e}`);
    }
  };

  const handleSaveResults = async () => {
    if (strings.length === 0) return;
    try {
      const savePath = await save({
        defaultPath: 'strings.csv',
        filters: [
          { name: 'CSV', extensions: ['csv'] },
          { name: 'JSON', extensions: ['json'] },
        ],
      });
      if (!savePath) return;
      let content: string;
      if (savePath.endsWith('.json')) {
        content = JSON.stringify(strings, null, 2);
      } else {
        content = 'Offset,Encoding,Text\n' + strings.map(s =>
          `0x${s.offset.toString(16)},${s.encoding},"${s.text.replace(/"/g, '""')}"`
        ).join('\n');
      }
      // Write file via Tauri FS or a command. Use invoke to write.
      await invoke('write_text_file', { path: savePath, content });
    } catch (e) {
      setError(`Save failed: ${e}`);
    }
  };

  if (!filePath) {
    return <div className="string-extractor empty">No file selected.</div>;
  }

  return (
    <div className="string-extractor">
      {/* Controls */}
      <div className="string-controls">
        <div className="string-control-group">
          <label>
            Min Length:
            <input
              type="number"
              min={1}
              max={256}
              value={minLength}
              onChange={(e) => setMinLength(parseInt(e.target.value) || 5)}
              style={{ width: '60px' }}
            />
          </label>
        </div>
        <div className="string-control-group">
          <label>
            <input
              type="checkbox"
              checked={extractAscii}
              onChange={(e) => setExtractAscii(e.target.checked)}
            />
            ASCII
          </label>
          <label>
            <input
              type="checkbox"
              checked={extractUtf16}
              onChange={(e) => setExtractUtf16(e.target.checked)}
            />
            UTF-16
          </label>
          <label>
            <input
              type="checkbox"
              checked={nullTerminatedOnly}
              onChange={(e) => setNullTerminatedOnly(e.target.checked)}
            />
            Null-terminated
          </label>
        </div>
        <div className="string-control-group">
          <label>
            Filter Mode:
            <select
              value={filterMode}
              onChange={(e) => setFilterMode(e.target.value as 'substring' | 'regexp' | 'links')}
              style={{ marginLeft: '4px' }}
            >
              <option value="substring">Substring</option>
              <option value="regexp">Regexp (wildcard)</option>
              <option value="links">Links only</option>
            </select>
          </label>
        </div>
        <div className="string-control-group">
          <label>
            Map Mode:
            <select
              value={mapMode}
              onChange={(e) => setMapMode(e.target.value as MapMode)}
              style={{ marginLeft: '4px' }}
            >
              <option value="file">File</option>
              <option value="virtual">Virtual</option>
              <option value="physical">Physical</option>
            </select>
          </label>
        </div>
        <div className="string-control-group">
          <label>
            File Type:
            <select
              value={fileType}
              onChange={(e) => setFileType(e.target.value as FileType)}
              style={{ marginLeft: '4px' }}
            >
              <option value="auto">Auto</option>
              <option value="pe">PE</option>
              <option value="elf">ELF</option>
              <option value="macho">Mach-O</option>
              <option value="dex">DEX</option>
              <option value="raw">Raw</option>
            </select>
          </label>
        </div>
        <div className="string-control-group">
          <label>
            Max Results:
            <input
              type="number"
              min={0}
              max={1000000}
              value={maxResults}
              onChange={(e) => setMaxResults(parseInt(e.target.value) || 0)}
              style={{ width: '80px' }}
            />
          </label>
        </div>
        <div className="string-control-group">
          <input
            type="text"
            placeholder={filterMode === 'links' ? 'Links mode (filter disabled)' : filterMode === 'regexp' ? 'Pattern (* and ? wildcards)...' : 'Filter (case-insensitive)...'}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ width: '200px' }}
            disabled={filterMode === 'links'}
          />
        </div>
        <button onClick={fetchStrings} disabled={loading}>
          {loading ? 'Extracting...' : 'Extract'}
        </button>
        <button onClick={handleSaveResults} disabled={loading || strings.length === 0}>
          Save
        </button>
      </div>

      {/* Stats */}
      <div className="string-stats">
        {loading ? (
          <span>Loading...</span>
        ) : (
          <span>{strings.length} strings found</span>
        )}
        {error && <span className="string-error">Error: {error}</span>}
        {editStatus && <span className="string-edit-status">{editStatus}</span>}
      </div>

      {/* Results table */}
      <div className="string-results">
        {!loading && strings.length > 0 && (
          <table className="string-table">
            <thead>
              <tr>
                <th>Offset</th>
                <th>Type</th>
                <th>String</th>
              </tr>
            </thead>
            <tbody>
              {strings.map((entry, i) => (
                <tr key={i} onContextMenu={(e) => handleContextMenu(e, entry)}>
                  <td className="string-offset">
                    0x{entry.offset.toString(16).padStart(8, '0')}
                  </td>
                  <td className="string-encoding">
                    {entry.encoding === 'ascii' ? 'ASCII' : 'UTF-16'}
                  </td>
                  <td className="string-text">{entry.text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!loading && strings.length === 0 && !error && (
          <div className="string-empty">No strings found.</div>
        )}
      </div>

      {/* Context menu */}
      {contextMenu && (
        <div
          ref={contextMenuRef}
          className="context-menu"
          style={{ position: 'fixed', left: contextMenu.x, top: contextMenu.y, zIndex: 1000 }}
        >
          {onHexJump && (
            <div
              className="context-menu-item"
              onClick={() => { onHexJump(contextMenu.entry.offset); setContextMenu(null); }}
            >
              Follow in Hex
            </div>
          )}
          {onDisasmJump && (
            <div
              className="context-menu-item"
              onClick={() => { onDisasmJump(contextMenu.entry.offset); setContextMenu(null); }}
            >
              Follow in Disasm
            </div>
          )}
          <div
            className="context-menu-item"
            onClick={() => { handleDemangle(contextMenu.entry); setContextMenu(null); }}
          >
            Demangle
          </div>
          <div
            className="context-menu-item"
            onClick={() => {
              setEditDialog({ entry: contextMenu.entry, newValue: contextMenu.entry.text });
              setContextMenu(null);
            }}
          >
            Edit String
          </div>
        </div>
      )}

      {/* Edit dialog */}
      {editDialog && (
        <div className="modal-overlay" onClick={() => setEditDialog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Edit String</h3>
            <p className="text-xs text-muted-foreground mb-2">
              Offset: 0x{editDialog.entry.offset.toString(16)} | Type: {editDialog.entry.encoding}
            </p>
            <input
              type="text"
              value={editDialog.newValue}
              onChange={(e) => setEditDialog({ ...editDialog, newValue: e.target.value })}
              style={{ width: '100%', marginBottom: '8px' }}
            />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setEditDialog(null)}>Cancel</button>
              <button onClick={handleEditString}>Save (.bak backup)</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
