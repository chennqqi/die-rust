import { useState, useCallback, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { save } from '@tauri-apps/plugin-dialog';
import { useTranslation } from 'react-i18next';

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
  const { t } = useTranslation();
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
      alert(t('strings.demangled', { result }));
    } catch {
      alert(t('strings.demangleFailed'));
    }
  };

  const handleEditString = async () => {
    if (!editDialog || !filePath) return;
    setEditStatus(t('common.saving'));
    try {
      const isUtf16 = editDialog.entry.encoding === 'utf16_le';
      await invoke('edit_string_at_offset', {
        path: filePath,
        offset: editDialog.entry.offset,
        newValue: editDialog.newValue,
        isUtf16,
      });
      setEditStatus(t('strings.editSuccess'));
      setEditDialog(null);
      fetchStrings();
    } catch (e) {
      setEditStatus(t('common.error', { error: String(e) }));
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
      setError(t('strings.saveFailed', { error: String(e) }));
    }
  };

  if (!filePath) {
    return <div className="string-extractor empty">{t('common.noFile')}</div>;
  }

  return (
    <div className="string-extractor">
      {/* Controls */}
      <div className="string-controls">
        <div className="string-control-group">
          <label>
            {t('strings.minLength')}:
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
            {t('strings.nullTerminated')}
          </label>
        </div>
        <div className="string-control-group">
          <label>
            {t('strings.filterMode')}:
            <select
              value={filterMode}
              onChange={(e) => setFilterMode(e.target.value as 'substring' | 'regexp' | 'links')}
              style={{ marginLeft: '4px' }}
            >
              <option value="substring">{t('strings.substring')}</option>
              <option value="regexp">{t('strings.regexp')}</option>
              <option value="links">{t('strings.linksOnly')}</option>
            </select>
          </label>
        </div>
        <div className="string-control-group">
          <label>
            {t('strings.mapMode')}:
            <select
              value={mapMode}
              onChange={(e) => setMapMode(e.target.value as MapMode)}
              style={{ marginLeft: '4px' }}
            >
              <option value="file">{t('strings.file')}</option>
              <option value="virtual">{t('strings.virtual')}</option>
              <option value="physical">{t('strings.physical')}</option>
            </select>
          </label>
        </div>
        <div className="string-control-group">
          <label>
            {t('strings.fileType')}:
            <select
              value={fileType}
              onChange={(e) => setFileType(e.target.value as FileType)}
              style={{ marginLeft: '4px' }}
            >
              <option value="auto">{t('common.auto')}</option>
              <option value="pe">PE</option>
              <option value="elf">ELF</option>
              <option value="macho">Mach-O</option>
              <option value="dex">DEX</option>
              <option value="raw">{t('strings.raw')}</option>
            </select>
          </label>
        </div>
        <div className="string-control-group">
          <label>
            {t('strings.maxResults')}:
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
            placeholder={filterMode === 'links' ? t('strings.phLinks') : filterMode === 'regexp' ? t('strings.phPattern') : t('strings.phFilter')}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ width: '200px' }}
            disabled={filterMode === 'links'}
          />
        </div>
        <button onClick={fetchStrings} disabled={loading}>
          {loading ? t('strings.extracting') : t('common.extract')}
        </button>
        <button onClick={handleSaveResults} disabled={loading || strings.length === 0}>
          {t('common.save')}
        </button>
      </div>

      {/* Stats */}
      <div className="string-stats">
        {loading ? (
          <span>{t('common.loading')}</span>
        ) : (
          <span>{t('strings.found', { count: strings.length })}</span>
        )}
        {error && <span className="string-error">{t('common.error', { error })}</span>}
        {editStatus && <span className="string-edit-status">{editStatus}</span>}
      </div>

      {/* Results table */}
      <div className="string-results">
        {!loading && strings.length > 0 && (
          <table className="string-table">
            <thead>
              <tr>
                <th>{t('common.offset')}</th>
                <th>{t('common.type')}</th>
                <th>{t('strings.colString')}</th>
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
          <div className="string-empty">{t('strings.noStrings')}</div>
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
              {t('common.followInHex')}
            </div>
          )}
          {onDisasmJump && (
            <div
              className="context-menu-item"
              onClick={() => { onDisasmJump(contextMenu.entry.offset); setContextMenu(null); }}
            >
              {t('common.followInDisasm')}
            </div>
          )}
          <div
            className="context-menu-item"
            onClick={() => { handleDemangle(contextMenu.entry); setContextMenu(null); }}
          >
            {t('strings.demangle')}
          </div>
          <div
            className="context-menu-item"
            onClick={() => {
              setEditDialog({ entry: contextMenu.entry, newValue: contextMenu.entry.text });
              setContextMenu(null);
            }}
          >
            {t('strings.editString')}
          </div>
        </div>
      )}

      {/* Edit dialog */}
      {editDialog && (
        <div className="modal-overlay" onClick={() => setEditDialog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>{t('strings.editString')}</h3>
            <p className="text-xs text-muted-foreground mb-2">
              {t('common.offset')}: 0x{editDialog.entry.offset.toString(16)} | {t('common.type')}: {editDialog.entry.encoding}
            </p>
            <input
              type="text"
              value={editDialog.newValue}
              onChange={(e) => setEditDialog({ ...editDialog, newValue: e.target.value })}
              style={{ width: '100%', marginBottom: '8px' }}
            />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setEditDialog(null)}>{t('common.cancel')}</button>
              <button onClick={handleEditString}>{t('strings.saveBak')}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
