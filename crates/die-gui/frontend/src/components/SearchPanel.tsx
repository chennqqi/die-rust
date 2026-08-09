import { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';

/**
 * Advanced search panel: signature search, value search, and packer detection.
 * Mirrors upstream DIE-engine search functionality.
 */

interface SearchHit {
  offset: string;
  matched: string;
}

interface SearchResult {
  file_size: string;
  hits: SearchHit[];
}

interface PackerInfo {
  name: string;
  version: string | null;
  section_name: string | null;
  entry_section: string | null;
}

type ValueType = 'u8' | 'u16_le' | 'u16_be' | 'u32_le' | 'u32_be' | 'u64_le' | 'u64_be';

type SearchMode = 'signature' | 'value' | 'packers';

export default function SearchPanel({ filePath }: { filePath: string | null }) {
  const [mode, setMode] = useState<SearchMode>('signature');
  const [signature, setSignature] = useState('');
  const [value, setValue] = useState('');
  const [valueType, setValueType] = useState<ValueType>('u32_le');
  const [startOffset, setStartOffset] = useState('0');
  const [maxHits, setMaxHits] = useState('1000');
  const [result, setResult] = useState<SearchResult | null>(null);
  const [packers, setPackers] = useState<PackerInfo[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = useCallback(async () => {
    if (!filePath) return;
    setLoading(true);
    setError(null);
    try {
      if (mode === 'signature') {
        const res = await invoke<SearchResult>('search_signature', {
          path: filePath,
          pattern: signature,
          startOffset: BigInt(startOffset).toString(),
          maxHits: parseInt(maxHits) || 1000,
        });
        setResult(res);
      } else if (mode === 'value') {
        const val = BigInt(value);
        const res = await invoke<SearchResult>('search_value', {
          path: filePath,
          value: val.toString(),
          valueType,
          startOffset: BigInt(startOffset).toString(),
          maxHits: parseInt(maxHits) || 1000,
        });
        setResult(res);
      } else if (mode === 'packers') {
        const res = await invoke<PackerInfo[]>('detect_packers', { path: filePath });
        setPackers(res);
      }
    } catch (e) {
      setError(String(e));
      setResult(null);
      setPackers(null);
    } finally {
      setLoading(false);
    }
  }, [filePath, mode, signature, value, valueType, startOffset, maxHits]);

  if (!filePath) return null;

  return (
    <div className="space-y-3 p-2">
      <h3 className="text-sm font-semibold">Search</h3>

      {/* Mode selector */}
      <div className="flex items-center gap-1">
        {(['signature', 'value', 'packers'] as SearchMode[]).map((m) => (
          <button
            key={m}
            onClick={() => {
              setMode(m);
              setResult(null);
              setPackers(null);
              setError(null);
            }}
            className={`px-2 py-1 text-xs border border-border rounded ${
              mode === m ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
            }`}
          >
            {m === 'signature' ? 'Signature' : m === 'value' ? 'Value' : 'Packers'}
          </button>
        ))}
      </div>

      {/* Search inputs */}
      {mode === 'signature' && (
        <div className="space-y-2">
          <div>
            <label className="text-xs block mb-1">Hex pattern (use ?? for wildcards):</label>
            <input
              type="text"
              value={signature}
              onChange={(e) => setSignature(e.target.value)}
              placeholder="DE AD BE EF  or  DE ?? ?? EF"
              className="input w-full font-mono text-xs"
            />
          </div>
        </div>
      )}

      {mode === 'value' && (
        <div className="space-y-2">
          <div>
            <label className="text-xs block mb-1">Value (decimal or 0xhex):</label>
            <input
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="12345 or 0x1234"
              className="input w-full font-mono text-xs"
            />
          </div>
          <div>
            <label className="text-xs block mb-1">Type:</label>
            <select
              value={valueType}
              onChange={(e) => setValueType(e.target.value as ValueType)}
              className="input text-xs"
            >
              <option value="u8">u8</option>
              <option value="u16_le">u16 LE</option>
              <option value="u16_be">u16 BE</option>
              <option value="u32_le">u32 LE</option>
              <option value="u32_be">u32 BE</option>
              <option value="u64_le">u64 LE</option>
              <option value="u64_be">u64 BE</option>
            </select>
          </div>
        </div>
      )}

      {mode !== 'packers' && (
        <div className="flex gap-2">
          <label className="text-xs">
            Start offset:
            <input
              type="text"
              value={startOffset}
              onChange={(e) => setStartOffset(e.target.value)}
              className="input ml-1 w-24 font-mono text-xs"
            />
          </label>
          <label className="text-xs">
            Max hits:
            <input
              type="text"
              value={maxHits}
              onChange={(e) => setMaxHits(e.target.value)}
              className="input ml-1 w-24 font-mono text-xs"
            />
          </label>
        </div>
      )}

      <button onClick={handleSearch} disabled={loading || (mode === 'signature' && !signature) || (mode === 'value' && !value)} className="btn btn-primary text-xs">
        {loading ? 'Searching...' : mode === 'packers' ? 'Detect Packers' : 'Search'}
      </button>

      {error && <p className="text-xs text-red-500">Error: {error}</p>}

      {/* Results */}
      {result && (
        <div>
          <p className="text-xs text-muted-foreground mb-1">
            {result.hits.length} hits found (file size: {result.file_size})
          </p>
          {result.hits.length > 0 && (
            <div className="border border-border rounded overflow-auto max-h-96">
              <table className="w-full text-xs">
                <thead className="bg-muted/50 sticky top-0">
                  <tr>
                    <th className="text-right px-2 py-1">Offset</th>
                    <th className="text-left px-2 py-1">Matched</th>
                  </tr>
                </thead>
                <tbody>
                  {result.hits.map((hit, i) => (
                    <tr key={i} className="border-b border-border/30">
                      <td className="px-2 py-0.5 text-right font-mono">0x{BigInt(hit.offset).toString(16)}</td>
                      <td className="px-2 py-0.5 font-mono">{hit.matched}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {packers && (
        <div>
          {packers.length === 0 ? (
            <p className="text-xs text-muted-foreground">No packers detected.</p>
          ) : (
            <div className="border border-border rounded">
              <table className="w-full text-xs">
                <thead className="bg-muted/50">
                  <tr>
                    <th className="text-left px-2 py-1">Packer</th>
                    <th className="text-left px-2 py-1">Version</th>
                    <th className="text-left px-2 py-1">Section</th>
                  </tr>
                </thead>
                <tbody>
                  {packers.map((p, i) => (
                    <tr key={i} className="border-b border-border/30">
                      <td className="px-2 py-0.5 font-mono">{p.name}</td>
                      <td className="px-2 py-0.5 font-mono">{p.version ?? '—'}</td>
                      <td className="px-2 py-0.5 font-mono">{p.section_name ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
