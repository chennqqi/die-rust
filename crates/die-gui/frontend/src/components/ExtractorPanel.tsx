import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open as openDialog } from '@tauri-apps/plugin-dialog';

/**
 * File extractor — extracts overlay, resources, sections, and arbitrary byte ranges.
 * Mirrors upstream XExtractorWidget.
 */

interface ExtractItem {
  name: string;
  item_type: string;
  offset: string;
  size: string;
  description: string | null;
}

interface ExtractItemList {
  file_path: string;
  file_size: string;
  items: ExtractItem[];
}

interface AnalyzeResult {
  file_type: string;
  size: string;
  entropy: number;
}

export default function ExtractorPanel({ filePath }: { filePath: string | null }) {
  const [list, setList] = useState<ExtractItemList | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [extracting, setExtracting] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [rawOffset, setRawOffset] = useState('0');
  const [rawSize, setRawSize] = useState('256');
  const [heuristicItems, setHeuristicItems] = useState<ExtractItem[]>([]);
  const [deepScan, setDeepScan] = useState(false);
  const [analyzeResults, setAnalyzeResults] = useState<Record<string, AnalyzeResult>>({});

  const fetchList = useCallback(async () => {
    if (!filePath) {
      setList(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<ExtractItemList>('list_extractable', { path: filePath });
      setList(result);
    } catch (e) {
      setError(String(e));
      setList(null);
    } finally {
      setLoading(false);
    }
  }, [filePath]);

  useEffect(() => {
    fetchList();
  }, [fetchList]);

  const handleExtractItem = async (itemName: string) => {
    if (!filePath) return;
    const outputDir = await openDialog({
      directory: true,
      multiple: false,
      title: 'Select output directory',
    });
    if (!outputDir || typeof outputDir !== 'string') return;

    setExtracting(itemName);
    setResult(null);
    try {
      const outPath = await invoke<string>('extract_item', {
        path: filePath,
        itemName,
        outputDir,
      });
      setResult(`Extracted to: ${outPath}`);
    } catch (e) {
      setResult(`Error: ${e}`);
    } finally {
      setExtracting(null);
    }
  };

  const handleExtractRaw = async () => {
    if (!filePath) return;
    const offset = BigInt(rawOffset);
    const size = BigInt(rawSize);
    if (size <= 0n) {
      setResult('Error: size must be > 0');
      return;
    }
    const outputDir = await openDialog({
      directory: true,
      multiple: false,
      title: 'Select output directory',
    });
    if (!outputDir || typeof outputDir !== 'string') return;

    const outputName = `raw_0x${offset.toString(16)}_${size}.bin`;
    setExtracting('raw');
    setResult(null);
    try {
      const outPath = await invoke<string>('extract_range', {
        path: filePath,
        offset: offset.toString(),
        size: size.toString(),
        outputDir,
        outputName,
      });
      setResult(`Extracted to: ${outPath}`);
    } catch (e) {
      setResult(`Error: ${e}`);
    } finally {
      setExtracting(null);
    }
  };

  if (!filePath) return null;
  if (loading) return <p className="text-xs text-muted-foreground p-2">Loading extractable items...</p>;
  if (error) return <p className="text-xs text-red-500 p-2">Error: {error}</p>;
  if (!list) return null;

  const handleHeuristicScan = async () => {
    if (!filePath) return;
    setExtracting('heuristic');
    setResult(null);
    try {
      const items = await invoke<ExtractItem[]>('extract_heuristic', {
        path: filePath,
        deepScan,
      });
      setHeuristicItems(items);
      setResult(`Heuristic scan found ${items.length} embedded files.`);
    } catch (e) {
      setResult(`Error: ${e}`);
    } finally {
      setExtracting(null);
    }
  };

  const handleAnalyze = async (item: ExtractItem) => {
    if (!filePath) return;
    try {
      const result = await invoke<AnalyzeResult>('analyze_item', {
        path: filePath,
        offset: item.offset,
        size: item.size,
      });
      setAnalyzeResults({ ...analyzeResults, [item.name]: result });
    } catch (e) {
      setResult(`Analyze error: ${e}`);
    }
  };

  return (
    <div className="space-y-3 p-2">
      <h3 className="text-sm font-semibold">Extractor</h3>

      {/* Heuristic extraction */}
      <div>
        <h4 className="text-xs font-semibold mb-1">Heuristic Extraction</h4>
        <div className="flex items-center gap-2 mb-2">
          <label className="flex items-center gap-1 text-xs">
            <input
              type="checkbox"
              checked={deepScan}
              onChange={(e) => setDeepScan(e.target.checked)}
            />
            Deep Scan (entire file)
          </label>
          <button
            onClick={handleHeuristicScan}
            disabled={extracting !== null}
            className="px-2 py-0.5 text-xs border border-border rounded hover:bg-muted disabled:opacity-50"
          >
            {extracting === 'heuristic' ? 'Scanning...' : 'Scan for Embedded Files'}
          </button>
        </div>
        {heuristicItems.length > 0 && (
          <div className="border border-border rounded overflow-auto max-h-64">
            <table className="w-full text-xs">
              <thead className="bg-muted/50 sticky top-0">
                <tr>
                  <th className="text-left px-2 py-1">Name</th>
                  <th className="text-left px-2 py-1">Type</th>
                  <th className="text-right px-2 py-1">Offset</th>
                  <th className="text-right px-2 py-1">Size</th>
                  <th className="text-center px-2 py-1">Analyze</th>
                  <th className="text-center px-2 py-1">Extract</th>
                </tr>
              </thead>
              <tbody>
                {heuristicItems.map((item, i) => (
                  <tr key={i} className="border-b border-border/30">
                    <td className="px-2 py-0.5 font-mono">{item.name}</td>
                    <td className="px-2 py-0.5 font-mono">{item.item_type}</td>
                    <td className="px-2 py-0.5 text-right font-mono">0x{BigInt(item.offset).toString(16)}</td>
                    <td className="px-2 py-0.5 text-right font-mono">{item.size}</td>
                    <td className="px-2 py-0.5 text-center">
                      <button
                        onClick={() => handleAnalyze(item)}
                        className="px-1 py-0.5 text-xs border border-border rounded hover:bg-muted"
                      >
                        {analyzeResults[item.name]
                          ? `${analyzeResults[item.name].file_type} (H=${analyzeResults[item.name].entropy.toFixed(2)})`
                          : 'Analyze'}
                      </button>
                    </td>
                    <td className="px-2 py-0.5 text-center">
                      <button
                        onClick={() => handleExtractItem(item.name)}
                        disabled={extracting !== null}
                        className="px-2 py-0.5 text-xs border border-border rounded hover:bg-muted disabled:opacity-50"
                      >
                        {extracting === item.name ? '...' : 'Extract'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Format-aware extraction */}
      <div>
        <h4 className="text-xs font-semibold mb-1">Format-Aware Extraction</h4>
        {list.items.length === 0 ? (
          <p className="text-xs text-muted-foreground">No extractable items found.</p>
        ) : (
          <div className="border border-border rounded overflow-auto max-h-64">
            <table className="w-full text-xs">
              <thead className="bg-muted/50 sticky top-0">
                <tr>
                  <th className="text-left px-2 py-1">Name</th>
                  <th className="text-left px-2 py-1">Type</th>
                  <th className="text-right px-2 py-1">Offset</th>
                  <th className="text-right px-2 py-1">Size</th>
                  <th className="text-left px-2 py-1">Description</th>
                  <th className="text-center px-2 py-1">Action</th>
                </tr>
              </thead>
              <tbody>
                {list.items.map((item, i) => (
                  <tr key={i} className="border-b border-border/30">
                    <td className="px-2 py-0.5 font-mono">{item.name}</td>
                    <td className="px-2 py-0.5 font-mono">{item.item_type}</td>
                    <td className="px-2 py-0.5 text-right font-mono">0x{BigInt(item.offset).toString(16)}</td>
                    <td className="px-2 py-0.5 text-right font-mono">{item.size}</td>
                    <td className="px-2 py-0.5 font-mono text-muted-foreground">{item.description ?? ''}</td>
                    <td className="px-2 py-0.5 text-center">
                      <button
                        onClick={() => handleExtractItem(item.name)}
                        disabled={extracting !== null}
                        className="px-2 py-0.5 text-xs border border-border rounded hover:bg-muted disabled:opacity-50"
                      >
                        {extracting === item.name ? '...' : 'Extract'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Raw byte range extraction */}
      <div>
        <h4 className="text-xs font-semibold mb-1">Raw Byte Range Extraction</h4>
        <div className="flex items-center gap-2">
          <label className="text-xs">
            Offset:
            <input
              type="text"
              value={rawOffset}
              onChange={(e) => setRawOffset(e.target.value)}
              className="ml-1 px-1 py-0.5 text-xs border border-border rounded w-32 font-mono"
              placeholder="0x0"
            />
          </label>
          <label className="text-xs">
            Size:
            <input
              type="text"
              value={rawSize}
              onChange={(e) => setRawSize(e.target.value)}
              className="ml-1 px-1 py-0.5 text-xs border border-border rounded w-32 font-mono"
              placeholder="256"
            />
          </label>
          <button
            onClick={handleExtractRaw}
            disabled={extracting !== null}
            className="px-2 py-0.5 text-xs border border-border rounded hover:bg-muted disabled:opacity-50"
          >
            {extracting === 'raw' ? 'Extracting...' : 'Extract Raw'}
          </button>
        </div>
      </div>

      {result && (
        <div className="text-xs p-2 border border-border rounded bg-muted/30">
          {result}
        </div>
      )}
    </div>
  );
}
