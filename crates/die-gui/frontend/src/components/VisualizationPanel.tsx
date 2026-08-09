import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { save } from '@tauri-apps/plugin-dialog';

/**
 * 2D file visualization — renders file bytes as a color-coded grid.
 * Mirrors upstream XVisualizationWidget.
 *
 * Supports 6 rendering methods:
 * - Entropy: Shannon entropy per block (blue → red)
 * - Gradient: average byte value (black → white)
 * - Zero bytes: zero-byte density (black → white)
 * - Text: printable ASCII density (black → white)
 * - Zeros gradient: rate of zero-byte transitions
 * - Text gradient: rate of text/non-text transitions
 */

type VizMethod = 'entropy' | 'gradient' | 'zero_bytes' | 'text' | 'zeros_gradient' | 'text_gradient';

interface VizRegion {
  name: string;
  offset: string;
  size: string;
  color: string;
}

interface VisualizationData {
  width: number;
  height: number;
  block_size: number;
  file_size: string;
  grid: number[];
  regions: VizRegion[];
  method: VizMethod;
}

interface HighlightRegion {
  startBlock: number;
  endBlock: number;
  color: string;
  label: string;
}

const METHOD_LABELS: { key: VizMethod; label: string }[] = [
  { key: 'entropy', label: 'Entropy' },
  { key: 'gradient', label: 'Gradient' },
  { key: 'zero_bytes', label: 'Zero Bytes' },
  { key: 'text', label: 'Text' },
  { key: 'zeros_gradient', label: 'Zeros Gradient' },
  { key: 'text_gradient', label: 'Text Gradient' },
];

/** Map a 0-255 value to an RGB color based on the rendering method. */
function valueToColor(val: number, method: VizMethod): string {
  switch (method) {
    case 'entropy': {
      // Blue (low entropy) → Red (high entropy)
      const t = val / 255;
      const r = Math.round(t * 255);
      const b = Math.round((1 - t) * 255);
      return `rgb(${r},0,${b})`;
    }
    case 'gradient':
    case 'zero_bytes':
    case 'text':
    case 'zeros_gradient':
    case 'text_gradient':
      return `rgb(${val},${val},${val})`;
    default:
      return `rgb(${val},${val},${val})`;
  }
}

export default function VisualizationPanel({ filePath }: { filePath: string | null }) {
  const [data, setData] = useState<VisualizationData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [method, setMethod] = useState<VizMethod>('entropy');
  const [showRegions, setShowRegions] = useState(true);
  const [zoom, setZoom] = useState(3);
  const [highlights, setHighlights] = useState<HighlightRegion[]>([]);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const fetchViz = useCallback(async () => {
    if (!filePath) {
      setData(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<VisualizationData>('get_visualization', {
        path: filePath,
        method,
        blockSize: 256,
        width: 256,
      });
      setData(result);
    } catch (e) {
      setError(String(e));
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [filePath, method]);

  useEffect(() => {
    fetchViz();
  }, [fetchViz]);

  // Render grid to canvas.
  useEffect(() => {
    if (!data || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const cellSize = zoom;
    canvas.width = data.width * cellSize;
    canvas.height = data.height * cellSize;

    // Draw cells.
    for (let i = 0; i < data.grid.length; i++) {
      const x = (i % data.width) * cellSize;
      const y = Math.floor(i / data.width) * cellSize;
      ctx.fillStyle = valueToColor(data.grid[i], data.method);
      ctx.fillRect(x, y, cellSize, cellSize);
    }

    // Draw region overlays.
    if (showRegions && data.regions.length > 0) {
      const blockSize = data.block_size;
      for (const region of data.regions) {
        const offset = BigInt(region.offset);
        const size = BigInt(region.size);
        if (size === 0n) continue;
        const startBlock = Number(offset / BigInt(blockSize));
        const endBlock = Number((offset + size) / BigInt(blockSize));
        const startCol = startBlock % data.width;
        const startRow = Math.floor(startBlock / data.width);
        const endCol = endBlock % data.width;
        const endRow = Math.floor(endBlock / data.width);

        // Draw rectangle outline.
        ctx.strokeStyle = region.color;
        ctx.lineWidth = 2;
        ctx.strokeRect(
          startCol * cellSize,
          startRow * cellSize,
          (endCol - startCol) * cellSize,
          (endRow - startRow) * cellSize,
        );
      }
    }

    // Draw highlights.
    for (const hl of highlights) {
      const startCol = hl.startBlock % data.width;
      const startRow = Math.floor(hl.startBlock / data.width);
      const endCol = hl.endBlock % data.width;
      const endRow = Math.floor(hl.endBlock / data.width);
      ctx.strokeStyle = hl.color;
      ctx.lineWidth = 3;
      ctx.strokeRect(
        startCol * cellSize,
        startRow * cellSize,
        (endCol - startCol) * cellSize,
        (endRow - startRow) * cellSize,
      );
    }
  }, [data, showRegions, zoom, highlights]);

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!data || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const cellSize = zoom;
    const col = Math.floor(x / cellSize);
    const row = Math.floor(y / cellSize);
    const blockIndex = row * data.width + col;
    // Add highlight from clicked block to clicked block + 10 blocks.
    const hl: HighlightRegion = {
      startBlock: blockIndex,
      endBlock: blockIndex + 10,
      color: '#ffff00',
      label: `Block ${blockIndex}`,
    };
    setHighlights([...highlights, hl]);
  };

  const handleSaveImage = async () => {
    if (!canvasRef.current) return;
    try {
      const savePath = await save({
        defaultPath: 'visualization.png',
        filters: [{ name: 'PNG', extensions: ['png'] }],
      });
      if (!savePath) return;
      const dataUrl = canvasRef.current.toDataURL('image/png');
      const base64 = dataUrl.split(',')[1];
      const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
      await invoke('write_binary_file', { path: savePath, data: Array.from(bytes) });
    } catch (e) {
      setError(`Save image failed: ${e}`);
    }
  };

  if (!filePath) return null;
  if (loading) return <p className="text-xs text-muted-foreground p-2">Loading visualization...</p>;
  if (error) return <p className="text-xs text-red-500 p-2">Error: {error}</p>;
  if (!data) return null;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex gap-1">
          {METHOD_LABELS.map((m) => (
            <button
              key={m.key}
              onClick={() => setMethod(m.key)}
              className={`px-2 py-1 text-xs border border-border rounded ${
                method === m.key ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1 text-xs">
          <input
            type="checkbox"
            checked={showRegions}
            onChange={(e) => setShowRegions(e.target.checked)}
          />
          Show Regions
        </label>
        <label className="flex items-center gap-1 text-xs">
          Zoom:
          <input
            type="range"
            min={1}
            max={10}
            value={zoom}
            onChange={(e) => setZoom(parseInt(e.target.value))}
          />
          {zoom}px
        </label>
        <button
          onClick={handleSaveImage}
          className="px-2 py-1 text-xs border border-border rounded hover:bg-muted"
        >
          Save Image
        </button>
        {highlights.length > 0 && (
          <button
            onClick={() => setHighlights([])}
            className="px-2 py-1 text-xs border border-border rounded hover:bg-muted"
          >
            Clear Highlights
          </button>
        )}
      </div>

      <div className="border border-border rounded p-2 overflow-auto">
        <canvas ref={canvasRef} className="max-w-full" onClick={handleCanvasClick} />
      </div>

      {/* Highlights list */}
      {highlights.length > 0 && (
        <div className="border border-border rounded">
          <table className="w-full text-xs">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-2 py-1">Color</th>
                <th className="text-left px-2 py-1">Label</th>
                <th className="text-right px-2 py-1">Start</th>
                <th className="text-right px-2 py-1">End</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {highlights.map((hl, i) => (
                <tr key={i} className="border-b border-border/30">
                  <td className="px-2 py-0.5">
                    <div
                      className="inline-block w-4 h-4 rounded"
                      style={{ backgroundColor: hl.color }}
                    />
                  </td>
                  <td className="px-2 py-0.5 font-mono">{hl.label}</td>
                  <td className="px-2 py-0.5 text-right font-mono">{hl.startBlock}</td>
                  <td className="px-2 py-0.5 text-right font-mono">{hl.endBlock}</td>
                  <td className="px-2 py-0.5">
                    <button
                      onClick={() => setHighlights(highlights.filter((_, j) => j !== i))}
                      className="text-red-500 hover:text-red-700"
                    >
                      ×
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.regions.length > 0 && (
        <div className="border border-border rounded">
          <table className="w-full text-xs">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-2 py-1">Color</th>
                <th className="text-left px-2 py-1">Name</th>
                <th className="text-right px-2 py-1">Offset</th>
                <th className="text-right px-2 py-1">Size</th>
              </tr>
            </thead>
            <tbody>
              {data.regions.map((r, i) => (
                <tr key={i} className="border-b border-border/30">
                  <td className="px-2 py-0.5">
                    <div
                      className="inline-block w-4 h-4 rounded"
                      style={{ backgroundColor: r.color }}
                    />
                  </td>
                  <td className="px-2 py-0.5 font-mono">{r.name}</td>
                  <td className="px-2 py-0.5 text-right font-mono">0x{BigInt(r.offset).toString(16)}</td>
                  <td className="px-2 py-0.5 text-right font-mono">{r.size}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
