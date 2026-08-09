import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface SectionInfo {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_offset: number;
  raw_size: number;
  entropy: number;
}

interface FileInfo {
  path: string;
  file_name: string;
  size: number;
  size_human: string;
  entropy: number;
  format: string;
  sections: SectionInfo[];
}

/** Section visualizer — displays sections as a color-coded proportional bar.
 *  Shows raw layout (file offsets) with entropy color coding.
 *  Mirrors upstream XVisualization widget. */
export default function SectionVisualizer({ filePath }: { filePath: string }) {
  const [info, setInfo] = useState<FileInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hoveredSection, setHoveredSection] = useState<number | null>(null);

  const fetchInfo = useCallback(async () => {
    if (!filePath) {
      setInfo(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<FileInfo>('get_file_info', { path: filePath });
      setInfo(result);
    } catch (e) {
      setError(String(e));
      setInfo(null);
    } finally {
      setLoading(false);
    }
  }, [filePath]);

  useEffect(() => {
    fetchInfo();
  }, [fetchInfo]);

  if (!filePath) {
    return <div className="section-viz empty">No file selected.</div>;
  }

  if (loading) {
    return <div className="section-viz">Loading...</div>;
  }

  if (error) {
    return <div className="section-viz error">Error: {error}</div>;
  }

  if (!info || info.sections.length === 0) {
    return <div className="section-viz empty">No sections available.</div>;
  }

  // Calculate total file size for proportional display.
  const fileSize = info.size;
  if (fileSize === 0) {
    return <div className="section-viz empty">File size is zero.</div>;
  }

  // Color sections by entropy: blue (low) → green (medium) → red (high).
  const entropyToColor = (entropy: number): string => {
    if (entropy < 3) return '#4a90d9'; // Low entropy - blue
    if (entropy < 5) return '#50c878'; // Medium entropy - green
    if (entropy < 7) return '#f0ad4e'; // High entropy - orange
    return '#d9534f'; // Very high entropy - red
  };

  // Build section segments for the bar.
  const segments = info.sections.map((sec, i) => {
    const startPct = (sec.raw_offset / fileSize) * 100;
    const widthPct = (sec.raw_size / fileSize) * 100;
    const color = entropyToColor(sec.entropy);
    return {
      index: i,
      name: sec.name,
      startPct,
      widthPct: Math.max(widthPct, 0.1), // Min 0.1% for visibility
      color,
      section: sec,
    };
  });

  // Find overlay (gap between last section end and file end).
  const lastSectionEnd = Math.max(
    ...info.sections.map((s) => s.raw_offset + s.raw_size)
  );
  const overlaySize = fileSize > lastSectionEnd ? fileSize - lastSectionEnd : 0;
  const overlayPct = (overlaySize / fileSize) * 100;

  // Header gap (from 0 to first section).
  const firstSectionStart = Math.min(...info.sections.map((s) => s.raw_offset));
  const headerPct = (firstSectionStart / fileSize) * 100;

  return (
    <div className="section-viz">
      <h3 className="viz-title">Section Layout (Raw File)</h3>

      {/* Visual bar */}
      <div className="viz-bar-container">
        {/* Header region */}
        {headerPct > 0 && (
          <div
            className="viz-segment header"
            style={{
              width: `${headerPct}%`,
              backgroundColor: '#888',
            }}
            title={`Header: 0x0 - 0x${firstSectionStart.toString(16)} (${firstSectionStart} bytes)`}
          />
        )}
        {/* Section segments */}
        {segments.map((seg) => (
          <div
            key={seg.index}
            className={`viz-segment ${hoveredSection === seg.index ? 'hovered' : ''}`}
            style={{
              width: `${seg.widthPct}%`,
              backgroundColor: seg.color,
            }}
            onMouseEnter={() => setHoveredSection(seg.index)}
            onMouseLeave={() => setHoveredSection(null)}
            title={`${seg.name}: 0x${seg.section.raw_offset.toString(16)} - 0x${(seg.section.raw_offset + seg.section.raw_size).toString(16)} (${seg.section.raw_size} bytes, entropy: ${seg.section.entropy.toFixed(2)})`}
          />
        ))}
        {/* Overlay region */}
        {overlayPct > 0 && (
          <div
            className="viz-segment overlay"
            style={{
              width: `${overlayPct}%`,
              backgroundColor: '#555',
            }}
            title={`Overlay: ${overlaySize} bytes`}
          />
        )}
      </div>

      {/* Offset ruler */}
      <div className="viz-ruler">
        <span>0x0</span>
        <span>0x{Math.floor(fileSize / 2).toString(16)}</span>
        <span>0x{fileSize.toString(16)}</span>
      </div>

      {/* Legend */}
      <div className="viz-legend">
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#888' }} />
          <span>Header</span>
        </div>
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#4a90d9' }} />
          <span>Low entropy (&lt;3)</span>
        </div>
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#50c878' }} />
          <span>Medium (3-5)</span>
        </div>
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#f0ad4e' }} />
          <span>High (5-7)</span>
        </div>
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#d9534f' }} />
          <span>Very high (&ge;7)</span>
        </div>
        {overlayPct > 0 && (
          <div className="legend-item">
            <span className="legend-color" style={{ background: '#555' }} />
            <span>Overlay</span>
          </div>
        )}
      </div>

      {/* Section details table */}
      <table className="viz-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Raw Offset</th>
            <th>Raw Size</th>
            <th>VAddr</th>
            <th>VSize</th>
            <th>Entropy</th>
            <th>%</th>
          </tr>
        </thead>
        <tbody>
          {info.sections.map((sec, i) => (
            <tr
              key={i}
              className={hoveredSection === i ? 'hovered' : ''}
              onMouseEnter={() => setHoveredSection(i)}
              onMouseLeave={() => setHoveredSection(null)}
            >
              <td className="sec-name">{sec.name}</td>
              <td className="mono">0x{sec.raw_offset.toString(16).padStart(8, '0')}</td>
              <td className="mono">{sec.raw_size.toLocaleString()}</td>
              <td className="mono">0x{sec.virtual_address.toString(16).padStart(8, '0')}</td>
              <td className="mono">{sec.virtual_size.toLocaleString()}</td>
              <td>
                <span
                  className="entropy-badge"
                  style={{ backgroundColor: entropyToColor(sec.entropy) }}
                >
                  {sec.entropy.toFixed(2)}
                </span>
              </td>
              <td>{((sec.raw_size / fileSize) * 100).toFixed(1)}%</td>
            </tr>
          ))}
          {overlaySize > 0 && (
            <tr className="overlay-row">
              <td className="sec-name">Overlay</td>
              <td className="mono">0x{lastSectionEnd.toString(16).padStart(8, '0')}</td>
              <td className="mono">{overlaySize.toLocaleString()}</td>
              <td colSpan={2}>—</td>
              <td>—</td>
              <td>{(overlayPct).toFixed(1)}%</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
