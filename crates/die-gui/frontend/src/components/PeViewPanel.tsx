import { useEffect, useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useTranslation } from 'react-i18next';
import { followInHex } from '../follow';

// --- PE view data types (mirror Rust PeView struct) ---

interface PeImportEntry {
  dll: string;
  name: string;
}

interface PeExportEntry {
  name: string;
  ordinal: number;
  rva: number;
}

interface PeResourceNode {
  id: number;
  name: string;
  data_size?: number;
  children?: PeResourceNode[];
}

interface PeDotNetInfo {
  has_clr: boolean;
  clr_rva: number;
  clr_size: number;
}

interface PeVersionEntry {
  entries: [string, string][];
}

interface PeDataDirectoryEntry {
  name: string;
  index: number;
  rva: number;
  size: number;
}

interface PeDebugEntry {
  debug_type: string;
  debug_type_val: number;
  size_of_data: number;
  address_of_raw_data: number;
  pointer_to_raw_data: number;
  pdb_file_name: string | null;
}

interface PeRelocBlock {
  virtual_address: number;
  block_size: number;
  count: number;
}

interface PeLoadConfig {
  size: number;
  security_cookie: string;
  se_handler_table: string;
  se_handler_count: string;
}

interface PeCertificate {
  certificate_type: number;
  data_length: number;
  has_data: boolean;
}

interface PeDosHeaderField {
  name: string;
  value: string;
  description: string | null;
}

interface PeDosStub {
  offset: number;
  size: number;
  hex_dump: string;
}

interface PeFileHeader {
  machine: string;
  machine_val: number;
  number_of_sections: number;
  time_date_stamp: number;
  pointer_to_symbol_table: number;
  number_of_symbols: number;
  size_of_optional_header: number;
  characteristics: string;
  characteristics_val: number;
}

interface PeOptionalHeader {
  is64: boolean;
  magic: number;
  magic_str: string;
  major_linker_version: number;
  minor_linker_version: number;
  size_of_code: number;
  size_of_initialized_data: number;
  size_of_uninitialized_data: number;
  address_of_entry_point: number;
  base_of_code: number;
  base_of_data: number | null;
  image_base: string;
  section_alignment: number;
  file_alignment: number;
  major_operating_system_version: number;
  minor_operating_system_version: number;
  major_image_version: number;
  minor_image_version: number;
  major_subsystem_version: number;
  minor_subsystem_version: number;
  win32_version_value: number;
  size_of_image: number;
  size_of_headers: number;
  check_sum: number;
  subsystem: string;
  subsystem_val: number;
  dll_characteristics: string;
  dll_characteristics_val: number;
  size_of_stack_reserve: string;
  size_of_stack_commit: string;
  size_of_heap_reserve: string;
  size_of_heap_commit: string;
  loader_flags: number;
  number_of_rva_and_sizes: number;
}

interface PeSectionDetail {
  name: string;
  virtual_size: number;
  virtual_address: number;
  size_of_raw_data: number;
  pointer_to_raw_data: number;
  pointer_to_relocations: number;
  pointer_to_linenumbers: number;
  number_of_relocations: number;
  number_of_linenumbers: number;
  characteristics: string;
  characteristics_val: number;
  entropy: number | null;
}

interface PeSectionStats {
  total_sections: number;
  total_virtual_size: number;
  total_raw_size: number;
  min_entropy: number | null;
  max_entropy: number | null;
  avg_entropy: number | null;
}

interface PeImportDllSummary {
  dll_name: string;
  function_count: number;
}

interface PeImportInfo {
  total_dlls: number;
  total_functions: number;
  dlls: PeImportDllSummary[];
}

interface PeExceptionEntry {
  begin_address: number;
  end_address: number;
  unwind_info_address: number;
}

interface PeBoundImportEntry {
  module_name: string;
  time_date_stamp: number;
  offset_module_name: number;
  number_of_module_forwarder_refs: number;
}

interface PeDelayImportEntry {
  dll_name: string;
  attributes: number;
  dll_name_rva: number;
  module_handle_rva: number;
  import_address_table_rva: number;
  import_name_table_rva: number;
  bound_import_address_table_rva: number;
  unload_information_table_rva: number;
  time_date_stamp: number;
}

interface PeDotNetStream {
  name: string;
  offset: number;
  size: number;
}

interface PeDotNetMetadata {
  runtime_version: string;
  metadata_rva: number;
  metadata_size: number;
  flags: number;
  entry_point_token: number;
  streams: PeDotNetStream[];
}

interface PeNtFileHeaderSummary {
  machine: string;
  number_of_sections: number;
  time_date_stamp: number;
  characteristics: string;
}

interface PeNtOptionalHeaderSummary {
  magic: string;
  is64: boolean;
  entry_point: number;
  image_base: string;
  section_alignment: number;
  file_alignment: number;
  size_of_image: number;
  size_of_headers: number;
  subsystem: string;
}

interface PeNtHeaders {
  signature: string;
  signature_val: number;
  offset: number;
  file_header_summary: PeNtFileHeaderSummary;
  optional_header_summary: PeNtOptionalHeaderSummary;
  number_of_data_directories: number;
  number_of_sections: number;
}

interface PeResourceStringEntry {
  id: number;
  value: string;
  offset: number;
}

interface PeDotNetStreamDetail {
  name: string;
  offset: number;
  size: number;
  stream_type: string;
  hex_preview: string;
}

interface PeDotNetMetadataTableRow {
  table_name: string;
  row: number;
  columns: [string, string][];
}

interface PeDotNetMetadataTable {
  present_tables: string[];
  row_counts: [string, number][];
  sample_rows: PeDotNetMetadataTableRow[];
}

interface PeView {
  imports: PeImportEntry[];
  exports: PeExportEntry[];
  resources: PeResourceNode[];
  overlay_offset: number;
  overlay_size: number;
  dotnet: PeDotNetInfo | null;
  manifest: string | null;
  version_info: PeVersionEntry[];
  tls_callbacks: number[];
  has_rich_header: boolean;
  data_directories: PeDataDirectoryEntry[];
  debug_entries: PeDebugEntry[];
  reloc_blocks: PeRelocBlock[];
  load_config: PeLoadConfig | null;
  certificates: PeCertificate[];
  dos_header: PeDosHeaderField[];
  dos_stub: PeDosStub | null;
  file_header: PeFileHeader | null;
  optional_header: PeOptionalHeader | null;
  section_details: PeSectionDetail[];
  section_stats: PeSectionStats | null;
  import_info: PeImportInfo | null;
  exceptions: PeExceptionEntry[];
  bound_imports: PeBoundImportEntry[];
  delay_imports: PeDelayImportEntry[];
  dotnet_metadata: PeDotNetMetadata | null;
  nt_headers: PeNtHeaders | null;
  resource_strings: PeResourceStringEntry[];
  dotnet_stream_details: PeDotNetStreamDetail[];
  dotnet_metadata_table: PeDotNetMetadataTable | null;
}

// --- Sub-components ---

function ImportTable({ imports }: { imports: PeImportEntry[] }) {
  const { t } = useTranslation();
  if (imports.length === 0) {
    return <div className="pe-empty">{t('pe.noImports')}</div>;
  }
  // Group by DLL
  const grouped = imports.reduce<Record<string, string[]>>((acc, imp) => {
    if (!acc[imp.dll]) acc[imp.dll] = [];
    acc[imp.dll].push(imp.name);
    return acc;
  }, {});
  return (
    <div className="pe-imports">
      {Object.entries(grouped).map(([dll, funcs]) => (
        <div key={dll} className="pe-import-group">
          <div className="pe-import-dll">{dll} ({funcs.length})</div>
          <ul className="pe-import-funcs">
            {funcs.map((fn, i) => (
              <li key={i} className="pe-import-func">{fn}</li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

function ExportTable({ exports: exportsList }: { exports: PeExportEntry[] }) {
  const { t } = useTranslation();
  if (exportsList.length === 0) {
    return <div className="pe-empty">{t('pe.noExports')}</div>;
  }
  return (
    <table className="pe-table">
      <thead>
        <tr>
          <th>{t('pe.ordinal')}</th>
          <th>{t('common.name')}</th>
          <th>RVA</th>
        </tr>
      </thead>
      <tbody>
        {exportsList.map((exp, i) => (
          <tr key={i}>
            <td>{exp.ordinal}</td>
            <td>{exp.name}</td>
            <td>0x{exp.rva.toString(16).padStart(8, '0')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ResourceTree({ nodes, depth = 0 }: { nodes: PeResourceNode[]; depth?: number }) {
  const { t } = useTranslation();
  if (nodes.length === 0) {
    return <div className="pe-empty">{t('pe.noResources')}</div>;
  }
  return (
    <ul className="pe-resource-tree" style={{ paddingLeft: depth * 20 }}>
      {nodes.map((node, i) => (
        <li key={i} className="pe-resource-node">
          <span className="pe-resource-name">{node.name}</span>
          {node.data_size != null && (
            <span className="pe-resource-size"> ({node.data_size} bytes)</span>
          )}
          {node.children && node.children.length > 0 && (
            <ResourceTree nodes={node.children} depth={depth + 1} />
          )}
        </li>
      ))}
    </ul>
  );
}

function DotNetInfo({ dotnet }: { dotnet: PeDotNetInfo | null }) {
  const { t } = useTranslation();
  if (!dotnet) {
    return <div className="pe-empty">{t('pe.notDotNet')}</div>;
  }
  return (
    <div className="pe-dotnet">
      <table className="pe-table">
        <tbody>
          <tr><td>{t('pe.clrHeader')}</td><td>{t('common.present')}</td></tr>
          <tr><td>CLR RVA</td><td>0x{dotnet.clr_rva.toString(16).padStart(8, '0')}</td></tr>
          <tr><td>{t('pe.clrSize')}</td><td>{dotnet.clr_size} {t('common.bytes')}</td></tr>
        </tbody>
      </table>
    </div>
  );
}

function ManifestView({ manifest }: { manifest: string | null }) {
  const { t } = useTranslation();
  if (!manifest) {
    return <div className="pe-empty">{t('pe.noManifest')}</div>;
  }
  return (
    <pre className="pe-manifest">{manifest}</pre>
  );
}

function VersionInfoView({ versionInfo }: { versionInfo: PeVersionEntry[] }) {
  const { t } = useTranslation();
  if (versionInfo.length === 0) {
    return <div className="pe-empty">{t('pe.noVersionInfo')}</div>;
  }
  return (
    <div className="pe-version-info">
      {versionInfo.map((entry, i) => (
        <table key={i} className="pe-table">
          <tbody>
            {entry.entries.map(([key, value], j) => (
              <tr key={j}>
                <td className="pe-version-key">{key}</td>
                <td className="pe-version-value">{value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}

function OverlayView({ offset, size }: { offset: number; size: number }) {
  const { t } = useTranslation();
  if (size === 0) {
    return <div className="pe-empty">{t('pe.noOverlay')}</div>;
  }
  return (
    <table className="pe-table">
      <tbody>
        <tr><td>{t('common.offset')}</td><td>0x{offset.toString(16).padStart(8, '0')} ({offset})</td></tr>
        <tr><td>{t('common.size')}</td><td>{size} {t('common.bytes')} ({(size / 1024).toFixed(2)} KB)</td></tr>
      </tbody>
    </table>
  );
}

function TlsView({ callbacks }: { callbacks: number[] }) {
  const { t } = useTranslation();
  if (callbacks.length === 0) {
    return <div className="pe-empty">{t('pe.noTls')}</div>;
  }
  return (
    <table className="pe-table">
      <thead>
        <tr><th>{t('pe.tlsRva')}</th></tr>
      </thead>
      <tbody>
        {callbacks.map((rva, i) => (
          <tr key={i}>
            <td>0x{rva.toString(16).padStart(8, '0')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RichHeaderView({ hasRich }: { hasRich: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="pe-rich-header">
      {hasRich ? (
        <span className="pe-rich-present">{t('pe.richPresent')}</span>
      ) : (
        <span className="pe-rich-absent">{t('pe.richAbsent')}</span>
      )}
    </div>
  );
}

function NtHeadersView({ headers }: { headers: PeNtHeaders | null }) {
  const { t } = useTranslation();
  if (!headers) return <div className="pe-empty">{t('pe.noNtHeaders')}</div>;
  const rows: [string, string][] = [
    [t('pe.signature'), `${headers.signature} (0x${headers.signature_val.toString(16).padStart(8, '0')})`],
    [t('common.offset'), `0x${headers.offset.toString(16)}`],
    [t('pe.machine'), headers.file_header_summary.machine],
    [t('pe.sections'), String(headers.number_of_sections)],
    ['TimeDateStamp', `0x${headers.file_header_summary.time_date_stamp.toString(16).padStart(8, '0')}`],
    ['Characteristics', headers.file_header_summary.characteristics],
    [t('pe.optHeaderMagic'), headers.optional_header_summary.magic],
    [t('pe.entryPoint'), `0x${headers.optional_header_summary.entry_point.toString(16)}`],
    [t('pe.imageBase'), headers.optional_header_summary.image_base],
    [t('pe.sectionAlignment'), `0x${headers.optional_header_summary.section_alignment.toString(16)}`],
    [t('pe.fileAlignment'), `0x${headers.optional_header_summary.file_alignment.toString(16)}`],
    [t('pe.sizeOfImage'), `0x${headers.optional_header_summary.size_of_image.toString(16)}`],
    [t('pe.sizeOfHeaders'), `0x${headers.optional_header_summary.size_of_headers.toString(16)}`],
    [t('pe.subsystem'), headers.optional_header_summary.subsystem],
    [t('pe.dataDirectories'), String(headers.number_of_data_directories)],
  ];
  return (
    <table className="pe-table">
      <tbody>
        {rows.map(([k, v], i) => (
          <tr key={i}><td className="pe-field-name">{k}</td><td className="pe-field-value">{v}</td></tr>
        ))}
      </tbody>
    </table>
  );
}

function ResourceStringsView({ entries }: { entries: PeResourceStringEntry[] }) {
  const { t } = useTranslation();
  if (entries.length === 0) return <div className="pe-empty">{t('pe.noResourceStrings')}</div>;
  return (
    <table className="pe-table">
      <thead><tr><th>ID</th><th>{t('common.value')}</th></tr></thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i}>
            <td>{e.id}</td>
            <td>{e.value || '(empty)'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DotNetStreamDetailsView({ details }: { details: PeDotNetStreamDetail[] }) {
  const { t } = useTranslation();
  if (details.length === 0) return <div className="pe-empty">{t('pe.noDotNetStreams')}</div>;
  return (
    <div>
      {details.map((d, i) => (
        <div key={i} className="mb-2">
          <table className="pe-table">
            <tbody>
              <tr><td className="pe-field-name">{t('common.name')}</td><td>{d.name}</td></tr>
              <tr><td className="pe-field-name">{t('common.type')}</td><td>{d.stream_type}</td></tr>
              <tr><td className="pe-field-name">{t('common.offset')}</td><td>0x{d.offset.toString(16)}</td></tr>
              <tr><td className="pe-field-name">{t('common.size')}</td><td>{d.size} {t('common.bytes')}</td></tr>
            </tbody>
          </table>
          {d.hex_preview && (
            <pre className="text-xs mt-1 p-1 bg-muted/30 overflow-auto max-h-32 font-mono">{d.hex_preview}</pre>
          )}
        </div>
      ))}
    </div>
  );
}

function DotNetMetadataTableView({ table }: { table: PeDotNetMetadataTable | null }) {
  const { t } = useTranslation();
  if (!table) return <div className="pe-empty">{t('pe.noDotNetTable')}</div>;
  return (
    <div>
      <h4 className="text-xs font-semibold mb-1">{t('pe.presentTables', { count: table.present_tables.length })}</h4>
      <div className="flex flex-wrap gap-1 mb-2">
        {table.present_tables.map((tbl, i) => (
          <span key={i} className="px-1 py-0.5 text-xs bg-muted rounded">{tbl}</span>
        ))}
      </div>
      <h4 className="text-xs font-semibold mb-1">{t('pe.rowCounts')}</h4>
      <table className="pe-table">
        <thead><tr><th>{t('pe.table')}</th><th>{t('pe.rows')}</th></tr></thead>
        <tbody>
          {table.row_counts.map(([name, count], i) => (
            <tr key={i}><td>{name}</td><td>{count}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PeToolsView({ filePath }: { filePath: string }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const runTool = async (cmd: string, label: string) => {
    if (!confirm(t('pe.confirmModify', { label }))) return;
    setBusy(true);
    setError(null);
    setStatus(null);
    try {
      await invoke(cmd, { path: filePath });
      setStatus(t('pe.toolDone', { label }));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const runDump = async (cmd: string, label: string, saveName: string) => {
    setBusy(true);
    setError(null);
    setStatus(null);
    try {
      const data = await invoke<number[]>(cmd, { path: filePath });
      const bytes = new Uint8Array(data);
      // Trigger download via blob.
      const blob = new Blob([bytes], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = saveName;
      a.click();
      URL.revokeObjectURL(url);
      setStatus(t('pe.dumpDone', { label, count: bytes.length }));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const Btn = ({ cmd, label, variant }: { cmd: string; label: string; variant: 'dump' | 'remove' | 'add' }) => (
    <button
      onClick={() => variant === 'dump' ? runDump(cmd, label, `${label.toLowerCase()}.bin`) : runTool(cmd, label)}
      disabled={busy}
      className={`px-2 py-1 text-xs border rounded ${variant === 'remove' ? 'border-red-500 text-red-500' : variant === 'add' ? 'border-blue-500 text-blue-500' : 'border-border'} hover:bg-muted disabled:opacity-50`}
    >
      {label}
    </button>
  );

  return (
    <div className="space-y-3 p-2">
      <div>
        <h4 className="text-xs font-semibold mb-1">{t('pe.dosStub')}</h4>
        <div className="flex gap-1">
          <Btn cmd="pe_dump_dos_stub" label={t('pe.dump')} variant="dump" />
          <Btn cmd="pe_remove_dos_stub" label={t('pe.remove')} variant="remove" />
          <Btn cmd="pe_add_dos_stub" label={t('pe.add')} variant="add" />
        </div>
      </div>
      <div>
        <h4 className="text-xs font-semibold mb-1">{t('pe.overlay')}</h4>
        <div className="flex gap-1">
          <Btn cmd="pe_dump_overlay" label={t('pe.dump')} variant="dump" />
          <Btn cmd="pe_remove_overlay" label={t('pe.remove')} variant="remove" />
          <Btn cmd="pe_add_overlay" label={t('pe.add')} variant="add" />
        </div>
      </div>
      {busy && <p className="text-xs text-muted-foreground">{t('pe.working')}</p>}
      {status && <p className="text-xs text-green-600">{status}</p>}
      {error && <p className="text-xs text-red-500">{error}</p>}
    </div>
  );
}

function DataDirectoryView({ entries }: { entries: PeDataDirectoryEntry[] }) {
  const { t } = useTranslation();
  if (entries.length === 0) {
    return <div className="pe-empty">{t('pe.noDataDirs')}</div>;
  }
  return (
    <table className="pe-table">
      <thead>
        <tr><th>#</th><th>{t('common.name')}</th><th>RVA</th><th>{t('common.size')}</th></tr>
      </thead>
      <tbody>
        {entries.map((d) => (
          <tr key={d.index}>
            <td>{d.index}</td>
            <td>{d.name}</td>
            <td>0x{d.rva.toString(16).padStart(8, '0')}</td>
            <td>{d.size > 0 ? `0x${d.size.toString(16)}` : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DebugView({ entries }: { entries: PeDebugEntry[] }) {
  const { t } = useTranslation();
  if (entries.length === 0) {
    return <div className="pe-empty">{t('pe.noDebug')}</div>;
  }
  return (
    <table className="pe-table">
      <thead>
        <tr><th>{t('common.type')}</th><th>SizeOfData</th><th>{t('common.address')}</th><th>Pointer</th></tr>
      </thead>
      <tbody>
        {entries.map((d, i) => (
          <tr key={i}>
            <td>{d.debug_type}</td>
            <td>{d.size_of_data}</td>
            <td>0x{d.address_of_raw_data.toString(16).padStart(8, '0')}</td>
            <td>0x{d.pointer_to_raw_data.toString(16).padStart(8, '0')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RelocsView({ blocks }: { blocks: PeRelocBlock[] }) {
  const { t } = useTranslation();
  if (blocks.length === 0) {
    return <div className="pe-empty">{t('pe.noRelocs')}</div>;
  }
  return (
    <table className="pe-table">
      <thead>
        <tr><th>VirtualAddress</th><th>BlockSize</th><th>{t('common.count')}</th></tr>
      </thead>
      <tbody>
        {blocks.map((b, i) => (
          <tr key={i}>
            <td>0x{b.virtual_address.toString(16).padStart(8, '0')}</td>
            <td>{b.block_size}</td>
            <td>{b.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LoadConfigView({ config }: { config: PeLoadConfig | null }) {
  const { t } = useTranslation();
  if (!config) {
    return <div className="pe-empty">{t('pe.noLoadConfig')}</div>;
  }
  return (
    <table className="pe-table">
      <tbody>
        <tr><td>{t('common.size')}</td><td>{config.size}</td></tr>
        <tr><td>SecurityCookie</td><td>0x{config.security_cookie}</td></tr>
        <tr><td>SEHandlerTable</td><td>0x{config.se_handler_table}</td></tr>
        <tr><td>SEHandlerCount</td><td>{config.se_handler_count}</td></tr>
      </tbody>
    </table>
  );
}

function CertificatesView({ certs }: { certs: PeCertificate[] }) {
  const { t } = useTranslation();
  if (certs.length === 0) {
    return <div className="pe-empty">{t('pe.noCerts')}</div>;
  }
  return (
    <table className="pe-table">
      <thead>
        <tr><th>{t('common.type')}</th><th>DataLength</th><th>HasData</th></tr>
      </thead>
      <tbody>
        {certs.map((c, i) => (
          <tr key={i}>
            <td>0x{c.certificate_type.toString(16).padStart(4, '0')}</td>
            <td>{c.data_length}</td>
            <td>{c.has_data ? t('common.yes') : t('common.no')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DosHeaderView({ fields }: { fields: PeDosHeaderField[] }) {
  const { t } = useTranslation();
  if (fields.length === 0) {
    return <div className="pe-empty">{t('pe.noDosHeader')}</div>;
  }
  return (
    <table className="pe-table">
      <thead>
        <tr><th>{t('pe.field')}</th><th>{t('common.value')}</th><th>{t('common.description')}</th></tr>
      </thead>
      <tbody>
        {fields.map((f, i) => (
          <tr key={i}>
            <td>{f.name}</td>
            <td>{f.value}</td>
            <td>{f.description ?? ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DosStubView({ stub }: { stub: PeDosStub | null }) {
  const { t } = useTranslation();
  if (!stub) {
    return <div className="pe-empty">{t('pe.noDosStub')}</div>;
  }
  return (
    <div className="pe-dos-stub">
      <p>{t('common.offset')}: 0x{stub.offset.toString(16)} | {t('common.size')}: {stub.size} {t('common.bytes')}</p>
      <pre className="pe-hex-dump">{stub.hex_dump}</pre>
    </div>
  );
}

function FileHeaderView({ fh }: { fh: PeFileHeader | null }) {
  const { t } = useTranslation();
  if (!fh) {
    return <div className="pe-empty">{t('pe.noFileHeader')}</div>;
  }
  return (
    <table className="pe-table">
      <tbody>
        <tr><td>Machine</td><td>{fh.machine} (0x{fh.machine_val.toString(16).padStart(4, '0')})</td></tr>
        <tr><td>NumberOfSections</td><td>{fh.number_of_sections}</td></tr>
        <tr><td>TimeDateStamp</td><td>0x{fh.time_date_stamp.toString(16).padStart(8, '0')}</td></tr>
        <tr><td>PointerToSymbolTable</td><td>0x{fh.pointer_to_symbol_table.toString(16).padStart(8, '0')}</td></tr>
        <tr><td>NumberOfSymbols</td><td>{fh.number_of_symbols}</td></tr>
        <tr><td>SizeOfOptionalHeader</td><td>{fh.size_of_optional_header}</td></tr>
        <tr><td>Characteristics</td><td>{fh.characteristics} (0x{fh.characteristics_val.toString(16).padStart(4, '0')})</td></tr>
      </tbody>
    </table>
  );
}

function OptionalHeaderView({ oh }: { oh: PeOptionalHeader | null }) {
  const { t } = useTranslation();
  if (!oh) {
    return <div className="pe-empty">{t('pe.noOptHeader')}</div>;
  }
  return (
    <table className="pe-table">
      <tbody>
        <tr><td>Magic</td><td>{oh.magic_str} (0x{oh.magic.toString(16).padStart(4, '0')})</td></tr>
        <tr><td>LinkerVersion</td><td>{oh.major_linker_version}.{oh.minor_linker_version}</td></tr>
        <tr><td>SizeOfCode</td><td>0x{oh.size_of_code.toString(16)}</td></tr>
        <tr><td>SizeOfInitializedData</td><td>0x{oh.size_of_initialized_data.toString(16)}</td></tr>
        <tr><td>SizeOfUninitializedData</td><td>0x{oh.size_of_uninitialized_data.toString(16)}</td></tr>
        <tr><td>AddressOfEntryPoint</td><td>0x{oh.address_of_entry_point.toString(16).padStart(8, '0')}</td></tr>
        <tr><td>BaseOfCode</td><td>0x{oh.base_of_code.toString(16).padStart(8, '0')}</td></tr>
        {oh.base_of_data !== null && <tr><td>BaseOfData</td><td>0x{oh.base_of_data.toString(16).padStart(8, '0')}</td></tr>}
        <tr><td>ImageBase</td><td>0x{oh.image_base}</td></tr>
        <tr><td>SectionAlignment</td><td>0x{oh.section_alignment.toString(16)}</td></tr>
        <tr><td>FileAlignment</td><td>0x{oh.file_alignment.toString(16)}</td></tr>
        <tr><td>OperatingSystemVersion</td><td>{oh.major_operating_system_version}.{oh.minor_operating_system_version}</td></tr>
        <tr><td>ImageVersion</td><td>{oh.major_image_version}.{oh.minor_image_version}</td></tr>
        <tr><td>SubsystemVersion</td><td>{oh.major_subsystem_version}.{oh.minor_subsystem_version}</td></tr>
        <tr><td>Win32VersionValue</td><td>0x{oh.win32_version_value.toString(16)}</td></tr>
        <tr><td>SizeOfImage</td><td>0x{oh.size_of_image.toString(16)}</td></tr>
        <tr><td>SizeOfHeaders</td><td>0x{oh.size_of_headers.toString(16)}</td></tr>
        <tr><td>CheckSum</td><td>0x{oh.check_sum.toString(16).padStart(8, '0')}</td></tr>
        <tr><td>Subsystem</td><td>{oh.subsystem} (0x{oh.subsystem_val.toString(16).padStart(4, '0')})</td></tr>
        <tr><td>DllCharacteristics</td><td>{oh.dll_characteristics} (0x{oh.dll_characteristics_val.toString(16).padStart(4, '0')})</td></tr>
        <tr><td>SizeOfStackReserve</td><td>0x{oh.size_of_stack_reserve}</td></tr>
        <tr><td>SizeOfStackCommit</td><td>0x{oh.size_of_stack_commit}</td></tr>
        <tr><td>SizeOfHeapReserve</td><td>0x{oh.size_of_heap_reserve}</td></tr>
        <tr><td>SizeOfHeapCommit</td><td>0x{oh.size_of_heap_commit}</td></tr>
        <tr><td>LoaderFlags</td><td>0x{oh.loader_flags.toString(16)}</td></tr>
        <tr><td>NumberOfRvaAndSizes</td><td>{oh.number_of_rva_and_sizes}</td></tr>
      </tbody>
    </table>
  );
}

function SectionsDetailView({ sections }: { sections: PeSectionDetail[] }) {
  const { t } = useTranslation();
  if (sections.length === 0) {
    return <div className="pe-empty">{t('pe.noSections')}</div>;
  }
  return (
    <table className="pe-table">
      <thead>
        <tr><th>{t('common.name')}</th><th>VirtAddr</th><th>VirtSize</th><th>RawAddr</th><th>RawSize</th><th>{t('pe.entropy')}</th><th>Characteristics</th></tr>
      </thead>
      <tbody>
        {sections.map((s, i) => (
          <tr key={i}>
            <td>{s.name}</td>
            <td>0x{s.virtual_address.toString(16).padStart(8, '0')}</td>
            <td>0x{s.virtual_size.toString(16)}</td>
            <td>
              <button
                className="hover:underline text-accent-blue"
                title={t('common.followInHex')}
                onClick={() => followInHex(s.pointer_to_raw_data)}
              >
                0x{s.pointer_to_raw_data.toString(16).padStart(8, '0')}
              </button>
            </td>
            <td>0x{s.size_of_raw_data.toString(16)}</td>
            <td>{s.entropy !== null ? s.entropy.toFixed(4) : '—'}</td>
            <td>{s.characteristics}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SectionsInfoView({ stats }: { stats: PeSectionStats | null }) {
  const { t } = useTranslation();
  if (!stats) {
    return <div className="pe-empty">{t('pe.noSectionStats')}</div>;
  }
  return (
    <table className="pe-table">
      <tbody>
        <tr><td>{t('pe.totalSections')}</td><td>{stats.total_sections}</td></tr>
        <tr><td>{t('pe.totalVirtualSize')}</td><td>{stats.total_virtual_size} ({(stats.total_virtual_size / 1024).toFixed(2)} KB)</td></tr>
        <tr><td>{t('pe.totalRawSize')}</td><td>{stats.total_raw_size} ({(stats.total_raw_size / 1024).toFixed(2)} KB)</td></tr>
        <tr><td>{t('pe.minEntropy')}</td><td>{stats.min_entropy !== null ? stats.min_entropy.toFixed(4) : '—'}</td></tr>
        <tr><td>{t('pe.maxEntropy')}</td><td>{stats.max_entropy !== null ? stats.max_entropy.toFixed(4) : '—'}</td></tr>
        <tr><td>{t('pe.avgEntropy')}</td><td>{stats.avg_entropy !== null ? stats.avg_entropy.toFixed(4) : '—'}</td></tr>
      </tbody>
    </table>
  );
}

function ImportInfoView({ info }: { info: PeImportInfo | null }) {
  const { t } = useTranslation();
  if (!info) {
    return <div className="pe-empty">{t('pe.noImportInfo')}</div>;
  }
  return (
    <div>
      <table className="pe-table">
        <tbody>
          <tr><td>{t('pe.totalDlls')}</td><td>{info.total_dlls}</td></tr>
          <tr><td>{t('pe.totalFunctions')}</td><td>{info.total_functions}</td></tr>
        </tbody>
      </table>
      <h4>{t('pe.dllSummary')}</h4>
      <table className="pe-table">
        <thead><tr><th>{t('pe.dllName')}</th><th>{t('pe.functionCount')}</th></tr></thead>
        <tbody>
          {info.dlls.map((d, i) => (
            <tr key={i}><td>{d.dll_name}</td><td>{d.function_count}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ExceptionsView({ entries }: { entries: PeExceptionEntry[] }) {
  const { t } = useTranslation();
  if (entries.length === 0) {
    return <div className="pe-empty">{t('pe.noExceptions')}</div>;
  }
  return (
    <table className="pe-table">
      <thead><tr><th>BeginAddress</th><th>EndAddress</th><th>UnwindData</th></tr></thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i}>
            <td>0x{e.begin_address.toString(16).padStart(8, '0')}</td>
            <td>0x{e.end_address.toString(16).padStart(8, '0')}</td>
            <td>0x{e.unwind_info_address.toString(16).padStart(8, '0')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function BoundImportsView({ entries }: { entries: PeBoundImportEntry[] }) {
  const { t } = useTranslation();
  if (entries.length === 0) {
    return <div className="pe-empty">{t('pe.noBoundImports')}</div>;
  }
  return (
    <table className="pe-table">
      <thead><tr><th>{t('pe.module')}</th><th>TimeDateStamp</th><th>ForwarderRefs</th></tr></thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i}>
            <td>{e.module_name}</td>
            <td>0x{e.time_date_stamp.toString(16).padStart(8, '0')}</td>
            <td>{e.number_of_module_forwarder_refs}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DelayImportsView({ entries }: { entries: PeDelayImportEntry[] }) {
  const { t } = useTranslation();
  if (entries.length === 0) {
    return <div className="pe-empty">{t('pe.noDelayImports')}</div>;
  }
  return (
    <table className="pe-table">
      <thead><tr><th>DLL</th><th>Attributes</th><th>TimeDateStamp</th></tr></thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i}>
            <td>{e.dll_name}</td>
            <td>0x{e.attributes.toString(16)}</td>
            <td>0x{e.time_date_stamp.toString(16).padStart(8, '0')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DotNetMetadataView({ meta }: { meta: PeDotNetMetadata | null }) {
  const { t } = useTranslation();
  if (!meta) {
    return <div className="pe-empty">{t('pe.noDotNetMeta')}</div>;
  }
  return (
    <div>
      <table className="pe-table">
        <tbody>
          <tr><td>{t('pe.runtimeVersion')}</td><td>{meta.runtime_version}</td></tr>
          <tr><td>{t('pe.metadataRva')}</td><td>0x{meta.metadata_rva.toString(16).padStart(8, '0')}</td></tr>
          <tr><td>{t('pe.metadataSize')}</td><td>{meta.metadata_size}</td></tr>
          <tr><td>{t('common.flags')}</td><td>0x{meta.flags.toString(16)}</td></tr>
          <tr><td>{t('pe.entryPointToken')}</td><td>0x{meta.entry_point_token.toString(16)}</td></tr>
        </tbody>
      </table>
      <h4>{t('pe.streams')}</h4>
      <table className="pe-table">
        <thead><tr><th>{t('common.name')}</th><th>{t('common.offset')}</th><th>{t('common.size')}</th></tr></thead>
        <tbody>
          {meta.streams.map((s, i) => (
            <tr key={i}>
              <td>{s.name}</td>
              <td>0x{s.offset.toString(16)}</td>
              <td>{s.size}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// --- Main component ---

type SubTab =
  | 'dosheader'
  | 'dosstub'
  | 'fileheader'
  | 'optionalheader'
  | 'sections'
  | 'sectionsinfo'
  | 'imports'
  | 'importinfo'
  | 'exports'
  | 'resources'
  | 'directories'
  | 'debug'
  | 'relocs'
  | 'exceptions'
  | 'loadconfig'
  | 'boundimports'
  | 'delayimports'
  | 'certificates'
  | 'dotnet'
  | 'dotnetmeta'
  | 'dotnetstream'
  | 'dotnettable'
  | 'manifest'
  | 'version'
  | 'overlay'
  | 'tls'
  | 'rich'
  | 'ntheaders'
  | 'resourcestrings'
  | 'tools';

const SUB_TABS: { key: SubTab; labelKey: string }[] = [
  { key: 'dosheader', labelKey: 'pe.tabDosHeader' },
  { key: 'dosstub', labelKey: 'pe.tabDosStub' },
  { key: 'fileheader', labelKey: 'pe.tabFileHeader' },
  { key: 'optionalheader', labelKey: 'pe.tabOptionalHeader' },
  { key: 'sections', labelKey: 'pe.tabSections' },
  { key: 'sectionsinfo', labelKey: 'pe.tabSectionsInfo' },
  { key: 'imports', labelKey: 'pe.tabImports' },
  { key: 'importinfo', labelKey: 'pe.tabImportInfo' },
  { key: 'exports', labelKey: 'pe.tabExports' },
  { key: 'resources', labelKey: 'pe.tabResources' },
  { key: 'directories', labelKey: 'pe.tabDirectories' },
  { key: 'debug', labelKey: 'pe.tabDebug' },
  { key: 'relocs', labelKey: 'pe.tabRelocs' },
  { key: 'exceptions', labelKey: 'pe.tabExceptions' },
  { key: 'loadconfig', labelKey: 'pe.tabLoadConfig' },
  { key: 'boundimports', labelKey: 'pe.tabBoundImports' },
  { key: 'delayimports', labelKey: 'pe.tabDelayImports' },
  { key: 'certificates', labelKey: 'pe.tabCertificates' },
  { key: 'dotnet', labelKey: 'pe.tabDotNet' },
  { key: 'dotnetmeta', labelKey: 'pe.tabDotNetMeta' },
  { key: 'dotnetstream', labelKey: 'pe.tabDotNetStreams' },
  { key: 'dotnettable', labelKey: 'pe.tabDotNetTables' },
  { key: 'manifest', labelKey: 'pe.tabManifest' },
  { key: 'version', labelKey: 'pe.tabVersionInfo' },
  { key: 'overlay', labelKey: 'pe.tabOverlay' },
  { key: 'tls', labelKey: 'pe.tabTls' },
  { key: 'rich', labelKey: 'pe.tabRichHeader' },
  { key: 'ntheaders', labelKey: 'pe.tabNtHeaders' },
  { key: 'resourcestrings', labelKey: 'pe.tabResourceStrings' },
  { key: 'tools', labelKey: 'pe.tabTools' },
];

interface PeViewPanelProps {
  filePath: string | null;
}

export default function PeViewPanel({ filePath }: PeViewPanelProps) {
  const { t } = useTranslation();
  const [peView, setPeView] = useState<PeView | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<SubTab>('imports');

  const fetchPeView = useCallback(async () => {
    if (!filePath) {
      setPeView(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<Option<PeView>>('get_pe_view', { path: filePath });
      setPeView(result ?? null);
    } catch (e) {
      setError(String(e));
      setPeView(null);
    } finally {
      setLoading(false);
    }
  }, [filePath]);

  useEffect(() => {
    fetchPeView();
  }, [fetchPeView]);

  if (!filePath) {
    return <div className="pe-view-panel pe-empty">{t('common.noFileSelected')}</div>;
  }

  if (loading) {
    return <div className="pe-view-panel">{t('pe.loading')}</div>;
  }

  if (error) {
    return <div className="pe-view-panel pe-error">{t('common.error', { error })}</div>;
  }

  if (!peView) {
    return <div className="pe-view-panel pe-empty">{t('pe.notPe')}</div>;
  }

  return (
    <div className="pe-view-panel">
      <div className="pe-sub-tabs">
        {SUB_TABS.map((tab) => (
          <button
            key={tab.key}
            className={`pe-sub-tab ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {t(tab.labelKey)}
          </button>
        ))}
      </div>
      <div className="pe-sub-content">
        {activeTab === 'dosheader' && <DosHeaderView fields={peView.dos_header} />}
        {activeTab === 'dosstub' && <DosStubView stub={peView.dos_stub} />}
        {activeTab === 'fileheader' && <FileHeaderView fh={peView.file_header} />}
        {activeTab === 'optionalheader' && <OptionalHeaderView oh={peView.optional_header} />}
        {activeTab === 'sections' && <SectionsDetailView sections={peView.section_details} />}
        {activeTab === 'sectionsinfo' && <SectionsInfoView stats={peView.section_stats} />}
        {activeTab === 'imports' && <ImportTable imports={peView.imports} />}
        {activeTab === 'importinfo' && <ImportInfoView info={peView.import_info} />}
        {activeTab === 'exports' && <ExportTable exports={peView.exports} />}
        {activeTab === 'resources' && <ResourceTree nodes={peView.resources} />}
        {activeTab === 'directories' && <DataDirectoryView entries={peView.data_directories} />}
        {activeTab === 'debug' && <DebugView entries={peView.debug_entries} />}
        {activeTab === 'relocs' && <RelocsView blocks={peView.reloc_blocks} />}
        {activeTab === 'exceptions' && <ExceptionsView entries={peView.exceptions} />}
        {activeTab === 'loadconfig' && <LoadConfigView config={peView.load_config} />}
        {activeTab === 'boundimports' && <BoundImportsView entries={peView.bound_imports} />}
        {activeTab === 'delayimports' && <DelayImportsView entries={peView.delay_imports} />}
        {activeTab === 'certificates' && <CertificatesView certs={peView.certificates} />}
        {activeTab === 'dotnet' && <DotNetInfo dotnet={peView.dotnet} />}
        {activeTab === 'dotnetmeta' && <DotNetMetadataView meta={peView.dotnet_metadata} />}
        {activeTab === 'manifest' && <ManifestView manifest={peView.manifest} />}
        {activeTab === 'version' && <VersionInfoView versionInfo={peView.version_info} />}
        {activeTab === 'overlay' && <OverlayView offset={peView.overlay_offset} size={peView.overlay_size} />}
        {activeTab === 'tls' && <TlsView callbacks={peView.tls_callbacks} />}
        {activeTab === 'rich' && <RichHeaderView hasRich={peView.has_rich_header} />}
        {activeTab === 'ntheaders' && <NtHeadersView headers={peView.nt_headers} />}
        {activeTab === 'resourcestrings' && <ResourceStringsView entries={peView.resource_strings} />}
        {activeTab === 'dotnetstream' && <DotNetStreamDetailsView details={peView.dotnet_stream_details} />}
        {activeTab === 'dotnettable' && <DotNetMetadataTableView table={peView.dotnet_metadata_table} />}
        {activeTab === 'tools' && filePath && <PeToolsView filePath={filePath} />}
      </div>
    </div>
  );
}

// Helper type for Option<T> from Rust
type Option<T> = T | null;
