import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useTranslation } from 'react-i18next';

/**
 * DEX/MSDOS/NE/LE dedicated views.
 * Mirrors upstream format widgets for less common executable formats.
 */

interface DexView {
  magic: string;
  version: string;
  checksum: number;
  signature: string;
  file_size: number;
  header_size: number;
  endian_tag: number;
  link_size: number;
  link_off: number;
  map_off: number;
  string_ids_size: number;
  string_ids_off: number;
  type_ids_size: number;
  type_ids_off: number;
  proto_ids_size: number;
  proto_ids_off: number;
  field_ids_size: number;
  field_ids_off: number;
  method_ids_size: number;
  method_ids_off: number;
  class_defs_size: number;
  class_defs_off: number;
  data_size: number;
  data_off: number;
}

interface MsdosView {
  magic: string;
  e_cblp: number;
  e_cp: number;
  e_crlc: number;
  e_cparhdr: number;
  e_minalloc: number;
  e_maxalloc: number;
  e_ss: number;
  e_sp: number;
  e_csum: number;
  e_ip: number;
  e_cs: number;
  e_lfarlc: number;
  e_ovno: number;
  e_oemid: number;
  e_oeminfo: number;
  e_lfanew: number;
  has_pe: boolean;
}

interface NeView {
  magic: string;
  linker_version: number;
  linker_revision: number;
  entry_table_offset: number;
  entry_table_length: number;
  file_load_size: number;
  non_resident_name_offset: number;
  non_resident_name_length: number;
  module_description_offset: number;
  module_description_length: number;
  segment_count: number;
  module_refs_count: number;
  movable_segments: number;
  alignment_shift: number;
  resource_segments: number;
  target_os: number;
  os_version: number;
  windows_version: number;
}

interface LeView {
  magic: string;
  byte_order: number;
  word_order: number;
  exe_format_level: number;
  cpu_type: number;
  os_type: number;
  module_version: number;
  module_flags: number;
  module_page_count: number;
  init_object_count: number;
  object_count: number;
  object_page_map_offset: number;
  object_iterated_data_offset: number;
  resource_table_offset: number;
  resource_table_count: number;
  resident_name_table_offset: number;
  entry_table_offset: number;
  module_directives_offset: number;
  module_directives_count: number;
  fixup_page_table_offset: number;
  fixup_record_table_offset: number;
  imported_modules_name_table_offset: number;
  imported_modules_count: number;
}

type MiscFormat = 'dex' | 'msdos' | 'ne' | 'le';

function KeyValueTable({ rows }: { rows: [string, string][] }) {
  return (
    <div className="border border-border rounded">
      <table className="w-full text-xs">
        <tbody>
          {rows.map(([k, v], i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono text-muted-foreground">{k}</td>
              <td className="px-2 py-0.5 font-mono break-all">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface DexDeepView {
  strings: string[];
  types: string[];
  protos: { shorty: string; return_type: string; parameters: string[] }[];
  fields: { class: string; field_type: string; name: string }[];
  methods: { class: string; name: string; proto: string }[];
  class_defs: { class: string; access_flags: number; superclass: string; source_file: string }[];
  map_items: { item_type: number; type_name: string; size: number; offset: number }[];
  truncated: boolean;
}

type DexTab = 'strings' | 'types' | 'protos' | 'fields' | 'methods' | 'classes' | 'map';

const MAX_ROWS = 5000;

/** Generic capped table renderer for DEX deep views. */
function DexTable({ headers, rows, truncated }: { headers: string[]; rows: string[][]; truncated?: boolean }) {
  const { t } = useTranslation();
  const shown = rows.slice(0, MAX_ROWS);
  return (
    <div className="border border-border rounded text-xs overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="text-left border-b border-border">
            <th className="px-2 py-0.5 font-mono text-muted-foreground">#</th>
            {headers.map((h) => (
              <th key={h} className="px-2 py-0.5 font-mono text-muted-foreground">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {shown.map((r, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono text-muted-foreground">{i}</td>
              {r.map((c, j) => (
                <td key={j} className="px-2 py-0.5 font-mono break-all">{c}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {(truncated || rows.length > MAX_ROWS) && (
        <p className="px-2 py-1 text-muted-foreground">
          {t('misc.showing', { shown: shown.length, total: rows.length })}{truncated ? t('misc.parserTruncated') : ''}
        </p>
      )}
    </div>
  );
}

/** Deep DEX tables panel (strings/types/protos/fields/methods/classes/map),
 *  mirroring upstream DEX widget sub-views. */
function DexDeepPanel({ filePath }: { filePath: string }) {
  const { t } = useTranslation();
  const [deep, setDeep] = useState<DexDeepView | null>(null);
  const [tab, setTab] = useState<DexTab>('strings');
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    invoke<DexDeepView | null>('get_dex_deep_view', { path: filePath })
      .then(setDeep)
      .catch((e) => setErr(String(e)));
  }, [filePath]);

  if (err) return <p className="text-xs text-red-500">{err}</p>;
  if (!deep) return null;

  const TABS: { key: DexTab; label: string; count: number }[] = [
    { key: 'strings', label: t('misc.tabStrings'), count: deep.strings.length },
    { key: 'types', label: t('misc.tabTypes'), count: deep.types.length },
    { key: 'protos', label: t('misc.tabProtos'), count: deep.protos.length },
    { key: 'fields', label: t('misc.tabFields'), count: deep.fields.length },
    { key: 'methods', label: t('misc.tabMethods'), count: deep.methods.length },
    { key: 'classes', label: t('misc.tabClasses'), count: deep.class_defs.length },
    { key: 'map', label: t('misc.tabMap'), count: deep.map_items.length },
  ];

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1 flex-wrap">
        {TABS.map((tb) => (
          <button
            key={tb.key}
            onClick={() => setTab(tb.key)}
            className={`px-2 py-0.5 text-xs border border-border rounded ${
              tab === tb.key ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
            }`}
          >
            {tb.label} ({tb.count})
          </button>
        ))}
      </div>
      {tab === 'strings' && <DexTable headers={[t('common.value')]} rows={deep.strings.map((s) => [s])} truncated={deep.truncated} />}
      {tab === 'types' && <DexTable headers={[t('misc.descriptor')]} rows={deep.types.map((x) => [x])} truncated={deep.truncated} />}
      {tab === 'protos' && (
        <DexTable
          headers={[t('misc.shorty'), t('misc.return'), t('misc.parameters')]}
          rows={deep.protos.map((p) => [p.shorty, p.return_type, p.parameters.join(' ')])}
          truncated={deep.truncated}
        />
      )}
      {tab === 'fields' && (
        <DexTable
          headers={[t('misc.class'), t('common.type'), t('common.name')]}
          rows={deep.fields.map((f) => [f.class, f.field_type, f.name])}
          truncated={deep.truncated}
        />
      )}
      {tab === 'methods' && (
        <DexTable
          headers={[t('misc.class'), t('common.name'), t('misc.proto')]}
          rows={deep.methods.map((m) => [m.class, m.name, m.proto])}
          truncated={deep.truncated}
        />
      )}
      {tab === 'classes' && (
        <DexTable
          headers={[t('misc.class'), t('misc.access'), t('misc.superclass'), t('misc.source')]}
          rows={deep.class_defs.map((c) => [
            c.class,
            `0x${c.access_flags.toString(16)}`,
            c.superclass,
            c.source_file,
          ])}
          truncated={deep.truncated}
        />
      )}
      {tab === 'map' && (
        <DexTable
          headers={[t('common.type'), t('common.name'), t('common.size'), t('common.offset')]}
          rows={deep.map_items.map((m) => [
            `0x${m.item_type.toString(16).padStart(4, '0')}`,
            m.type_name,
            String(m.size),
            `0x${m.offset.toString(16)}`,
          ])}
        />
      )}
    </div>
  );
}

function DexViewPanel({ view }: { view: DexView }) {
  const { t } = useTranslation();
  return (
    <KeyValueTable rows={[
      [t('misc.magic'), view.magic],
      [t('common.version'), view.version],
      [t('misc.checksum'), `0x${view.checksum.toString(16)}`],
      [t('misc.signature'), view.signature],
      [t('misc.fileSize'), String(view.file_size)],
      [t('misc.headerSize'), `0x${view.header_size.toString(16)}`],
      [t('misc.endianTag'), `0x${view.endian_tag.toString(16)}`],
      [t('misc.linkSize'), String(view.link_size)],
      [t('misc.linkOffset'), `0x${view.link_off.toString(16)}`],
      [t('misc.mapOffset'), `0x${view.map_off.toString(16)}`],
      [t('misc.stringIds'), `${view.string_ids_size} @ 0x${view.string_ids_off.toString(16)}`],
      [t('misc.typeIds'), `${view.type_ids_size} @ 0x${view.type_ids_off.toString(16)}`],
      [t('misc.protoIds'), `${view.proto_ids_size} @ 0x${view.proto_ids_off.toString(16)}`],
      [t('misc.fieldIds'), `${view.field_ids_size} @ 0x${view.field_ids_off.toString(16)}`],
      [t('misc.methodIds'), `${view.method_ids_size} @ 0x${view.method_ids_off.toString(16)}`],
      [t('misc.classDefs'), `${view.class_defs_size} @ 0x${view.class_defs_off.toString(16)}`],
      [t('misc.data'), `${view.data_size} @ 0x${view.data_off.toString(16)}`],
    ]} />
  );
}

function MsdosViewPanel({ view }: { view: MsdosView }) {
  const { t } = useTranslation();
  return (
    <KeyValueTable rows={[
      [t('misc.magic'), view.magic],
      ['e_cblp', `0x${view.e_cblp.toString(16)}`],
      ['e_cp', `0x${view.e_cp.toString(16)}`],
      ['e_crlc', `0x${view.e_crlc.toString(16)}`],
      ['e_cparhdr', `0x${view.e_cparhdr.toString(16)}`],
      ['e_minalloc', `0x${view.e_minalloc.toString(16)}`],
      ['e_maxalloc', `0x${view.e_maxalloc.toString(16)}`],
      ['e_ss', `0x${view.e_ss.toString(16)}`],
      ['e_sp', `0x${view.e_sp.toString(16)}`],
      ['e_csum', `0x${view.e_csum.toString(16)}`],
      ['e_ip', `0x${view.e_ip.toString(16)}`],
      ['e_cs', `0x${view.e_cs.toString(16)}`],
      ['e_lfarlc', `0x${view.e_lfarlc.toString(16)}`],
      ['e_ovno', `0x${view.e_ovno.toString(16)}`],
      ['e_oemid', `0x${view.e_oemid.toString(16)}`],
      ['e_oeminfo', `0x${view.e_oeminfo.toString(16)}`],
      ['e_lfanew', `0x${view.e_lfanew.toString(16)}`],
      [t('misc.hasPe'), view.has_pe ? t('common.yes') : t('common.no')],
    ]} />
  );
}

function NeViewPanel({ view }: { view: NeView }) {
  const { t } = useTranslation();
  const osName = { 1: 'DOS', 2: 'Windows', 3: 'OS/2', 4: 'Windows 386' }[view.target_os] ?? `0x${view.target_os.toString(16)}`;
  return (
    <KeyValueTable rows={[
      [t('misc.magic'), view.magic],
      [t('misc.linkerVersion'), `${view.linker_version}.${view.linker_revision}`],
      [t('misc.entryTable'), `${view.entry_table_length} @ 0x${view.entry_table_offset.toString(16)}`],
      [t('misc.fileLoadSize'), String(view.file_load_size)],
      [t('misc.nonResidentNames'), `${view.non_resident_name_length} @ 0x${view.non_resident_name_offset.toString(16)}`],
      [t('misc.moduleDescription'), `${view.module_description_length} @ 0x${view.module_description_offset.toString(16)}`],
      [t('misc.segments'), String(view.segment_count)],
      [t('misc.moduleRefs'), String(view.module_refs_count)],
      [t('misc.movableSegments'), String(view.movable_segments)],
      [t('misc.alignmentShift'), String(view.alignment_shift)],
      [t('misc.resourceSegments'), String(view.resource_segments)],
      [t('misc.targetOs'), osName],
      [t('misc.osVersion'), `0x${view.os_version.toString(16)}`],
      [t('misc.windowsVersion'), `0x${view.windows_version.toString(16)}`],
    ]} />
  );
}

function LeViewPanel({ view }: { view: LeView }) {
  const { t } = useTranslation();
  const cpuName = { 1: '80286', 2: '80386', 3: '80486' }[view.cpu_type] ?? `0x${view.cpu_type.toString(16)}`;
  const osName = { 1: 'OS/2', 2: 'Windows', 3: 'DOS 4.x', 4: 'Windows 386' }[view.os_type] ?? `0x${view.os_type.toString(16)}`;
  return (
    <KeyValueTable rows={[
      [t('misc.magic'), view.magic],
      [t('misc.byteOrder'), view.byte_order === 0 ? t('misc.littleEndian') : t('misc.bigEndian')],
      [t('misc.wordOrder'), view.word_order === 0 ? t('misc.littleEndian') : t('misc.bigEndian')],
      [t('misc.exeFormatLevel'), `0x${view.exe_format_level.toString(16)}`],
      [t('misc.cpuType'), cpuName],
      [t('misc.osType'), osName],
      [t('misc.moduleVersion'), `0x${view.module_version.toString(16)}`],
      [t('misc.moduleFlags'), `0x${view.module_flags.toString(16)}`],
      [t('misc.modulePages'), String(view.module_page_count)],
      [t('misc.initObjects'), String(view.init_object_count)],
      [t('misc.objects'), String(view.object_count)],
      [t('misc.objectPageMap'), `0x${view.object_page_map_offset.toString(16)}`],
      [t('misc.iteratedData'), `0x${view.object_iterated_data_offset.toString(16)}`],
      [t('misc.resourceTable'), `${view.resource_table_count} @ 0x${view.resource_table_offset.toString(16)}`],
      [t('misc.residentNames'), `0x${view.resident_name_table_offset.toString(16)}`],
      [t('misc.entryTable'), `0x${view.entry_table_offset.toString(16)}`],
      [t('misc.moduleDirectives'), `${view.module_directives_count} @ 0x${view.module_directives_offset.toString(16)}`],
      [t('misc.fixupPageTable'), `0x${view.fixup_page_table_offset.toString(16)}`],
      [t('misc.fixupRecordTable'), `0x${view.fixup_record_table_offset.toString(16)}`],
      [t('misc.importedModules'), `${view.imported_modules_count} @ 0x${view.imported_modules_name_table_offset.toString(16)}`],
    ]} />
  );
}

export default function MiscViewPanel({ filePath }: { filePath: string | null }) {
  const { t } = useTranslation();
  const [format, setFormat] = useState<MiscFormat>('dex');
  const [data, setData] = useState<DexView | MsdosView | NeView | LeView | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchView = useCallback(async () => {
    if (!filePath) {
      setData(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const cmd = `get_${format}_view` as const;
      const result = await invoke<DexView | MsdosView | NeView | LeView | null>(cmd, { path: filePath });
      setData(result);
    } catch (e) {
      setError(String(e));
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [filePath, format]);

  useEffect(() => {
    fetchView();
  }, [fetchView]);

  if (!filePath) return null;
  if (loading) return <p className="text-xs text-muted-foreground p-2">{t('misc.loadingView', { format: format.toUpperCase() })}</p>;
  if (error) return <p className="text-xs text-red-500 p-2">{t('common.error', { error })}</p>;

  const FORMATS: { key: MiscFormat; label: string }[] = [
    { key: 'dex', label: 'DEX' },
    { key: 'msdos', label: 'MSDOS' },
    { key: 'ne', label: 'NE' },
    { key: 'le', label: 'LE' },
  ];

  return (
    <div className="space-y-2 p-2">
      <div className="flex items-center gap-1 flex-wrap">
        {FORMATS.map((f) => (
          <button
            key={f.key}
            onClick={() => setFormat(f.key)}
            className={`px-2 py-1 text-xs border border-border rounded ${
              format === f.key ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>
      {!data && <p className="text-xs text-muted-foreground">{t('misc.notFormat', { format: format.toUpperCase() })}</p>}
      {data && format === 'dex' && (
        <>
          <DexViewPanel view={data as DexView} />
          <DexDeepPanel filePath={filePath} />
        </>
      )}
      {data && format === 'msdos' && <MsdosViewPanel view={data as MsdosView} />}
      {data && format === 'ne' && <NeViewPanel view={data as NeView} />}
      {data && format === 'le' && <LeViewPanel view={data as LeView} />}
    </div>
  );
}
