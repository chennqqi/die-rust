import { useEffect, useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';

/**
 * Mach-O-specific views: header, load commands, segments, sections,
 * and libraries.
 *
 * Mirrors upstream FormatWidgets/MACH/machwidget.cpp sub-views.
 */

interface MachLoadCommand {
  cmd: string;
  cmd_val: number;
  cmdsize: number;
  info: string;
}

interface MachSegment {
  name: string;
  vmaddr: string;
  vmsize: string;
  fileoff: string;
  filesize: string;
  maxprot: string;
  initprot: string;
  nsects: number;
  flags: number;
}

interface MachSection {
  sectname: string;
  segname: string;
  addr: string;
  size: string;
  offset: number;
  align: number;
  reloff: number;
  nreloc: number;
  flags: number;
}

interface MachLibrary {
  name: string;
  current_version: number;
  compatibility_version: number;
}

interface MachUuid { uuid: string; }
interface MachSymtab { symoff: number; nsyms: number; stroff: number; strsize: number; }
interface MachDysymtab {
  ilocalsym: number; nlocalsym: number; iextdefsym: number; nextdefsym: number;
  iundefsym: number; nundefsym: number; tocoff: number; ntoc: number;
  modtaboff: number; nmodtab: number; extrefsymoff: number; nextrefsyms: number;
  indirectsymoff: number; nindirectsyms: number; extreloff: number; nextrel: number;
  locreloff: number; nlocrel: number;
}
interface MachDyldInfo {
  rebase_off: number; rebase_size: number; bind_off: number; bind_size: number;
  weak_bind_off: number; weak_bind_size: number; lazy_bind_off: number; lazy_bind_size: number;
  export_off: number; export_size: number;
}
interface MachVersionMin { platform: string; version: string; sdk: string; }
interface MachBuildVersion { platform: string; minos: string; sdk: string; ntools: number; }
interface MachRpath { path: string; }
interface MachSourceVersion { version: string; }
interface MachDylinker { name: string; }
interface MachLinkeditData { cmd: string; dataoff: number; datasize: number; }
interface MachEncryptionInfo { cryptoff: number; cryptsize: number; cryptid: number; }
interface MachEntryPoint { entryoff: string; stacksize: string; }

interface MachView {
  load_commands: MachLoadCommand[];
  segments: MachSegment[];
  sections: MachSection[];
  libraries: MachLibrary[];
  is64: boolean;
  magic: number;
  cputype: string;
  cpusubtype: number;
  filetype: string;
  ncmds: number;
  sizeofcmds: number;
  entry: string | null;
  uuid: MachUuid | null;
  symtab: MachSymtab | null;
  dysymtab: MachDysymtab | null;
  dyld_info: MachDyldInfo | null;
  version_min: MachVersionMin | null;
  build_version: MachBuildVersion | null;
  rpaths: MachRpath[];
  source_version: MachSourceVersion | null;
  dylinker: MachDylinker | null;
  linkedit_data: MachLinkeditData[];
  encryption_info: MachEncryptionInfo | null;
  entry_point: MachEntryPoint | null;
  weak_libraries: MachWeakLibrary[];
  id_library: MachIdLibrary | null;
  fvmlibs: MachFvmlib[];
  id_fvmlibs: MachIdFvmlib[];
  function_starts: MachFunctionStart[];
  data_in_code: MachDataInCodeEntry[];
  code_signature: MachCodeSignature | null;
  superblob: MachSuperBlob | null;
  unix_thread: MachUnixThread | null;
  dyld_chained_fixups: MachDyldChainedFixups | null;
  dyld_exports_trie: MachDyldExportsTrie | null;
  string_table: MachStringTableEntry[];
}

interface MachWeakLibrary { name: string; current_version: number; compatibility_version: number; }
interface MachIdLibrary { name: string; current_version: number; compatibility_version: number; }
interface MachFvmlib { name: string; minor_version: number; header_addr: number; }
interface MachIdFvmlib { name: string; minor_version: number; header_addr: number; }
interface MachFunctionStart { address: number; }
interface MachDataInCodeEntry { offset: number; length: number; kind: number; kind_name: string; }
interface MachCodeSlot { type_val: number; type_name: string; offset: number; }
interface MachCodeSignature { magic: number; length: number; count: number; slots: MachCodeSlot[]; }
interface MachSuperBlobEntry { type_val: number; type_name: string; offset: number; }
interface MachSuperBlob { magic: number; length: number; count: number; entries: MachSuperBlobEntry[]; }
interface MachUnixThread { cputype: string; entry: number; }
interface MachDyldChainedFixups { dataoff: number; datasize: number; fixups_version: number; starts_offset: number; image_base: number; }
interface MachDyldExportsTrie { dataoff: number; datasize: number; export_count: number; }
interface MachStringTableEntry { offset: number; value: string; }

type MachSubView =
  | 'overview'
  | 'load_commands'
  | 'segments'
  | 'sections'
  | 'libraries'
  | 'uuid'
  | 'symtab'
  | 'dysymtab'
  | 'dyld_info'
  | 'version'
  | 'rpaths'
  | 'dylinker'
  | 'linkedit'
  | 'encryption'
  | 'entrypoint'
  | 'weak_libraries'
  | 'id_library'
  | 'fvmlib'
  | 'id_fvmlib'
  | 'function_starts'
  | 'data_in_code'
  | 'code_signature'
  | 'superblob'
  | 'unix_thread'
  | 'dyld_chained_fixups'
  | 'dyld_exports_trie'
  | 'stringtable';

const SUB_VIEWS: { key: MachSubView; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'load_commands', label: 'Load Commands' },
  { key: 'segments', label: 'Segments' },
  { key: 'sections', label: 'Sections' },
  { key: 'libraries', label: 'Libraries' },
  { key: 'uuid', label: 'UUID' },
  { key: 'symtab', label: 'Symtab' },
  { key: 'dysymtab', label: 'Dysymtab' },
  { key: 'dyld_info', label: 'Dyld Info' },
  { key: 'version', label: 'Version' },
  { key: 'rpaths', label: 'Rpaths' },
  { key: 'dylinker', label: 'Dylinker' },
  { key: 'linkedit', label: 'Linkedit Data' },
  { key: 'encryption', label: 'Encryption' },
  { key: 'entrypoint', label: 'Entry Point' },
  { key: 'weak_libraries', label: 'Weak Libs' },
  { key: 'id_library', label: 'ID Library' },
  { key: 'fvmlib', label: 'FVMLIB' },
  { key: 'id_fvmlib', label: 'IDFVMLIB' },
  { key: 'function_starts', label: 'Func Starts' },
  { key: 'data_in_code', label: 'Data in Code' },
  { key: 'code_signature', label: 'Code Sig' },
  { key: 'superblob', label: 'SuperBlob' },
  { key: 'unix_thread', label: 'Unix Thread' },
  { key: 'dyld_chained_fixups', label: 'Chained Fixups' },
  { key: 'dyld_exports_trie', label: 'Exports Trie' },
  { key: 'stringtable', label: 'String Table' },
];

function hex(n: string | number | bigint): string {
  if (typeof n === 'string') return n;
  return `0x${BigInt(n).toString(16)}`;
}

function Overview({ view }: { view: MachView }) {
  const rows: [string, string][] = [
    ['Architecture', view.is64 ? '64-bit' : '32-bit'],
    ['Magic', `0x${view.magic.toString(16)}`],
    ['CPU Type', view.cputype],
    ['CPU Subtype', `0x${view.cpusubtype.toString(16)}`],
    ['File Type', view.filetype],
    ['Load Commands', view.ncmds.toString()],
    ['Size of Cmds', view.sizeofcmds.toString()],
    ['Segments', view.segments.length.toString()],
    ['Sections', view.sections.length.toString()],
    ['Libraries', view.libraries.length.toString()],
    ['Entry', view.entry ? hex(view.entry) : '—'],
  ];

  return (
    <table className="w-full text-xs">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k} className="border-b border-border/50">
            <td className="py-1 pr-4 text-muted-foreground font-mono">{k}</td>
            <td className="py-1 font-mono break-all">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LoadCommands({ commands }: { commands: MachLoadCommand[] }) {
  if (commands.length === 0)
    return <p className="text-xs text-muted-foreground">No load commands.</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">Command</th>
            <th className="text-right px-2 py-1">Size</th>
            <th className="text-left px-2 py-1">Info</th>
          </tr>
        </thead>
        <tbody>
          {commands.map((lc, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{lc.cmd}</td>
              <td className="px-2 py-0.5 text-right font-mono">{lc.cmdsize}</td>
              <td className="px-2 py-0.5 font-mono break-all">{lc.info || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Segments({ segments }: { segments: MachSegment[] }) {
  if (segments.length === 0)
    return <p className="text-xs text-muted-foreground">No segments.</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">Name</th>
            <th className="text-right px-2 py-1">VM Addr</th>
            <th className="text-right px-2 py-1">VM Size</th>
            <th className="text-right px-2 py-1">File Off</th>
            <th className="text-right px-2 py-1">File Sz</th>
            <th className="text-left px-2 py-1">MaxProt</th>
            <th className="text-left px-2 py-1">InitProt</th>
            <th className="text-right px-2 py-1">Nsects</th>
          </tr>
        </thead>
        <tbody>
          {segments.map((seg, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{seg.name || '—'}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(seg.vmaddr)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(seg.vmsize)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(seg.fileoff)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(seg.filesize)}</td>
              <td className="px-2 py-0.5 font-mono">{seg.maxprot}</td>
              <td className="px-2 py-0.5 font-mono">{seg.initprot}</td>
              <td className="px-2 py-0.5 text-right font-mono">{seg.nsects}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Sections({ sections }: { sections: MachSection[] }) {
  if (sections.length === 0)
    return <p className="text-xs text-muted-foreground">No sections.</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">Section</th>
            <th className="text-left px-2 py-1">Segment</th>
            <th className="text-right px-2 py-1">Addr</th>
            <th className="text-right px-2 py-1">Size</th>
            <th className="text-right px-2 py-1">Offset</th>
            <th className="text-right px-2 py-1">Align</th>
          </tr>
        </thead>
        <tbody>
          {sections.map((sec, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{sec.sectname || '—'}</td>
              <td className="px-2 py-0.5 font-mono">{sec.segname || '—'}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(sec.addr)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(sec.size)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{sec.offset}</td>
              <td className="px-2 py-0.5 text-right font-mono">{sec.align}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Libraries({ libs }: { libs: MachLibrary[] }) {
  if (libs.length === 0)
    return <p className="text-xs text-muted-foreground">No libraries.</p>;
  return (
    <div className="border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50">
          <tr>
            <th className="text-left px-2 py-1">Path</th>
            <th className="text-right px-2 py-1">Current</th>
            <th className="text-right px-2 py-1">Compat</th>
          </tr>
        </thead>
        <tbody>
          {libs.map((lib, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono break-all">{lib.name}</td>
              <td className="px-2 py-0.5 text-right font-mono">
                0x{lib.current_version.toString(16)}
              </td>
              <td className="px-2 py-0.5 text-right font-mono">
                0x{lib.compatibility_version.toString(16)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function KeyValueView({ rows }: { rows: [string, string][] }) {
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

function UuidView({ uuid }: { uuid: MachUuid | null }) {
  if (!uuid) return <p className="text-xs text-muted-foreground">No UUID.</p>;
  return <KeyValueView rows={[['UUID', uuid.uuid]]} />;
}

function SymtabView({ symtab }: { symtab: MachSymtab | null }) {
  if (!symtab) return <p className="text-xs text-muted-foreground">No symbol table.</p>;
  return (
    <KeyValueView rows={[
      ['SymOff', `0x${symtab.symoff.toString(16)}`],
      ['NumSymbols', String(symtab.nsyms)],
      ['StrOff', `0x${symtab.stroff.toString(16)}`],
      ['StrSize', String(symtab.strsize)],
    ]} />
  );
}

function DysymtabView({ dysymtab }: { dysymtab: MachDysymtab | null }) {
  if (!dysymtab) return <p className="text-xs text-muted-foreground">No dynamic symbol table.</p>;
  return (
    <KeyValueView rows={[
      ['iLocalSym', String(dysymtab.ilocalsym)],
      ['nLocalSym', String(dysymtab.nlocalsym)],
      ['iExtDefSym', String(dysymtab.iextdefsym)],
      ['nExtDefSym', String(dysymtab.nextdefsym)],
      ['iUndefSym', String(dysymtab.iundefsym)],
      ['nUndefSym', String(dysymtab.nundefsym)],
      ['TOCOffset', `0x${dysymtab.tocoff.toString(16)}`],
      ['nTOC', String(dysymtab.ntoc)],
      ['ModTabOff', `0x${dysymtab.modtaboff.toString(16)}`],
      ['nModTab', String(dysymtab.nmodtab)],
      ['ExtRefSymOff', `0x${dysymtab.extrefsymoff.toString(16)}`],
      ['nExtRefSyms', String(dysymtab.nextrefsyms)],
      ['IndirectSymOff', `0x${dysymtab.indirectsymoff.toString(16)}`],
      ['nIndirectSyms', String(dysymtab.nindirectsyms)],
      ['ExtRelOff', `0x${dysymtab.extreloff.toString(16)}`],
      ['nExtRel', String(dysymtab.nextrel)],
      ['LocRelOff', `0x${dysymtab.locreloff.toString(16)}`],
      ['nLocRel', String(dysymtab.nlocrel)],
    ]} />
  );
}

function DyldInfoView({ info }: { info: MachDyldInfo | null }) {
  if (!info) return <p className="text-xs text-muted-foreground">No dyld info.</p>;
  return (
    <KeyValueView rows={[
      ['Rebase', `off=0x${info.rebase_off.toString(16)} size=${info.rebase_size}`],
      ['Bind', `off=0x${info.bind_off.toString(16)} size=${info.bind_size}`],
      ['WeakBind', `off=0x${info.weak_bind_off.toString(16)} size=${info.weak_bind_size}`],
      ['LazyBind', `off=0x${info.lazy_bind_off.toString(16)} size=${info.lazy_bind_size}`],
      ['Export', `off=0x${info.export_off.toString(16)} size=${info.export_size}`],
    ]} />
  );
}

function VersionView({ view }: { view: MachView }) {
  const rows: [string, string][] = [];
  if (view.version_min) {
    rows.push(['VersionMin Platform', view.version_min.platform]);
    rows.push(['VersionMin', view.version_min.version]);
    rows.push(['VersionMin SDK', view.version_min.sdk]);
  }
  if (view.build_version) {
    rows.push(['BuildVersion Platform', view.build_version.platform]);
    rows.push(['BuildVersion MinOS', view.build_version.minos]);
    rows.push(['BuildVersion SDK', view.build_version.sdk]);
    rows.push(['BuildVersion Tools', String(view.build_version.ntools)]);
  }
  if (view.source_version) {
    rows.push(['SourceVersion', view.source_version.version]);
  }
  if (rows.length === 0) return <p className="text-xs text-muted-foreground">No version info.</p>;
  return <KeyValueView rows={rows} />;
}

function RpathsView({ rpaths }: { rpaths: MachRpath[] }) {
  if (rpaths.length === 0) return <p className="text-xs text-muted-foreground">No rpaths.</p>;
  return (
    <div className="border border-border rounded">
      <table className="w-full text-xs">
        <tbody>
          {rpaths.map((r, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono break-all">{r.path}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DylinkerView({ dylinker }: { dylinker: MachDylinker | null }) {
  if (!dylinker) return <p className="text-xs text-muted-foreground">No dylinker.</p>;
  return <KeyValueView rows={[['Dylinker', dylinker.name]]} />;
}

function LinkeditDataView({ entries }: { entries: MachLinkeditData[] }) {
  if (entries.length === 0) return <p className="text-xs text-muted-foreground">No linkedit data.</p>;
  return (
    <div className="border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50">
          <tr>
            <th className="text-left px-2 py-1">Command</th>
            <th className="text-right px-2 py-1">Offset</th>
            <th className="text-right px-2 py-1">Size</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{e.cmd}</td>
              <td className="px-2 py-0.5 text-right font-mono">0x{e.dataoff.toString(16)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{e.datasize}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EncryptionView({ info }: { info: MachEncryptionInfo | null }) {
  if (!info) return <p className="text-xs text-muted-foreground">No encryption info.</p>;
  return (
    <KeyValueView rows={[
      ['CryptOffset', `0x${info.cryptoff.toString(16)}`],
      ['CryptSize', String(info.cryptsize)],
      ['CryptID', String(info.cryptid)],
      ['Encrypted', info.cryptid !== 0 ? 'Yes' : 'No'],
    ]} />
  );
}

function EntryPointView({ ep }: { ep: MachEntryPoint | null }) {
  if (!ep) return <p className="text-xs text-muted-foreground">No entry point info.</p>;
  return (
    <KeyValueView rows={[
      ['EntryOffset', ep.entryoff],
      ['StackSize', ep.stacksize],
    ]} />
  );
}

export function MachoViewPanel({ filePath }: { filePath: string | null }) {
  const [view, setView] = useState<MachView | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [subView, setSubView] = useState<MachSubView>('overview');

  const fetchView = useCallback(async () => {
    if (!filePath) {
      setView(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<MachView | null>('get_macho_view', { path: filePath });
      setView(result);
    } catch (e) {
      setError(String(e));
      setView(null);
    } finally {
      setLoading(false);
    }
  }, [filePath]);

  useEffect(() => {
    fetchView();
  }, [fetchView]);

  if (!filePath) return null;
  if (loading)
    return <p className="text-xs text-muted-foreground p-2">Loading Mach-O view...</p>;
  if (error) return <p className="text-xs text-red-500 p-2">Error: {error}</p>;
  if (!view) return null;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1 flex-wrap">
        {SUB_VIEWS.map((sv) => (
          <button
            key={sv.key}
            onClick={() => setSubView(sv.key)}
            className={`px-2 py-1 text-xs border border-border rounded ${
              subView === sv.key ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
            }`}
          >
            {sv.label}
          </button>
        ))}
      </div>

      {subView === 'overview' && <Overview view={view} />}
      {subView === 'load_commands' && <LoadCommands commands={view.load_commands} />}
      {subView === 'segments' && <Segments segments={view.segments} />}
      {subView === 'sections' && <Sections sections={view.sections} />}
      {subView === 'libraries' && <Libraries libs={view.libraries} />}
      {subView === 'uuid' && <UuidView uuid={view.uuid} />}
      {subView === 'symtab' && <SymtabView symtab={view.symtab} />}
      {subView === 'dysymtab' && <DysymtabView dysymtab={view.dysymtab} />}
      {subView === 'dyld_info' && <DyldInfoView info={view.dyld_info} />}
      {subView === 'version' && <VersionView view={view} />}
      {subView === 'rpaths' && <RpathsView rpaths={view.rpaths} />}
      {subView === 'dylinker' && <DylinkerView dylinker={view.dylinker} />}
      {subView === 'linkedit' && <LinkeditDataView entries={view.linkedit_data} />}
      {subView === 'encryption' && <EncryptionView info={view.encryption_info} />}
      {subView === 'entrypoint' && <EntryPointView ep={view.entry_point} />}
      {subView === 'weak_libraries' && <WeakLibrariesView libs={view.weak_libraries} />}
      {subView === 'id_library' && <IdLibraryView lib={view.id_library} />}
      {subView === 'fvmlib' && <FvmlibView entries={view.fvmlibs} />}
      {subView === 'id_fvmlib' && <IdFvmlibView entries={view.id_fvmlibs} />}
      {subView === 'function_starts' && <FunctionStartsView entries={view.function_starts} />}
      {subView === 'data_in_code' && <DataInCodeView entries={view.data_in_code} />}
      {subView === 'code_signature' && <CodeSignatureView sig={view.code_signature} />}
      {subView === 'superblob' && <SuperBlobView sb={view.superblob} />}
      {subView === 'unix_thread' && <UnixThreadView thread={view.unix_thread} />}
      {subView === 'dyld_chained_fixups' && <DyldChainedFixupsView fixups={view.dyld_chained_fixups} />}
      {subView === 'dyld_exports_trie' && <DyldExportsTrieView trie={view.dyld_exports_trie} />}
      {subView === 'stringtable' && <StringTableView entries={view.string_table} />}
    </div>
  );
}

// --- New sub-view components for Batch B ---

function WeakLibrariesView({ libs }: { libs: MachWeakLibrary[] }) {
  if (libs.length === 0) return <p className="text-xs text-muted-foreground">No weak libraries.</p>;
  return (
    <table className="w-full text-xs">
      <thead><tr><th className="text-left">Name</th><th>Current</th><th>Compat</th></tr></thead>
      <tbody>
        {libs.map((l, i) => (
          <tr key={i} className="border-b border-border/30">
            <td className="py-0.5 px-2 font-mono">{l.name}</td>
            <td className="py-0.5 px-2 text-right">0x{l.current_version.toString(16)}</td>
            <td className="py-0.5 px-2 text-right">0x{l.compatibility_version.toString(16)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function IdLibraryView({ lib }: { lib: MachIdLibrary | null }) {
  if (!lib) return <p className="text-xs text-muted-foreground">No ID library.</p>;
  return (
    <table className="w-full text-xs">
      <tbody>
        <tr><td className="py-0.5 px-2 font-mono text-muted-foreground">Name</td><td className="py-0.5 px-2 font-mono">{lib.name}</td></tr>
        <tr><td className="py-0.5 px-2 font-mono text-muted-foreground">Current Version</td><td className="py-0.5 px-2 font-mono">0x{lib.current_version.toString(16)}</td></tr>
        <tr><td className="py-0.5 px-2 font-mono text-muted-foreground">Compatibility Version</td><td className="py-0.5 px-2 font-mono">0x{lib.compatibility_version.toString(16)}</td></tr>
      </tbody>
    </table>
  );
}

function FvmlibView({ entries }: { entries: MachFvmlib[] }) {
  if (entries.length === 0) return <p className="text-xs text-muted-foreground">No FVMLIB entries.</p>;
  return (
    <table className="w-full text-xs">
      <thead><tr><th className="text-left">Name</th><th>Minor Version</th><th>Header Addr</th></tr></thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i} className="border-b border-border/30">
            <td className="py-0.5 px-2 font-mono">{e.name}</td>
            <td className="py-0.5 px-2 text-right">0x{e.minor_version.toString(16)}</td>
            <td className="py-0.5 px-2 text-right">0x{e.header_addr.toString(16)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function IdFvmlibView({ entries }: { entries: MachIdFvmlib[] }) {
  if (entries.length === 0) return <p className="text-xs text-muted-foreground">No IDFVMLIB entries.</p>;
  return (
    <table className="w-full text-xs">
      <thead><tr><th className="text-left">Name</th><th>Minor Version</th><th>Header Addr</th></tr></thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i} className="border-b border-border/30">
            <td className="py-0.5 px-2 font-mono">{e.name}</td>
            <td className="py-0.5 px-2 text-right">0x{e.minor_version.toString(16)}</td>
            <td className="py-0.5 px-2 text-right">0x{e.header_addr.toString(16)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function FunctionStartsView({ entries }: { entries: MachFunctionStart[] }) {
  if (entries.length === 0) return <p className="text-xs text-muted-foreground">No function starts.</p>;
  return (
    <div>
      <p className="text-xs text-muted-foreground mb-1">{entries.length} functions</p>
      <div className="border border-border rounded overflow-auto max-h-96">
        <table className="w-full text-xs">
          <thead className="bg-muted/50 sticky top-0"><tr><th className="text-right px-2 py-1">#</th><th className="text-right px-2 py-1">Address</th></tr></thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={i} className="border-b border-border/30">
                <td className="py-0.5 px-2 text-right">{i + 1}</td>
                <td className="py-0.5 px-2 text-right font-mono">0x{e.address.toString(16)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DataInCodeView({ entries }: { entries: MachDataInCodeEntry[] }) {
  if (entries.length === 0) return <p className="text-xs text-muted-foreground">No data-in-code entries.</p>;
  return (
    <table className="w-full text-xs">
      <thead><tr><th className="text-right">Offset</th><th className="text-right">Length</th><th>Kind</th></tr></thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i} className="border-b border-border/30">
            <td className="py-0.5 px-2 text-right font-mono">0x{e.offset.toString(16)}</td>
            <td className="py-0.5 px-2 text-right">{e.length}</td>
            <td className="py-0.5 px-2">{e.kind_name}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CodeSignatureView({ sig }: { sig: MachCodeSignature | null }) {
  if (!sig) return <p className="text-xs text-muted-foreground">No code signature.</p>;
  return (
    <div>
      <table className="w-full text-xs mb-2">
        <tbody>
          <tr><td className="py-0.5 px-2 text-muted-foreground">Magic</td><td className="py-0.5 px-2 font-mono">0x{sig.magic.toString(16)}</td></tr>
          <tr><td className="py-0.5 px-2 text-muted-foreground">Length</td><td className="py-0.5 px-2">{sig.length}</td></tr>
          <tr><td className="py-0.5 px-2 text-muted-foreground">Count</td><td className="py-0.5 px-2">{sig.count}</td></tr>
        </tbody>
      </table>
      {sig.slots.length > 0 && (
        <table className="w-full text-xs">
          <thead><tr><th>Type</th><th className="text-right">Offset</th></tr></thead>
          <tbody>
            {sig.slots.map((s, i) => (
              <tr key={i} className="border-b border-border/30">
                <td className="py-0.5 px-2">{s.type_name}</td>
                <td className="py-0.5 px-2 text-right font-mono">0x{s.offset.toString(16)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function SuperBlobView({ sb }: { sb: MachSuperBlob | null }) {
  if (!sb) return <p className="text-xs text-muted-foreground">No SuperBlob.</p>;
  return (
    <div>
      <table className="w-full text-xs mb-2">
        <tbody>
          <tr><td className="py-0.5 px-2 text-muted-foreground">Magic</td><td className="py-0.5 px-2 font-mono">0x{sb.magic.toString(16)}</td></tr>
          <tr><td className="py-0.5 px-2 text-muted-foreground">Length</td><td className="py-0.5 px-2">{sb.length}</td></tr>
          <tr><td className="py-0.5 px-2 text-muted-foreground">Count</td><td className="py-0.5 px-2">{sb.count}</td></tr>
        </tbody>
      </table>
      {sb.entries.length > 0 && (
        <table className="w-full text-xs">
          <thead><tr><th>Type</th><th className="text-right">Offset</th></tr></thead>
          <tbody>
            {sb.entries.map((e, i) => (
              <tr key={i} className="border-b border-border/30">
                <td className="py-0.5 px-2">{e.type_name}</td>
                <td className="py-0.5 px-2 text-right font-mono">0x{e.offset.toString(16)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function UnixThreadView({ thread }: { thread: MachUnixThread | null }) {
  if (!thread) return <p className="text-xs text-muted-foreground">No Unix thread.</p>;
  return (
    <table className="w-full text-xs">
      <tbody>
        <tr><td className="py-0.5 px-2 text-muted-foreground">CPU Type</td><td className="py-0.5 px-2">{thread.cputype}</td></tr>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Entry Point</td><td className="py-0.5 px-2 font-mono">0x{thread.entry.toString(16)}</td></tr>
      </tbody>
    </table>
  );
}

function DyldChainedFixupsView({ fixups }: { fixups: MachDyldChainedFixups | null }) {
  if (!fixups) return <p className="text-xs text-muted-foreground">No dyld chained fixups.</p>;
  return (
    <table className="w-full text-xs">
      <tbody>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Data Offset</td><td className="py-0.5 px-2 font-mono">0x{fixups.dataoff.toString(16)}</td></tr>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Data Size</td><td className="py-0.5 px-2">{fixups.datasize}</td></tr>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Fixups Version</td><td className="py-0.5 px-2">{fixups.fixups_version}</td></tr>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Starts Offset</td><td className="py-0.5 px-2 font-mono">0x{fixups.starts_offset.toString(16)}</td></tr>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Image Base</td><td className="py-0.5 px-2 font-mono">0x{fixups.image_base.toString(16)}</td></tr>
      </tbody>
    </table>
  );
}

function DyldExportsTrieView({ trie }: { trie: MachDyldExportsTrie | null }) {
  if (!trie) return <p className="text-xs text-muted-foreground">No dyld exports trie.</p>;
  return (
    <table className="w-full text-xs">
      <tbody>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Data Offset</td><td className="py-0.5 px-2 font-mono">0x{trie.dataoff.toString(16)}</td></tr>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Data Size</td><td className="py-0.5 px-2">{trie.datasize}</td></tr>
        <tr><td className="py-0.5 px-2 text-muted-foreground">Export Count</td><td className="py-0.5 px-2">{trie.export_count}</td></tr>
      </tbody>
    </table>
  );
}

function StringTableView({ entries }: { entries: MachStringTableEntry[] }) {
  if (entries.length === 0) return <p className="text-xs text-muted-foreground">No string table entries.</p>;
  return (
    <div>
      <p className="text-xs text-muted-foreground mb-1">{entries.length} entries</p>
      <div className="border border-border rounded overflow-auto max-h-96">
        <table className="w-full text-xs">
          <thead className="bg-muted/50 sticky top-0"><tr><th className="text-right px-2 py-1">Offset</th><th className="text-left px-2 py-1">Value</th></tr></thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={i} className="border-b border-border/30">
                <td className="py-0.5 px-2 text-right font-mono">0x{e.offset.toString(16)}</td>
                <td className="py-0.5 px-2 font-mono break-all">{e.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
