import { useEffect, useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useTranslation } from 'react-i18next';
import { followInHex } from '../follow';

/**
 * ELF-specific views: program headers, section headers, dynamic entries,
 * libraries, interpreter, notes, and symbol table.
 *
 * Mirrors upstream FormatWidgets/ELF/elfwidget.cpp sub-views.
 */

interface ElfProgramHeader {
  p_type: string;
  p_type_val: number;
  p_flags: string;
  p_offset: string;
  p_vaddr: string;
  p_paddr: string;
  p_filesz: string;
  p_memsz: string;
  p_align: string;
  p_flags_val: number;
}

interface ElfSectionHeader {
  sh_name: string;
  sh_type: string;
  sh_type_val: number;
  sh_flags: string;
  sh_flags_val: number;
  sh_addr: number;
  sh_offset: number;
  sh_size: number;
  sh_link: number;
  sh_info: number;
  sh_addralign: number;
  sh_entsize: number;
}

interface ElfDynamicEntry {
  d_tag: string;
  d_tag_val: string;
  d_val: string;
}

interface ElfLibrary {
  name: string;
}

interface ElfNote {
  name: string;
  n_type: string;
  n_type_val: number;
  desc: string;
}

interface ElfSymbol {
  name: string;
  value: string;
  size: string;
  binding: string;
  sym_type: string;
  visibility: string;
  shndx: string;
}

interface ElfRelocation {
  r_offset: string;
  r_info: string;
  r_addend: string;
  r_sym: number;
  r_type: number;
  is_rela: boolean;
}

interface ElfView {
  program_headers: ElfProgramHeader[];
  section_headers: ElfSectionHeader[];
  dynamic_entries: ElfDynamicEntry[];
  libraries: ElfLibrary[];
  interpreter: string | null;
  notes: ElfNote[];
  symbols: ElfSymbol[];
  runpath: string | null;
  is64: boolean;
  is_le: boolean;
  machine: string;
  e_type: string;
  entry: string;
  relocations: ElfRelocation[];
  string_table: ElfStringTableEntry[];
}

interface ElfStringTableEntry {
  offset: number;
  value: string;
  section: string;
}

type ElfSubView =
  | 'overview'
  | 'program_headers'
  | 'section_headers'
  | 'dynamic'
  | 'libraries'
  | 'notes'
  | 'symbols'
  | 'relocations'
  | 'stringtable';

const SUB_VIEWS: { key: ElfSubView; labelKey: string }[] = [
  { key: 'overview', labelKey: 'elf.tabOverview' },
  { key: 'program_headers', labelKey: 'elf.tabProgramHeaders' },
  { key: 'section_headers', labelKey: 'elf.tabSectionHeaders' },
  { key: 'dynamic', labelKey: 'elf.tabDynamic' },
  { key: 'libraries', labelKey: 'elf.tabLibraries' },
  { key: 'notes', labelKey: 'elf.tabNotes' },
  { key: 'symbols', labelKey: 'elf.tabSymbols' },
  { key: 'relocations', labelKey: 'elf.tabRelocations' },
  { key: 'stringtable', labelKey: 'elf.tabStringTable' },
];

function hex(n: string | number | bigint): string {
  if (typeof n === 'string') return n;
  return `0x${BigInt(n).toString(16)}`;
}

function Overview({ view }: { view: ElfView }) {
  const { t } = useTranslation();
  const rows: [string, string][] = [
    [t('elf.arch'), view.is64 ? t('common.bits64') : t('common.bits32')],
    [t('elf.endianness'), view.is_le ? t('common.little') : t('common.big')],
    [t('elf.machine'), view.machine],
    [t('common.type'), view.e_type],
    [t('elf.entryPoint'), hex(view.entry)],
    [t('elf.programHeaders'), view.program_headers.length.toString()],
    [t('elf.sectionHeaders'), view.section_headers.length.toString()],
    [t('elf.libraries'), view.libraries.length.toString()],
    [t('elf.symbols'), view.symbols.length.toString()],
    [t('elf.interpreter'), view.interpreter ?? '—'],
    [t('elf.runpath'), view.runpath ?? '—'],
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

function ProgramHeaders({ headers }: { headers: ElfProgramHeader[] }) {
  const { t } = useTranslation();
  if (headers.length === 0)
    return <p className="text-xs text-muted-foreground">{t('elf.noProgramHeaders')}</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">{t('common.type')}</th>
            <th className="text-left px-2 py-1">{t('common.flags')}</th>
            <th className="text-right px-2 py-1">{t('common.offset')}</th>
            <th className="text-right px-2 py-1">VAddr</th>
            <th className="text-right px-2 py-1">FileSz</th>
            <th className="text-right px-2 py-1">MemSz</th>
            <th className="text-right px-2 py-1">Align</th>
          </tr>
        </thead>
        <tbody>
          {headers.map((ph, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{ph.p_type}</td>
              <td className="px-2 py-0.5 font-mono">{ph.p_flags}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(ph.p_offset)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(ph.p_vaddr)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(ph.p_filesz)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(ph.p_memsz)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(ph.p_align)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SectionHeaders({ sections }: { sections: ElfSectionHeader[] }) {
  const { t } = useTranslation();
  if (sections.length === 0)
    return <p className="text-xs text-muted-foreground">{t('elf.noSectionHeaders')}</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">{t('common.name')}</th>
            <th className="text-left px-2 py-1">{t('common.type')}</th>
            <th className="text-left px-2 py-1">{t('common.flags')}</th>
            <th className="text-right px-2 py-1">Addr</th>
            <th className="text-right px-2 py-1">{t('common.offset')}</th>
            <th className="text-right px-2 py-1">{t('common.size')}</th>
          </tr>
        </thead>
        <tbody>
          {sections.map((sh, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{sh.sh_name || '—'}</td>
              <td className="px-2 py-0.5 font-mono">{sh.sh_type}</td>
              <td className="px-2 py-0.5 font-mono">{sh.sh_flags}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(sh.sh_addr)}</td>
              <td className="px-2 py-0.5 text-right font-mono">
                <button className="hover:underline" title={t('common.followInHex')} onClick={() => followInHex(sh.sh_offset)}>
                  {hex(sh.sh_offset)}
                </button>
              </td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(sh.sh_size)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DynamicEntries({ entries }: { entries: ElfDynamicEntry[] }) {
  const { t } = useTranslation();
  if (entries.length === 0)
    return <p className="text-xs text-muted-foreground">{t('elf.noDynamic')}</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">Tag</th>
            <th className="text-right px-2 py-1">{t('common.value')}</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((d, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{d.d_tag}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(d.d_val)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Libraries({ libs }: { libs: ElfLibrary[] }) {
  const { t } = useTranslation();
  if (libs.length === 0)
    return <p className="text-xs text-muted-foreground">{t('elf.noLibraries')}</p>;
  return (
    <div className="border border-border rounded">
      <ul className="text-xs font-mono">
        {libs.map((lib, i) => (
          <li key={i} className="px-2 py-0.5 border-b border-border/30 last:border-0">
            {lib.name}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Notes({ notes }: { notes: ElfNote[] }) {
  const { t } = useTranslation();
  if (notes.length === 0)
    return <p className="text-xs text-muted-foreground">{t('elf.noNotes')}</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">{t('common.name')}</th>
            <th className="text-left px-2 py-1">{t('common.type')}</th>
            <th className="text-left px-2 py-1">{t('common.description')}</th>
          </tr>
        </thead>
        <tbody>
          {notes.map((n, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{n.name || '—'}</td>
              <td className="px-2 py-0.5 font-mono">{n.n_type}</td>
              <td className="px-2 py-0.5 font-mono break-all">{n.desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Symbols({ symbols }: { symbols: ElfSymbol[] }) {
  const { t } = useTranslation();
  if (symbols.length === 0)
    return <p className="text-xs text-muted-foreground">{t('elf.noSymbols')}</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">{t('common.name')}</th>
            <th className="text-right px-2 py-1">{t('common.value')}</th>
            <th className="text-right px-2 py-1">{t('common.size')}</th>
            <th className="text-left px-2 py-1">{t('elf.binding')}</th>
            <th className="text-left px-2 py-1">{t('common.type')}</th>
            <th className="text-left px-2 py-1">Vis</th>
            <th className="text-left px-2 py-1">Ndx</th>
          </tr>
        </thead>
        <tbody>
          {symbols.map((s, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{s.name || '—'}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(s.value)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(s.size)}</td>
              <td className="px-2 py-0.5 font-mono">{s.binding}</td>
              <td className="px-2 py-0.5 font-mono">{s.sym_type}</td>
              <td className="px-2 py-0.5 font-mono">{s.visibility}</td>
              <td className="px-2 py-0.5 font-mono">{s.shndx}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Relocations({ relocs }: { relocs: ElfRelocation[] }) {
  const { t } = useTranslation();
  if (relocs.length === 0)
    return <p className="text-xs text-muted-foreground">{t('elf.noRelocs')}</p>;
  return (
    <div className="overflow-auto max-h-96 border border-border rounded">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">{t('common.type')}</th>
            <th className="text-right px-2 py-1">{t('common.offset')}</th>
            <th className="text-right px-2 py-1">SymIdx</th>
            <th className="text-right px-2 py-1">RelType</th>
            <th className="text-right px-2 py-1">Addend</th>
          </tr>
        </thead>
        <tbody>
          {relocs.map((r, i) => (
            <tr key={i} className="border-b border-border/30">
              <td className="px-2 py-0.5 font-mono">{r.is_rela ? 'Rela' : 'Rel'}</td>
              <td className="px-2 py-0.5 text-right font-mono">{hex(r.r_offset)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{r.r_sym}</td>
              <td className="px-2 py-0.5 text-right font-mono">0x{r.r_type.toString(16)}</td>
              <td className="px-2 py-0.5 text-right font-mono">{r.r_addend}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ElfViewPanel({ filePath }: { filePath: string | null }) {
  const { t } = useTranslation();
  const [view, setView] = useState<ElfView | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [subView, setSubView] = useState<ElfSubView>('overview');

  const fetchView = useCallback(async () => {
    if (!filePath) {
      setView(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<ElfView | null>('get_elf_view', { path: filePath });
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
    return <p className="text-xs text-muted-foreground p-2">{t('elf.loading')}</p>;

  if (error) return <p className="text-xs text-red-500 p-2">{t('common.error', { error })}</p>;

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
            {t(sv.labelKey)}
          </button>
        ))}
      </div>

      {subView === 'overview' && <Overview view={view} />}
      {subView === 'program_headers' && <ProgramHeaders headers={view.program_headers} />}
      {subView === 'section_headers' && <SectionHeaders sections={view.section_headers} />}
      {subView === 'dynamic' && <DynamicEntries entries={view.dynamic_entries} />}
      {subView === 'libraries' && <Libraries libs={view.libraries} />}
      {subView === 'notes' && <Notes notes={view.notes} />}
      {subView === 'symbols' && <Symbols symbols={view.symbols} />}
      {subView === 'relocations' && <Relocations relocs={view.relocations} />}
      {subView === 'stringtable' && <StringTableView entries={view.string_table} />}
    </div>
  );
}

function StringTableView({ entries }: { entries: ElfStringTableEntry[] }) {
  const { t } = useTranslation();
  if (entries.length === 0) return <p className="text-xs text-muted-foreground">{t('elf.noStringTable')}</p>;
  return (
    <div>
      <p className="text-xs text-muted-foreground mb-1">{t('common.numEntries', { count: entries.length })}</p>
      <div className="border border-border rounded overflow-auto max-h-96">
        <table className="w-full text-xs">
          <thead className="bg-muted/50 sticky top-0">
            <tr><th className="text-right px-2 py-1">{t('common.offset')}</th><th className="text-left px-2 py-1">{t('common.section')}</th><th className="text-left px-2 py-1">{t('common.value')}</th></tr>
          </thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={i} className="border-b border-border/30">
                <td className="py-0.5 px-2 text-right font-mono">0x{e.offset.toString(16)}</td>
                <td className="py-0.5 px-2 font-mono">{e.section}</td>
                <td className="py-0.5 px-2 font-mono break-all">{e.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
