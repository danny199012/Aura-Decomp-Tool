import type { ReactNode } from 'react';
import { useFile } from '../lib/FileContext';
import type { BinarySummary } from '../lib/tauri';

export type ViewId =
  | 'home'
  | 'binary'
  | 'disasm'
  | 'callgraph'
  | 'sdk'
  | 'export'
  | 'ps1';

interface NavItem {
  id: ViewId;
  label: string;
  icon: string;
  needsFile?: boolean;
}

const NAV: NavItem[] = [
  { id: 'home', label: 'Home / Open', icon: '𝌆' },
  { id: 'binary', label: 'Binary info', icon: '▤', needsFile: true },
  { id: 'disasm', label: 'Disassembly', icon: '⌗', needsFile: true },
  { id: 'callgraph', label: 'Call graph', icon: '◉', needsFile: true },
  { id: 'sdk', label: 'SDK scan', icon: '⚗' },
  { id: 'export', label: 'Export project', icon: '⇩' },
  { id: 'ps1', label: 'PS1 analysis', icon: '▓' },
];

function NavRow({ item, active, disabled, onClick }: {
  item: NavItem;
  active: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`group flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
        active
          ? 'bg-accent/15 font-semibold text-fg'
          : disabled
            ? 'cursor-not-allowed text-fg-faint'
            : 'text-fg-secondary hover:bg-app-hover hover:text-fg'
      }`}
    >
      <span className="w-4 text-accent-bright">{item.icon}</span>
      <span className="flex-1">{item.label}</span>
    </button>
  );
}

/** Compact horizontal chip for the current binary, shown above nav. */
function CurrentFile({ summary }: { summary: BinarySummary | null }) {
  if (!summary) return <div className="px-1 pb-2 text-xs text-fg-muted">No file loaded</div>;
  return (
    <div className="mb-2 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2">
      <div className="truncate font-mono text-xs font-semibold text-fg">{summary.filename}</div>
      <div className="truncate text-[10px] text-fg-muted">{summary.platform}</div>
    </div>
  );
}

export default function Sidebar({ active, onNavigate, children }: {
  active: ViewId;
  onNavigate: (v: ViewId) => void;
  children?: ReactNode;
}) {
  const { summary } = useFile();
  return (
    <aside className="flex w-full flex-col gap-1 overflow-y-auto border-app-border p-3 md:h-full md:w-60 md:border-r">
      <div className="mb-1 flex items-center gap-2 px-1">
        <span className="grid h-7 w-7 place-items-center rounded-lg bg-accent text-sm font-black text-white">A</span>
        <div>
          <div className="text-sm font-bold leading-tight text-fg">Aura Decomp Tool</div>
          <div className="text-[10px] text-fg-muted">cross-platform reverse engineering</div>
        </div>
      </div>

      <CurrentFile summary={summary} />

      <nav className="flex-1 space-y-0.5">
        {NAV.map((item) => {
          const disabled = !!item.needsFile && !summary;
          return (
            <NavRow
              key={item.id}
              item={item}
              active={active === item.id}
              disabled={disabled}
              onClick={() => onNavigate(item.id)}
            />
          );
        })}
      </nav>

      {children}
    </aside>
  );
}
