import { useCallback, useEffect, useMemo, useState } from 'react';
import { FileContext } from './lib/FileContext';
import { probeBinary, openFileDialog, type BinarySummary } from './lib/tauri';
import Sidebar, { type ViewId } from './components/Sidebar';
import HomeView from './components/HomeView';
import BinaryView from './components/BinaryView';
import DisasmView from './components/DisasmView';
import CallGraphView from './components/CallGraphView';
import CfgView from './components/CfgView';
import DecompileView from './components/DecompileView';
import ProjectView from './components/ProjectView';
import SearchView from './components/SearchView';
import SdkScanView from './components/SdkScanView';
import ExportView from './components/ExportView';
import HexView from './components/HexView';
import Ps1View from './components/Ps1View';
import ThemeSwitcher from './components/ThemeSwitcher';

function renderView(view: ViewId): JSX.Element {
  switch (view) {
    case 'binary':
      return <BinaryView />;
    case 'disasm':
      return <DisasmView />;
    case 'callgraph':
      return <CallGraphView />;
    case 'cfg':
      return <CfgView />;
    case 'decompile':
      return <DecompileView />;
    case 'project':
      return <ProjectView />;
    case 'search':
      return <SearchView />;
    case 'sdk':
      return <SdkScanView />;
    case 'export':
      return <ExportView />;
    case 'hex':
      return <HexView />;
    case 'ps1':
      return <Ps1View />;
    case 'home':
    default:
      return <HomeView />;
  }
}

/**
 * A keyboard shortcut registration. Drives both the global handler and the
 * help overlay so the two never drift apart.
 */
interface Shortcut {
  label: string;
  keys: string;
  view?: ViewId;
  action?: 'open' | 'help';
}

/** Views reachable by a bare 1–9 digit, in sidebar order. */
const NUMBER_VIEWS: ViewId[] = [
  'home', 'binary', 'disasm', 'hex', 'callgraph',
  'cfg', 'decompile', 'project', 'search',
];

const SHORTCUTS: Shortcut[] = [
  { label: 'Open file…', keys: 'Ctrl+O', action: 'open' },
  ...NUMBER_VIEWS.map((v, i) => ({ label: labelFor(v), keys: String(i + 1), view: v })),
  { label: 'Search & strings', keys: 'Ctrl+F', view: 'search' },
  { label: 'Go to disassembly', keys: 'Ctrl+G', view: 'disasm' },
  { label: 'Call graph', keys: 'Ctrl+Shift+G', view: 'callgraph' },
  { label: 'CFG & xrefs', keys: 'Ctrl+Shift+X', view: 'cfg' },
  { label: 'Decompiler', keys: 'Ctrl+E', view: 'decompile' },
  { label: 'Show this help', keys: '?', action: 'help' },
];

/** Friendly label for a view id (used by the help overlay + shortcuts). */
function labelFor(v: ViewId): string {
  switch (v) {
    case 'home': return 'Home / Open';
    case 'binary': return 'Binary info';
    case 'disasm': return 'Disassembly';
    case 'hex': return 'Hex view';
    case 'callgraph': return 'Call graph';
    case 'cfg': return 'CFG & xrefs';
    case 'decompile': return 'Decompiler';
    case 'project': return 'Project & script';
    case 'search': return 'Search & strings';
    case 'sdk': return 'SDK scan';
    case 'export': return 'Export project';
    case 'ps1': return 'PS1 analysis';
  }
}

/** True when the key event originated inside a text-entry element, where
 *  single-key / Ctrl+letter shortcuts would hijack the user's typing. */
function isTypingTarget(e: KeyboardEvent): boolean {
  const t = e.target as HTMLElement | null;
  if (!t) return false;
  const tag = t.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t.isContentEditable;
}

export default function App() {
  const [summary, setSummary] = useState<BinarySummary | null>(null);
  const [view, setView] = useState<ViewId>('home');
  const [error, setError] = useState<string | null>(null);
  const [showHelp, setShowHelp] = useState(false);

  const loadPath = useCallback(async (path: string): Promise<BinarySummary> => {
    setError(null);
    try {
      const s = await probeBinary(path);
      if (s.kind === 'ps1') {
        setView('ps1');
      } else {
        setView('binary');
      }
      setSummary(s);
      setError(null);
      return s;
    } catch (e) {
      setError(String(e));
      throw e;
    }
  }, []);

  const clear = useCallback(() => {
    setSummary(null);
    setError(null);
  }, []);

  /** Ctrl/Cmd+O: open the native file dialog and load the chosen file. */
  const openFile = useCallback(async () => {
    try {
      const p = await openFileDialog();
      if (p) await loadPath(p);
    } catch (e) {
      setError(String(e));
    }
  }, [loadPath]);

  const context = useMemo(() => ({ summary, loadPath, error, clear }), [summary, loadPath, error, clear]);

  // Global keyboard shortcuts. Registered once; reads latest state via deps so
  // navigation stays in sync with the current view / loaded file.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (e.key === '?' && e.shiftKey) { e.preventDefault(); setShowHelp((s) => !s); return; }
      if (e.key === 'Escape') { setShowHelp(false); return; }
      if (isTypingTarget(e)) return;
      if (mod) {
        const k = e.key.toLowerCase();
        if (k === 'o') { e.preventDefault(); void openFile(); return; }
        if (k === 'f') { e.preventDefault(); setView('search'); return; }
        if (k === 'g' && e.shiftKey) { e.preventDefault(); setView('callgraph'); return; }
        if (k === 'x' && e.shiftKey) { e.preventDefault(); setView('cfg'); return; }
        if (k === 'e') { e.preventDefault(); setView('decompile'); return; }
      }
      if (!mod && !e.altKey && /^[1-9]$/.test(e.key)) {
        const target = NUMBER_VIEWS[Number(e.key) - 1];
        if (target) {
          const needsFile = !['home', 'sdk', 'export', 'ps1'].includes(target);
          if (needsFile && !summary) return;
          e.preventDefault();
          setView(target);
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [openFile, summary]);

  return (
    <FileContext.Provider value={context}>
      <div className="flex h-full flex-col bg-app-base">
        <header className="flex items-center justify-between border-b border-app-border px-4 py-2.5">
          <div className="flex items-center gap-2 text-sm text-fg-muted">
            <span className="font-semibold text-fg">Aura Decomp Tool</span>
            {summary && (
              <span className="hidden truncate sm:inline">
                · <span className="text-accent-bright">{summary.platform}</span>
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button
              className="rounded-md px-2 py-1 text-xs text-fg-muted transition-colors hover:bg-app-hover hover:text-fg"
              onClick={() => setShowHelp(true)}
              title="Keyboard shortcuts (?)"
            >
              ⌨ Shortcuts
            </button>
            <div className="w-44">
              <ThemeSwitcher />
            </div>
          </div>
        </header>

        <div className="flex flex-1 flex-col overflow-hidden md:flex-row">
          <Sidebar active={view} onNavigate={(v) => setView(v)} />
          <main className="flex-1 overflow-y-auto p-5">
            {error && (
              <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm text-red-200">
                {error}
              </div>
            )}
            {renderView(view)}
          </main>
        </div>

        {showHelp && <ShortcutsOverlay shortcuts={SHORTCUTS} onClose={() => setShowHelp(false)} />}
      </div>
    </FileContext.Provider>
  );
}

/** Modal listing every keyboard shortcut, driven by the same SHORTCUTS table
 *  the global handler uses so it can never go stale. */
function ShortcutsOverlay({ shortcuts, onClose }: {
  shortcuts: Shortcut[];
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-xl border border-app-border bg-app-panel p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-bold text-fg">Keyboard shortcuts</h2>
          <button
            className="rounded-md px-2 py-1 text-sm text-fg-muted hover:bg-app-hover hover:text-fg"
            onClick={onClose}
          >
            ✕
          </button>
        </div>
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
          {shortcuts.map((s) => (
            <div key={s.label} className="flex items-center justify-between gap-3">
              <dt className="text-sm text-fg-secondary">{s.label}</dt>
              <dd>
                <kbd className="rounded border border-app-border bg-app-panel-soft px-1.5 py-0.5 font-mono text-xs text-fg">
                  {s.keys}
                </kbd>
              </dd>
            </div>
          ))}
        </dl>
        <p className="mt-4 text-xs text-fg-muted">
          Number-key shortcuts skip views that require a loaded file when none is open. Press{' '}
          <kbd className="font-mono">Esc</kbd> to close.
        </p>
      </div>
    </div>
  );
}
