import { useCallback, useMemo, useState } from 'react';
import { FileContext } from './lib/FileContext';
import { probeBinary, type BinarySummary } from './lib/tauri';
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

export default function App() {
  const [summary, setSummary] = useState<BinarySummary | null>(null);
  const [view, setView] = useState<ViewId>('home');
  const [error, setError] = useState<string | null>(null);

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

  const context = useMemo(() => ({ summary, loadPath, error, clear }), [summary, loadPath, error, clear]);

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
          <div className="w-44">
            <ThemeSwitcher />
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
      </div>
    </FileContext.Provider>
  );
}
