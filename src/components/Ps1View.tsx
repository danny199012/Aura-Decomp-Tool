import { useEffect, useState } from 'react';
import { Button, Chip, ErrorBox, Panel, Spinner, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { call } from '../lib/tauri';

interface ExtractedString { offset: number; value: string; length: number }
interface ConstantPoolEntry { register: number; value: number }
interface InterruptHandler { offset: number; size: number; reasons: string[] }
interface StateMachinePattern { load_offset: number; estimated_entries: number }
interface Ps1AnalysisResult {
  strings: ExtractedString[];
  constants: ConstantPoolEntry[];
  interrupt_handlers: InterruptHandler[];
  state_machines: StateMachinePattern[];
}

interface Ps1SymbolMatch { symbol: string; library: string; description: string; section_name: string }
interface Ps1SymbolScanResult { matches: Ps1SymbolMatch[]; total_matches: number; per_library: Record<string, number> }
interface EnhancedGraphResult { nodes: { address: number; name: string | null; size: number; caller_count: number; callee_count: number }[]; total_functions: number; hot_paths: string[] }
interface RecompConfigResult { binary_name: string; sections: unknown[]; functions: { address: number; name: string | null; size: number }[]; function_count: number }
interface FunctionEntry { name: string; start: number; end: number; size: number }

export default function Ps1View() {
  const { summary } = useFile();
  const [path, setPath] = useState(summary?.path ?? '');
  const [result, setResult] = useState<Ps1AnalysisResult | null>(null);
  const [syms, setSyms] = useState<Ps1SymbolScanResult | null>(null);
  const [enhanced, setEnhanced] = useState<EnhancedGraphResult | null>(null);
  const [recomp, setRecomp] = useState<RecompConfigResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (summary?.path) setPath(summary.path);
  }, [summary?.path]);

  const run = async () => {
    if (!path) return;
    setBusy(true);
    setError(null);
    setResult(null);
    setSyms(null);
    setEnhanced(null);
    setRecomp(null);
    try {
      const a = await call<Ps1AnalysisResult>('analyze_ps1_binary', { path });
      setResult(a);
      const s = await call<Ps1SymbolScanResult>('scan_ps1_symbols', { path }).catch(() => null);
      setSyms(s);

      // Convert detected functions into the tuple shape both enhanced-graph and
      // recomp-config commands expect: [(address, optional_name)].
      const funs: [number, string | null][] = await call<FunctionEntry[]>('detect_functions', { path })
        .then((fs) => fs.map((f) => [f.start as number, f.name as string] as [number, string | null]))
        .catch(() => [] as [number, string | null][]);

      const en = await call<EnhancedGraphResult>('get_enhanced_call_graph', { functions: funs }).catch(() => null);
      setEnhanced(en);
      const rc = await call<RecompConfigResult>('generate_ps1_recomp_config', {
        binaryName: path.split(/[\\/]/).pop() ?? path,
        sections: [],
        functions: funs,
      }).catch(() => null);
      setRecomp(rc);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">PS1 analysis</h1>
        <p className="text-sm text-fg-secondary">
          String extraction, LUI+ORI constant pools, interrupt-handler heuristics and jump-table
          (state machine) dispatch detection.
        </p>
      </header>

      <Panel title="Analyse a PlayStation 1 binary">
        <div className="flex gap-2">
          <input
            className="flex-1 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
            value={path}
            placeholder="/path/to/ps1.elf — use a PS1 / ELF build"
            onChange={(e) => setPath(e.target.value)}
          />
          <Button variant="primary" disabled={busy || !path} onClick={run}>
            Analyse
          </Button>
        </div>
        {busy && <Spinner label="Analysing PS1 binary…" />}
        {error && <ErrorBox message={error} />}
      </Panel>
      {result && (
        <>
          <StatGrid>
            <Stat label="Strings" value={result.strings.length} />
            <Stat label="Constants" value={result.constants.length} />
            <Stat label="Interrupt handlers" value={result.interrupt_handlers.length} />
            <Stat label="State machines" value={result.state_machines.length} />
          </StatGrid>

          {enhanced && (
            <Panel title={`Enhanced call graph (${enhanced.total_functions} functions)`}>
              <p className="mb-2 text-sm text-fg-secondary">
                {enhanced.hot_paths.length > 0
                  ? `Hot paths: ${enhanced.hot_paths.join(', ')}`
                  : 'No hot paths flagged.'}
              </p>
              <div className="grid max-h-48 grid-cols-2 gap-x-4 overflow-auto font-mono text-xs sm:grid-cols-3">
                {enhanced.nodes.map((n, i) => (
                  <div key={i} className="flex justify-between gap-2 border-b border-app-border/30 py-0.5">
                    <span className="truncate text-fg">{n.name ?? `sub_${n.address.toString(16).toUpperCase()}`}</span>
                    <span className="text-fg-muted">{n.caller_count}→{n.callee_count}</span>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {recomp && (
            <Panel title={`PS1 recomp config (${recomp.function_count} functions)`}>
              <div className="space-y-1 font-mono text-xs">
                <div className="text-fg-secondary">binary: <span className="text-fg">{recomp.binary_name}</span></div>
                <div className="text-fg-secondary">sections: <span className="text-fg">{recomp.sections.length}</span></div>
                <div className="text-fg-secondary">functions: <span className="text-fg">{recomp.function_count}</span></div>
              </div>
            </Panel>
          )}

          {syms && (
            <Panel
              title={`PS1 symbol references (${syms.total_matches})`}
              actions={<Chip color="#10b981">{Object.keys(syms.per_library).length} libraries</Chip>}
            >
              {syms.matches.length === 0 ? (
                <div className="text-sm text-fg-muted">No PS1 SDK references matched.</div>
              ) : (
                <div className="max-h-56 overflow-auto">
                  <table className="w-full font-mono text-xs">
                    <thead className="sticky top-0 bg-app-panel text-left uppercase tracking-wide text-fg-muted">
                      <tr>
                        <th className="px-2 py-1">Symbol</th>
                        <th className="px-2 py-1">Library</th>
                        <th className="px-2 py-1">Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {syms.matches.map((m, i) => (
                        <tr key={i} className="border-t border-app-border/40">
                          <td className="px-2 py-1 font-semibold text-fg">{m.symbol}</td>
                          <td className="px-2 py-1"><Chip color="#22d3ee">{m.library}</Chip></td>
                          <td className="px-2 py-1 text-fg-secondary">{m.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          )}

          <Panel title={`Strings (${result.strings.length})`}>
            <div className="max-h-52 space-y-0.5 overflow-auto font-mono text-xs">
              {result.strings.length === 0 && <div className="text-fg-muted">No strings extracted.</div>}
              {result.strings.map((s, i) => (
                <div key={i} className="border-b border-app-border/30 py-0.5">
                  <span className="text-accent-bright">@{s.offset}</span>{' '}
                  <span className="text-fg">“{s.value}”</span>{' '}
                  <span className="text-fg-muted">({s.length} B)</span>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title={`Interrupt handlers (${result.interrupt_handlers.length})`}>
            {result.interrupt_handlers.length === 0 ? (
              <div className="text-sm text-fg-muted">None detected.</div>
            ) : (
              <div className="grid gap-2 sm:grid-cols-2">
                {result.interrupt_handlers.map((h, i) => (
                  <div key={i} className="rounded-lg border border-app-border bg-app-panel-soft p-2 font-mono text-xs">
                    <div className="text-accent-bright">offset {h.offset} · ~{h.size} B</div>
                    <div className="text-fg-secondary">{h.reasons.join(', ')}</div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}

