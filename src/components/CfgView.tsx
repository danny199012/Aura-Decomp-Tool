import { useState } from 'react';
import { Button, Chip, ErrorBox, Panel, Spinner, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { getCfgSummary, getXrefs } from '../lib/tauri';
import type { CfgSummary, XrefResult } from '../lib/tauri';
import { hex32 } from '../lib/format';

const KIND_COLORS: Record<string, string> = {
  call: '#22d3ee',
  jump: '#a78bfa',
  branch: '#f59e0b',
  data: '#10b981',
};

export default function CfgView() {
  const { summary } = useFile();
  const [path, setPath] = useState(summary?.path ?? '');
  const [cfg, setCfg] = useState<CfgSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [addr, setAddr] = useState('');
  const [xrefs, setXrefs] = useState<XrefResult | null>(null);
  const [xBusy, setXBusy] = useState(false);
  const [xError, setXError] = useState<string | null>(null);

  const run = async () => {
    if (!path) return;
    setBusy(true);
    setError(null);
    try {
      setCfg(await getCfgSummary(path));
    } catch (e) {
      setError(String(e));
      setCfg(null);
    } finally {
      setBusy(false);
    }
  };

  const lookupXrefs = async () => {
    if (!path || !addr) return;
    setXBusy(true);
    setXError(null);
    try {
      const a = addr.trim().startsWith('0x') || addr.trim().startsWith('0X')
        ? addr.trim()
        : '0x' + addr.trim();
      setXrefs(await getXrefs(path, a));
    } catch (e) {
      setXError(String(e));
      setXrefs(null);
    } finally {
      setXBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">Control-flow graph &amp; cross-references</h1>
        <p className="text-sm text-fg-secondary">
          Recursive-descent basic-block analysis (like Ghidra / Binary Ninja) plus a global
          cross-reference index — the navigation primitive those tools use.
        </p>
      </header>

      <Panel title="CFG analysis">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[240px]">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Binary path</span>
            <input
              className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={path}
              placeholder="/path/to/binary"
              onChange={(e) => setPath(e.target.value)}
            />
          </label>
          <Button variant="primary" disabled={busy || !path} onClick={run}>Analyze</Button>
        </div>
        {busy && <Spinner label="Building per-function CFGs…" />}
        {error && <ErrorBox message={error} />}
      </Panel>

      {cfg && (
        <>
          <StatGrid>
            <Stat label="Functions" value={cfg.functions.length} />
            <Stat label="Basic blocks" value={cfg.total_blocks} />
            <Stat label="CFG edges" value={cfg.total_edges} />
            <Stat label="Returning funcs" value={cfg.returning_functions} />
            <Stat label="Xref targets" value={cfg.xref_targets} />
          </StatGrid>

          <Panel title={`Per-function CFG (${cfg.functions.length})`}>
            <div className="max-h-[45vh] overflow-auto rounded-lg border border-app-border">
              <table className="w-full font-mono text-[13px]">
                <thead className="sticky top-0 bg-app-panel text-xs uppercase tracking-wide text-fg-muted">
                  <tr>
                    <th className="px-3 py-2 text-left">Entry</th>
                    <th className="px-3 py-2 text-left">Blocks</th>
                    <th className="px-3 py-2 text-left">Edges</th>
                    <th className="px-3 py-2 text-left">Returns</th>
                  </tr>
                </thead>
                <tbody>
                  {cfg.functions.map((f, i) => (
                    <tr key={i} className="border-t border-app-border/40 hover:bg-app-hover">
                      <td className="px-3 py-1 text-accent-bright">{hex32(f.entry)}</td>
                      <td className="px-3 py-1">{f.blocks}</td>
                      <td className="px-3 py-1">{f.edges}</td>
                      <td className="px-3 py-1">
                        {f.returns ? <Chip color="#10b981">yes</Chip> : <Chip color="#f59e0b">no</Chip>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}

      <Panel title="Cross-references to an address">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[240px]">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Address (hex)</span>
            <input
              className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={addr}
              placeholder="0x80123456"
              onChange={(e) => setAddr(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') lookupXrefs(); }}
            />
          </label>
          <Button variant="primary" disabled={xBusy || !path || !addr} onClick={lookupXrefs}>
            Find xrefs
          </Button>
        </div>
        {xBusy && <Spinner label="Looking up cross-references…" />}
        {xError && <ErrorBox message={xError} />}
        {xrefs && (
          <div className="mt-3">
            {xrefs.refs.length === 0 ? (
              <div className="text-sm text-fg-muted">No cross-references to {hex32(xrefs.target)}.</div>
            ) : (
              <div className="max-h-[35vh] overflow-auto rounded-lg border border-app-border">
                <table className="w-full font-mono text-[13px]">
                  <thead className="sticky top-0 bg-app-panel text-xs uppercase tracking-wide text-fg-muted">
                    <tr>
                      <th className="px-3 py-2 text-left">From</th>
                      <th className="px-3 py-2 text-left">Kind</th>
                    </tr>
                  </thead>
                  <tbody>
                    {xrefs.refs.map((r, i) => (
                      <tr key={i} className="border-t border-app-border/40 hover:bg-app-hover">
                        <td className="px-3 py-1 text-accent-bright">{hex32(r.from)}</td>
                        <td className="px-3 py-1"><Chip color={KIND_COLORS[r.kind] ?? '#888'}>{r.kind}</Chip></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}

