import { useEffect, useMemo, useState } from 'react';
import { Button, Chip, ErrorBox, Panel, Stat, StatGrid, Spinner } from './ui';
import { useFile } from '../lib/FileContext';
import { call, interactiveCallGraph } from '../lib/tauri';
import type { GraphNode, InteractiveCallGraph } from '../types';
import { hex32 } from '../lib/format';
import ForceGraph from './callgraph/ForceGraph';

export default function CallGraphView() {
  const { summary } = useFile();
  const [graph, setGraph] = useState<InteractiveCallGraph | null>(null);
  const [raw, setRaw] = useState<{ edges: number; external: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sel, setSel] = useState<GraphNode | null>(null);

  const elfEligible = summary ? summary.kind === 'elf' || summary.kind === 'ps1' : false;

  const load = async () => {
    if (!summary || !elfEligible) return;
    setBusy(true);
    setError(null);
    setSel(null);
    try {
      const g = await interactiveCallGraph(summary.path);
      setGraph(g);
      setRaw({ edges: g.edges.length, external: 0 });
      // Also call the base `get_call_graph` command to expose external targets.
      const base = await call<{ edges: unknown[]; external_targets: number[] }>('get_call_graph', { path: summary.path });
      setRaw({ edges: (base.edges ?? []).length, external: (base.external_targets ?? []).length });
    } catch (e) {
      setError(String(e));
      setGraph(null);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    setGraph(null);
    setSel(null);
    setRaw(null);
    if (summary && elfEligible) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary?.path]);

  const details = useMemo(() => {
    if (!sel || !graph) return null;
    const callers = graph.edges.filter((e) => e.target === sel.id).map((e) => e.source);
    const callees = graph.edges.filter((e) => e.source === sel.id).map((e) => e.target);
    const nodeByName = new Map(graph.nodes.map((n) => [n.id, n]));
    return { callers, callees, nodeByName };
  }, [sel, graph]);

  if (!summary) return <div className="text-sm text-fg-muted">No file loaded.</div>;
  if (!elfEligible) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-bold text-fg">Call graph</h1>
        <ErrorBox
          message={`Interactive call graph is currently backed by the ELF parser. ${summary.platform} support is a backend-hardening follow-up.`}
        />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-fg">Interactive call graph</h1>
          <p className="text-sm text-fg-secondary">Force-directed render of detected functions &amp; calls (D3.js).</p>
        </div>
        <Button variant="ghost" onClick={load} disabled={busy}>
          ↻ Reload
        </Button>
      </header>

      {graph && (
        <StatGrid>
          <Stat label="Functions" value={graph.statistics.total_functions} />
          <Stat label="Named" value={graph.statistics.named_functions} />
          <Stat label="Edges" value={graph.statistics.total_edges} />
          <Stat label="Libraries" value={graph.statistics.libraries.length} />
          {raw && <Stat label="External targets (get_call_graph)" value={raw.external} />}
        </StatGrid>
      )}

      {error && <ErrorBox message={error} />}
      {busy && !graph && <Spinner label="Building call graph…" />}
      {graph && <ForceGraph graph={graph} selectedId={sel?.id ?? null} onSelect={setSel} />}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {details ? (
          <Panel title={`Node — ${details.nodeByName.get(sel!.id)?.name ?? sel!.id}`}>
            <div className="space-y-1 font-mono text-sm">
              <div><span className="text-fg-muted">address</span> <span className="text-accent-bright">{hex32(sel!.address)}</span></div>
              <div><span className="text-fg-muted">size</span> <span className="text-fg">{sel!.size} B</span></div>
              <div><span className="text-fg-muted">library</span> <span className="text-fg">{sel!.library ?? '—'}</span></div>
              <div><span className="text-fg-muted">call_count</span> <span className="text-fg">{sel!.call_count}</span></div>
              <div><span className="text-fg-muted">called_by</span> <span className="text-fg">{sel!.called_by_count}</span></div>
              <div className="flex gap-2 pt-2">
                {sel!.is_entry && <Chip color="#f59e0b">entry</Chip>}
                {sel!.is_external && <Chip color="#94a3b8">external</Chip>}
                {sel!.is_named ? <Chip color="#22d3ee">named</Chip> : <Chip color="#64748b">anonymous</Chip>}
              </div>
            </div>
          </Panel>
        ) : (
          <Panel title="Node details">
            <div className="text-sm text-fg-muted">Click a graph node to inspect its callers and callees.</div>
          </Panel>
        )}
        <Panel title="Top hubs">
          {!graph || graph.statistics.hub_functions.length === 0 ? (
            <div className="text-sm text-fg-muted">No hub functions ranked.</div>
          ) : (
            <div className="max-h-56 space-y-1 overflow-auto font-mono text-xs">
              {graph.statistics.hub_functions.slice(0, 20).map((h, i) => (
                <button
                  key={`${h.name}-${i}`}
                  onClick={() => {
                    const hit = graph.nodes.find((n) => n.name === h.name);
                    if (hit) setSel(hit);
                  }}
                  className="flex w-full items-center justify-between gap-2 rounded border-b border-app-border/40 py-1 text-left hover:bg-app-hover"
                >
                  <span className="truncate text-fg">{i + 1}. {h.name}</span>
                  <span className="text-fg-muted">score {h.score}</span>
                </button>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {details && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Panel title={`Callers (${details.callers.length})`}>
            <CallList ids={details.callers} nodeByName={details.nodeByName} onPick={setSel} />
          </Panel>
          <Panel title={`Callees (${details.callees.length})`}>
            <CallList ids={details.callees} nodeByName={details.nodeByName} onPick={setSel} />
          </Panel>
        </div>
      )}
    </div>
  );
}

function CallList({ ids, nodeByName, onPick }: {
  ids: string[];
  nodeByName: Map<string, GraphNode>;
  onPick: (n: GraphNode) => void;
}) {
  if (ids.length === 0) return <div className="text-sm text-fg-muted">None.</div>;
  return (
    <div className="grid max-h-52 grid-cols-1 gap-x-4 overflow-auto sm:grid-cols-2">
      {ids.map((id) => {
        const n = nodeByName.get(id);
        if (!n) return null;
        return (
          <button
            key={id}
            onClick={() => onPick(n)}
            className="flex items-center gap-2 border-b border-app-border/40 py-0.5 text-left font-mono text-xs hover:bg-app-hover"
          >
            <span className="text-accent-bright">{hex32(n.address)}</span>
            <span className="truncate text-fg">{n.name}</span>
          </button>
        );
      })}
    </div>
  );
}

