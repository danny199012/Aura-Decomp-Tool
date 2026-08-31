import { useMemo } from 'react';
import { Chip, Panel, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { fmtBytes, hex32 } from '../lib/format';

export default function BinaryView() {
  const { summary } = useFile();

  const metaRows = useMemo(() => {
    if (!summary) return [];
    return Object.entries(summary.meta).map(([k, v]) => ({
      k,
      v: typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v ?? '—'),
    }));
  }, [summary]);

  if (!summary) {
    return <div className="text-sm text-fg-muted">No file loaded. Open one from the home view first.</div>;
  }

  return (
    <div className="space-y-5">
      <header>
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-fg">{summary.filename}</h1>
          <Chip color="#6366f1">{summary.platform}</Chip>
          <Chip color="#10b981">{summary.identify}</Chip>
          {summary.littleEndian ? (
            <Chip color="#f59e0b">little-endian</Chip>
          ) : (
            <Chip color="#8b5cf6">big-endian</Chip>
          )}
        </div>
        <p className="mt-1 break-all font-mono text-xs text-fg-muted">{summary.path}</p>
      </header>

      <StatGrid>
        <Stat label="Sections" value={summary.sections.length} />
        <Stat label="Code sections" value={summary.codeSections.length} />
        <Stat label="Entry point" value={summary.entryPoint != null ? hex32(summary.entryPoint) : '—'} />
        <Stat label="Total (code+data)" value={fmtBytes(summary.sections.reduce((a, s) => a + s.size, 0))} />
      </StatGrid>

      <Panel title="Metadata">
        {metaRows.length === 0 ? (
          <div className="text-sm text-fg-muted">No platform-specific metadata available.</div>
        ) : (
          <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
            {metaRows.map((r) => (
              <div key={r.k} className="flex justify-between gap-4 border-b border-app-border/60 py-1 font-mono text-sm">
                <span className="text-fg-muted">{r.k}</span>
                <span className="text-right text-fg">{r.v}</span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel
        title={`Section table (${summary.sections.length})`}
        actions={<Chip color="#22d3ee">address · size</Chip>}
      >
        {summary.sections.length === 0 ? (
          <div className="text-sm text-fg-muted">
            No discrete sections exposed. Use the Disassembly view directly.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-sm">
              <thead>
                <tr className="border-b border-app-border text-xs uppercase tracking-wide text-fg-muted">
                  <th className="py-2 pr-3">Name</th>
                  <th className="py-2 pr-3">Address</th>
                  <th className="py-2 pr-3">Size</th>
                  <th className="py-2">Role</th>
                </tr>
              </thead>
              <tbody>
                {summary.sections.map((s) => (
                  <tr key={s.name} className="border-b border-app-border/50 last:border-0 hover:bg-app-hover">
                    <td className="py-1.5 pr-3 font-semibold text-fg">{s.name}</td>
                    <td className="py-1.5 pr-3 text-accent-bright">{hex32(s.address)}</td>
                    <td className="py-1.5 pr-3 text-fg-secondary">{fmtBytes(s.size)}</td>
                    <td className="py-1.5">
                      {s.isCode ? <Chip color="#22d3ee">code</Chip> : <Chip color="#94a3b8">data</Chip>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
