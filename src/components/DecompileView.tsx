import { useState } from 'react';
import { Button, Chip, ErrorBox, Panel, Spinner, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { decompileFunction, decompileAll } from '../lib/tauri';
import type { DecompileResult, DecompileAllResult } from '../lib/tauri';
import { hex32 } from '../lib/format';

export default function DecompileView() {
  const { summary } = useFile();
  const [path, setPath] = useState(summary?.path ?? '');
  const [addr, setAddr] = useState('');
  const [single, setSingle] = useState<DecompileResult | null>(null);
  const [all, setAll] = useState<DecompileAllResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const decompOne = async () => {
    if (!path || !addr) return;
    setBusy(true); setError(null); setAll(null);
    try {
      const a = addr.trim().startsWith('0x') || addr.trim().startsWith('0X') ? addr.trim() : '0x' + addr.trim();
      setSingle(await decompileFunction(path, a));
    } catch (e) { setError(String(e)); setSingle(null); } finally { setBusy(false); }
  };

  const decompAll = async () => {
    if (!path) return;
    setBusy(true); setError(null); setSingle(null);
    try {
      setAll(await decompileAll(path, 200));
    } catch (e) { setError(String(e)); setAll(null); } finally { setBusy(false); }
  };

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">Decompiler (MIPS → pseudocode)</h1>
        <p className="text-sm text-fg-secondary">
          Pattern-based lifter that raises MIPS disassembly to C-like pseudocode — the headline
          feature closing the gap with Ghidra / Binary Ninja. Walks the per-function CFG and lifts
          each instruction to typed IR, then renders readable code.
        </p>
      </header>

      <Panel title="Decompile a function">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[240px]">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Binary path</span>
            <input className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={path} placeholder="/path/to/binary" onChange={(e) => setPath(e.target.value)} />
          </label>
          <label className="min-w-[180px]">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Function address (hex)</span>
            <input className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={addr} placeholder="0x80123456" onChange={(e) => setAddr(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') decompOne(); }} />
          </label>
          <Button variant="primary" disabled={busy || !path || !addr} onClick={decompOne}>Decompile</Button>
          <Button variant="ghost" disabled={busy || !path} onClick={decompAll}>Decompile all</Button>
        </div>
        {busy && <Spinner label="Lifting MIPS to pseudocode…" />}
        {error && <ErrorBox message={error} />}
      </Panel>

      {single && (
        <>
          <StatGrid>
            <Stat label="Function" value={single.name} />
            <Stat label="Entry" value={hex32(single.entry)} />
            <Stat label="Blocks" value={single.block_count} />
            <Stat label="Statements" value={single.stmt_count} />
          </StatGrid>
          <Panel title="Pseudocode">
            <pre className="overflow-auto rounded-lg border border-app-border bg-app-panel-soft p-4 font-mono text-[13px] leading-relaxed text-fg">
              {single.pseudocode}
            </pre>
          </Panel>
        </>
      )}

      {all && (
        <>
          <StatGrid>
            <Stat label="Functions decompiled" value={all.total} />
          </StatGrid>
          <Panel title={`All functions (${all.total})`}>
            <div className="max-h-[60vh] space-y-3 overflow-auto">
              {all.functions.map((f, i) => (
                <div key={i}>
                  <div className="mb-1 flex items-center gap-2">
                    <Chip color="#22d3ee">{hex32(f.entry)}</Chip>
                    <span className="font-mono text-sm font-semibold text-fg">{f.name}</span>
                    <span className="text-xs text-fg-muted">{f.block_count} blocks · {f.stmt_count} stmts</span>
                  </div>
                  <pre className="overflow-auto rounded-lg border border-app-border bg-app-panel-soft p-3 font-mono text-[12px] leading-relaxed text-fg">
                    {f.pseudocode}
                  </pre>
                </div>
              ))}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
