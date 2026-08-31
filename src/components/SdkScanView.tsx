import { useCallback, useEffect, useState } from 'react';
import { Button, Chip, ErrorBox, Panel, Spinner, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { scanSdk, SDK_PLATFORMS, sdkDbStats } from '../lib/tauri';
import type { SdkDbStats, SdkScanResult } from '../types';
import { hex32 } from '../lib/format';

export default function SdkScanView() {
  const { summary } = useFile();
  const [path, setPath] = useState(summary?.path ?? '');
  const [platform, setPlatform] = useState<string>('PS2');
  const [result, setResult] = useState<SdkScanResult | null>(null);
  const [stats, setStats] = useState<SdkDbStats | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (summary?.path) setPath(summary.path);
  }, [summary?.path]);

  const refreshStats = useCallback(async (plat: string) => {
    try {
      const s = await sdkDbStats(plat);
      setStats(s);
    } catch {
      setStats(null);
    }
  }, []);

  useEffect(() => {
    refreshStats(platform);
  }, [platform, refreshStats]);

  const run = async () => {
    if (!path) return;
    setBusy(true);
    setError(null);
    try {
      const r = await scanSdk(path, platform);
      setResult(r);
    } catch (e) {
      setError(String(e));
      setResult(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">SDK symbol scan</h1>
        <p className="text-sm text-fg-secondary">
          Match import names against the cross-platform SDK database (346 symbols) to auto-name functions.
        </p>
      </header>

      <Panel title="Scan parameters">
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
          <label>
            <span className="mb-1 block text-xs font-medium text-fg-muted">Platform</span>
            <select
              className="rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={platform}
              onChange={(e) => {
                setPlatform(e.target.value);
                setResult(null);
              }}
            >
              {SDK_PLATFORMS.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </label>
          <Button variant="primary" disabled={busy || !path} onClick={run}>
            Scan
          </Button>
        </div>
        {busy && <Spinner label="Scanning SDK symbols…" />}
        {error && <ErrorBox message={error} />}
      </Panel>

      {stats && (
        <StatGrid>
          <Stat label={`${platform} symbol DB`} value={stats.symbol_count} />
          <Stat label="Libraries in DB" value={stats.libraries.length} />
          <Stat label="All platforms" value={stats.total_symbols_all_platforms} />
          <Stat label="Detected libraries" value={result?.detected_libraries.length ?? 0} />
        </StatGrid>
      )}

      {stats && stats.libraries.length > 0 && (
        <Panel title={`Libraries in DB (${platform})`}>
          <div className="flex flex-wrap gap-2">
            {stats.libraries.map((lib) => (
              <Chip key={lib} color="#22d3ee">{lib}</Chip>
            ))}
          </div>
        </Panel>
      )}

      {result && (
        <Panel
          title={`Matches (${result.matched_count}) — ${result.total_functions_scanned} names scanned`}
          actions={<Chip color="#6366f1">{result.platform}</Chip>}
        >
          {result.matches.length === 0 ? (
            <div className="text-sm text-fg-muted">No SDK symbols matched. The binary may use a different platform or stripped names.</div>
          ) : (
            <div className="max-h-[55vh] overflow-auto rounded-lg border border-app-border">
              <table className="w-full font-mono text-[13px]">
                <thead className="sticky top-0 bg-app-panel text-xs uppercase tracking-wide text-fg-muted">
                  <tr>
                    <th className="px-3 py-2 text-left">Address</th>
                    <th className="px-3 py-2 text-left">Symbol</th>
                    <th className="px-3 py-2 text-left">Library</th>
                    <th className="px-3 py-2 text-left">Description</th>
                    <th className="px-3 py-2 text-left">Method</th>
                  </tr>
                </thead>
                <tbody>
                  {result.matches.map((m, i) => (
                    <tr key={i} className="border-t border-app-border/40 hover:bg-app-hover">
                      <td className="px-3 py-1 text-accent-bright">{hex32(m.address)}</td>
                      <td className="px-3 py-1 font-semibold text-fg">{m.name}</td>
                      <td className="px-3 py-1"><Chip color="#10b981">{m.library}</Chip></td>
                      <td className="px-3 py-1 text-fg-secondary">{m.description}</td>
                      <td className="px-3 py-1 text-fg-muted">{m.match_method}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}