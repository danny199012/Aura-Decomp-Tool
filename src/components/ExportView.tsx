import { useEffect, useState } from 'react';
import { Button, Chip, ErrorBox, Panel, Spinner, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { call, exportDecompProject, pickOutputFolder, SDK_PLATFORMS } from '../lib/tauri';

interface ExportResult {
  project_dir: string;
  files_written: string[];
  function_count: number;
  named_count: number;
  sdk_named_count: number;
  section_count: number;
  platform: string;
}

interface ConfigResult {
  toml_path: string;
  csv_path: string;
  function_count: number;
  from_symbols: number;
  from_jal_heuristic: number;
  sce_sdk_named: number;
  relocation_count: number;
}

export default function ExportView() {
  const { summary } = useFile();
  const [path, setPath] = useState(summary?.path ?? '');
  const [platform, setPlatform] = useState<string>('PS2');
  const [outDir, setOutDir] = useState('');
  const [result, setResult] = useState<ExportResult | null>(null);
  const [cfg, setCfg] = useState<ConfigResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyCfg, setBusyCfg] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (summary?.path) setPath(summary.path);
  }, [summary?.path]);

  const browseDir = async () => {
    const dir = await pickOutputFolder();
    if (dir) setOutDir(dir);
  };

  const run = async () => {
    if (!outDir) {
      setError('Choose an output directory first.');
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await exportDecompProject(path, platform, outDir);
      setResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const runConfig = async () => {
    if (!outDir) {
      setError('Choose an output directory first.');
      return;
    }
    setBusyCfg(true);
    setError(null);
    setCfg(null);
    try {
      const r = await call<ConfigResult>('generate_config_toml', { path, outputDir: outDir });
      setCfg(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusyCfg(false);
    }
  };

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">One-click decomp export</h1>
        <p className="text-sm text-fg-secondary">
          Emits a complete decomp project scaffold: functions.csv, symbol_addrs.txt, undefined_syms.txt,
          splat.yaml, config.toml, Makefile and a build README.
        </p>
      </header>

      <Panel title="Export parameters">
        <div className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <label className="min-w-[240px] flex-1">
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
                onChange={(e) => setPlatform(e.target.value)}
              >
                {SDK_PLATFORMS.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="flex gap-2">
            <input
              className="flex-1 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={outDir}
              placeholder="output directory"
              onChange={(e) => setOutDir(e.target.value)}
            />
            <Button variant="ghost" onClick={browseDir}>Browse…</Button>
            <Button variant="primary" disabled={busy || !outDir} onClick={run}>
              Export
            </Button>
          </div>
          <div className="flex items-center justify-between pt-1">
            <Button variant="ghost" onClick={runConfig} disabled={busyCfg || !outDir}>
              Generate ps2recomp config (config.toml + CSV)
            </Button>
            {busyCfg && <Spinner label="Generating config…" />}
          </div>
          {busy && <Spinner label="Writing decomp project…" />}
          {error && <ErrorBox message={error} />}
        </div>
      </Panel>

      {cfg && (
        <Panel title="ps2recomp config bundle">
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat label="functions" value={cfg.function_count} />
              <Stat label="from symbols" value={cfg.from_symbols} />
              <Stat label="JAL heuristic" value={cfg.from_jal_heuristic} />
              <Stat label="relocations" value={cfg.relocation_count} />
            </div>
            <ul className="font-mono text-xs">
              <li className="border-b border-app-border/30 py-1">config.toml → <span className="text-accent-bright">{cfg.toml_path}</span></li>
              <li className="py-1">functions.csv → <span className="text-accent-bright">{cfg.csv_path}</span></li>
            </ul>
          </div>
        </Panel>
      )}

      {result && (
        <>
          <StatGrid>
            <Stat label="Project dir" value={result.project_dir} />
            <Stat label="Functions" value={result.function_count} />
            <Stat label="Named" value={result.named_count} />
            <Stat label="SDK-named" value={result.sdk_named_count} />
          </StatGrid>

          <Panel
            title={`Files written (${result.files_written.length})`}
            actions={<Chip color="#10b981">{result.platform}</Chip>}
          >
            <ul className="space-y-1 font-mono text-xs">
              {result.files_written.map((f) => (
                <li key={f} className="flex items-center gap-2 border-b border-app-border/30 py-1">
                  <span className="text-accent-bright">✓</span>
                  <span className="break-all text-fg-secondary">{f}</span>
                </li>
              ))}
            </ul>
          </Panel>
        </>
      )}
    </div>
  );
}