import { useEffect, useState } from 'react';
import { Button, Card, ErrorBox, Hint, Panel, Spinner } from '../components/ui';
import { useFile } from '../lib/FileContext';
import { getSupportedFormats, isBackendAvailable, openFileDialog, openFileMeta, probeBinary } from '../lib/tauri';
import { fmtBytes } from '../lib/format';

export default function HomeView() {
  const { loadPath } = useFile();
  const [path, setPath] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formats, setFormats] = useState<{ name: string; extensions: string[]; platforms: string[] }[]>([]);
  const [backend, setBackend] = useState(true);

  useEffect(() => {
    setBackend(isBackendAvailable());
    getSupportedFormats()
      .then(setFormats)
      .catch(() => setFormats([]));
  }, []);

  const doOpen = async (p: string) => {
    if (!p) return;
    setBusy(true);
    setError(null);
    try {
      const meta = await openFileMeta(p);
      if (meta && meta.success === false) {
        setError(meta.message || 'Could not open file');
        return;
      }
      const summary = await probeBinary(p);
      await loadPath(summary.path);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const onBrowse = async () => {
    const p = await openFileDialog();
    if (p) {
      setPath(p);
      await doOpen(p);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-fg">Open a binary</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Identify and route a file to the correct parser &mdash; ELF (PS1/PS2), XBE, XEX, Wii U, PS3, PS4/5 or GameBoy ROM.
        </p>
      </header>

      {!backend && (
        <ErrorBox message="Tauri backend not detected. Run inside the Aura Decomp Tool desktop shell to use these commands." />
      )}

      <Panel title="Open file">
        <div className="space-y-3">
          <div className="flex gap-2">
            <input
              className="flex-1 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              placeholder="/path/to/game.elf, game.xex, eboot.self…"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && doOpen(path)}
            />
            <Button variant="primary" disabled={busy || !path} onClick={() => doOpen(path)}>
              Open
            </Button>
          </div>
          <div className="flex items-center justify-between">
            <Button variant="ghost" onClick={onBrowse}>
              Browse…
            </Button>
            {busy && <Spinner label="Parsing…" />}
          </div>
          {error && <ErrorBox message={error} />}
        </div>
      </Panel>

      <Panel title="Supported formats">
        {formats.length === 0 ? (
          <Hint>Backend unavailable — supported formats will appear once running in the desktop shell.</Hint>
        ) : (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {formats.map((f) => (
              <Card key={f.name}>
                <div className="text-sm font-medium text-fg">{f.name}</div>
                <div className="mt-1 font-mono text-xs text-accent-bright">{f.extensions.join(', ')}</div>
                <div className="mt-0.5 text-xs text-fg-muted">Platforms: {f.platforms.join(', ')}</div>
              </Card>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="Quick start">
        <ol className="list-inside list-decimal space-y-1 text-sm text-fg-secondary">
          <li>Open a file (above) — the file is identified and routed automatically.</li>
          <li>Review the <b className="text-fg">Binary summary</b> and its section table.</li>
          <li>Pick a code section in <b className="text-fg">Disassembly</b>.</li>
          <li>Explore <b className="text-fg">Call graph</b> (ELF images) and run an <b className="text-fg">SDK scan</b>.</li>
          <li>Generate a full decomp project from the <b className="text-fg">Export</b> view.</li>
        </ol>
        <Hint>The window starts around {fmtBytes(256 * 1024)} of context; keep listings targeted.</Hint>
      </Panel>
    </div>
  );
}
