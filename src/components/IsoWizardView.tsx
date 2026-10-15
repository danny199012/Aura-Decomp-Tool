import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Chip, ErrorBox, Hint, Kbd, Panel, Spinner, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { isBackendAvailable, pickOutputFolder } from '../lib/tauri';
import { fmtBytes } from '../lib/format';
import {
  cancelPs2Ingest,
  findRecompiler,
  inspectDisc,
  onFileDrop,
  onIngestProgress,
  pickDiscImage,
  pickRecompiler,
  revealInFileManager,
  runPs2Ingest,
  type DiscInfo,
  type ExtractMode,
  type IngestProgress,
  type IngestResult,
} from '../lib/ingest';
import type { ViewId } from './Sidebar';

type Step = 'pick' | 'review' | 'running' | 'done';

const STEPS: { id: Step; label: string }[] = [
  { id: 'pick', label: 'Choose disc' },
  { id: 'review', label: 'Review' },
  { id: 'running', label: 'Build' },
  { id: 'done', label: 'Done' },
];

const PREF_OUT = 'aura-wizard-out';
const PREF_RECOMP = 'aura-wizard-recompiler';

/** localStorage that never throws (private windows, blocked storage). */
function readPref(key: string): string {
  try {
    return localStorage.getItem(key) ?? '';
  } catch {
    return '';
  }
}
function writePref(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* preference simply isn't remembered */
  }
}

const DISC_EXT = /\.(iso|bin|img|cue|mdf|nrg)$/i;

function StepBar({ step }: { step: Step }) {
  const idx = STEPS.findIndex((s) => s.id === step);
  return (
    <ol className="flex flex-wrap items-center gap-2 text-xs">
      {STEPS.map((s, i) => (
        <li key={s.id} className="flex items-center gap-2">
          <span
            className={`grid h-5 w-5 place-items-center rounded-full text-[11px] font-bold ${
              i < idx
                ? 'bg-accent/30 text-accent-bright'
                : i === idx
                  ? 'bg-accent text-white'
                  : 'bg-app-panel-soft text-fg-muted'
            }`}
          >
            {i < idx ? '✓' : i + 1}
          </span>
          <span className={i === idx ? 'font-semibold text-fg' : 'text-fg-muted'}>{s.label}</span>
          {i < STEPS.length - 1 && <span className="text-fg-faint">›</span>}
        </li>
      ))}
    </ol>
  );
}

function PathRow({ label, value }: { label: string; value: string }) {
  return (
    <li className="flex flex-col gap-0.5 border-b border-app-border/30 py-1.5 sm:flex-row sm:items-center sm:gap-3">
      <span className="w-36 shrink-0 text-fg-muted">{label}</span>
      <span className="break-all font-mono text-accent-bright">{value}</span>
    </li>
  );
}

export default function IsoWizardView({ onNavigate }: { onNavigate: (v: ViewId) => void }) {
  const { loadPath } = useFile();
  const backend = isBackendAvailable();

  const [step, setStep] = useState<Step>('pick');
  const [path, setPath] = useState('');
  const [info, setInfo] = useState<DiscInfo | null>(null);
  const [mode, setMode] = useState<ExtractMode>('executables');
  const [outRoot, setOutRoot] = useState(() => readPref(PREF_OUT));
  const [runRecompiler, setRunRecompiler] = useState(false);
  const [recompiler, setRecompiler] = useState(() => readPref(PREF_RECOMP));
  const [detected, setDetected] = useState<string | null>(null);
  const [progress, setProgress] = useState<IngestProgress | null>(null);
  const [result, setResult] = useState<IngestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  // Drop handler must see the latest step without re-subscribing.
  const stepRef = useRef<Step>(step);
  stepRef.current = step;

  const inspect = useCallback(async (p: string) => {
    if (!p) return;
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      const i = await inspectDisc(p);
      setPath(p);
      setInfo(i);
      setStep('review');
    } catch (e) {
      setError(String(e));
      setStep('pick');
    } finally {
      setBusy(false);
    }
  }, []);

  // Progress events + drag-and-drop subscriptions.
  useEffect(() => {
    let offProgress: (() => void) | undefined;
    let offDrop: (() => void) | undefined;
    let disposed = false;
    void onIngestProgress((p) => setProgress(p)).then((u) => {
      if (disposed) u();
      else offProgress = u;
    });
    void onFileDrop((paths) => {
      if (stepRef.current !== 'pick' && stepRef.current !== 'review') return;
      const hit = paths.find((p) => DISC_EXT.test(p)) ?? paths[0];
      if (hit) void inspect(hit);
    }).then((u) => {
      if (disposed) u();
      else offDrop = u;
    });
    return () => {
      disposed = true;
      offProgress?.();
      offDrop?.();
    };
  }, [inspect]);

  useEffect(() => {
    void findRecompiler().then((p) => {
      setDetected(p);
      if (p && !readPref(PREF_RECOMP)) setRecompiler(p);
    });
  }, []);

  const browseDisc = async () => {
    const p = await pickDiscImage();
    if (p) await inspect(p);
  };

  const browseOut = async () => {
    const d = await pickOutputFolder();
    if (d) {
      setOutRoot(d);
      writePref(PREF_OUT, d);
    }
  };

  const browseRecompiler = async () => {
    const p = await pickRecompiler();
    if (p) {
      setRecompiler(p);
      setRunRecompiler(true);
      writePref(PREF_RECOMP, p);
    }
  };

  const start = async () => {
    if (!info || !outRoot) return;
    writePref(PREF_OUT, outRoot);
    if (recompiler) writePref(PREF_RECOMP, recompiler);
    setError(null);
    setResult(null);
    setProgress(null);
    setCancelling(false);
    setStep('running');
    try {
      const r = await runPs2Ingest(path, outRoot, mode, runRecompiler && recompiler ? recompiler : null);
      setResult(r);
      setStep('done');
    } catch (e) {
      const msg = String(e);
      setError(msg.toLowerCase().includes('cancel') ? 'Cancelled. Anything already extracted was left in place.' : msg);
      setStep('review');
    }
  };

  const cancel = async () => {
    setCancelling(true);
    try {
      await cancelPs2Ingest();
    } catch {
      /* the run will finish or fail on its own */
    }
  };

  const reset = () => {
    setStep('pick');
    setInfo(null);
    setResult(null);
    setProgress(null);
    setError(null);
    setPath('');
  };

  const openInAura = async () => {
    if (!result) return;
    try {
      await loadPath(result.elf_path);
      onNavigate('binary');
    } catch (e) {
      setError(String(e));
    }
  };

  const pct = Math.round((progress?.fraction ?? 0) * 100);

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <header className="space-y-3">
        <div>
          <h1 className="text-2xl font-bold text-fg">One-click disc wizard</h1>
          <p className="mt-1 text-sm text-fg-secondary">
            Point Aura at a PS2 disc image you own. It reads the disc, finds the boot executable, extracts what it
            needs and writes a ready-to-run <Kbd>ps2_recomp</Kbd> project.
          </p>
        </div>
        <StepBar step={step} />
      </header>

      {!backend && (
        <ErrorBox message="Tauri backend not detected. Run inside the Aura Decomp Tool desktop shell to use the wizard." />
      )}
      {error && <ErrorBox message={error} />}

      {/* ---------------------------------------------------------------- 1 */}
      {step === 'pick' && (
        <Panel title="1 · Choose your disc image">
          <div className="space-y-3">
            <div className="rounded-xl border-2 border-dashed border-app-border bg-app-panel-soft px-6 py-8 text-center">
              <div className="text-sm font-medium text-fg">Drop a disc image here</div>
              <div className="mt-1 text-xs text-fg-muted">
                .iso, or .bin / .img / .mdf (raw 2352-byte sectors), or a .cue sheet
              </div>
              <div className="mt-4">
                <Button variant="primary" onClick={browseDisc} disabled={busy || !backend}>
                  Browse for disc image…
                </Button>
              </div>
            </div>
            <div className="flex gap-2">
              <input
                className="flex-1 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
                placeholder="…or paste a path to an .iso / .cue"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && void inspect(path)}
              />
              <Button variant="ghost" disabled={busy || !path} onClick={() => void inspect(path)}>
                Inspect
              </Button>
            </div>
            {busy && <Spinner label="Reading the disc…" />}
            <Hint>
              Compressed formats (CHD, CSO/ZSO, archives) must be converted to a plain .iso/.bin first. Your image is
              only read, never modified.
            </Hint>
          </div>
        </Panel>
      )}

      {/* ---------------------------------------------------------------- 2 */}
      {step === 'review' && info && (
        <>
          <Panel
            title="2 · What Aura found"
            actions={
              <>
                <Chip color={info.platform === 'PS2' ? '#10b981' : '#f59e0b'}>{info.platform}</Chip>
                <Button variant="ghost" onClick={reset}>
                  Choose another
                </Button>
              </>
            }
          >
            <div className="space-y-3">
              <div>
                <div className="text-lg font-semibold text-fg">{info.display_name}</div>
                <div className="font-mono text-xs text-fg-muted">{info.image_path}</div>
              </div>
              <StatGrid>
                <Stat label="Serial" value={info.serial ?? '—'} />
                <Stat label="Region" value={info.region} />
                <Stat label="Boot file" value={info.boot_file ?? '—'} />
                <Stat label="Video mode" value={info.vmode ?? '—'} />
                <Stat label="Files" value={info.file_count.toLocaleString()} />
                <Stat label="Disc data" value={fmtBytes(info.total_bytes)} />
                <Stat label="Executables" value={`${info.executable_count} ELF/IRX`} />
                <Stat label="Sector layout" value={info.layout.split(' (')[0]} />
              </StatGrid>

              {info.warnings.map((w) => (
                <div
                  key={w}
                  className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
                >
                  {w}
                </div>
              ))}

              {!info.can_ingest && (
                <ErrorBox
                  message={
                    info.platform === 'PS1'
                      ? 'This is a PS1 disc. The one-click recomp pipeline targets PS2 for now; the disc itself reads fine, so you can still extract it from the command line (aura-cli disc-extract).'
                      : info.platform === 'PS2'
                        ? 'The boot executable could not be used (missing, packed or not a PS2 ELF). See the warnings above.'
                        : 'This does not look like a PlayStation game disc (no BOOT2 entry in SYSTEM.CNF).'
                  }
                />
              )}
            </div>
          </Panel>

          {info.can_ingest && (
            <Panel title="3 · Options">
              <div className="space-y-4">
                <fieldset className="space-y-2">
                  <legend className="mb-1 text-xs font-medium text-fg-muted">What to copy off the disc</legend>
                  {(
                    [
                      ['executables', 'Executables only (recommended)', `The boot ELF, SYSTEM.CNF and ${info.executable_count} ELF/IRX modules — a few MB. Enough to analyse and recompile.`],
                      ['all', 'Entire disc', `All ${info.file_count.toLocaleString()} files (${fmtBytes(info.total_bytes)}). Needs that much free disk space.`],
                    ] as const
                  ).map(([val, title, desc]) => (
                    <label
                      key={val}
                      className={`flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2 ${
                        mode === val ? 'border-accent bg-accent/10' : 'border-app-border bg-app-panel-soft'
                      }`}
                    >
                      <input
                        type="radio"
                        name="mode"
                        className="mt-1"
                        checked={mode === val}
                        onChange={() => setMode(val)}
                      />
                      <span>
                        <span className="block text-sm font-medium text-fg">{title}</span>
                        <span className="block text-xs text-fg-muted">{desc}</span>
                      </span>
                    </label>
                  ))}
                </fieldset>

                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-fg-muted">Output folder</span>
                  <div className="flex gap-2">
                    <input
                      className="flex-1 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
                      placeholder="Where to create the game workspace"
                      value={outRoot}
                      onChange={(e) => setOutRoot(e.target.value)}
                    />
                    <Button variant="ghost" onClick={browseOut}>
                      Browse…
                    </Button>
                  </div>
                  <span className="mt-1 block text-xs text-fg-muted">
                    A <Kbd>{info.serial ?? 'game'}</Kbd> folder is created inside it.
                  </span>
                </label>

                <div className="space-y-2 rounded-lg border border-app-border bg-app-panel-soft p-3">
                  <label className="flex items-center gap-2 text-sm text-fg">
                    <input
                      type="checkbox"
                      checked={runRecompiler}
                      onChange={(e) => setRunRecompiler(e.target.checked)}
                    />
                    Also run <Kbd>ps2_recomp</Kbd> when the project is written
                  </label>
                  {runRecompiler && (
                    <div className="flex gap-2">
                      <input
                        className="flex-1 rounded-lg border border-app-border bg-app-panel px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
                        placeholder="Path to the ps2_recomp binary"
                        value={recompiler}
                        onChange={(e) => setRecompiler(e.target.value)}
                      />
                      <Button variant="ghost" onClick={browseRecompiler}>
                        Browse…
                      </Button>
                    </div>
                  )}
                  <Hint>
                    {detected
                      ? `Found ps2_recomp at ${detected}.`
                      : 'ps2_recomp was not found on PATH. You build it from the upstream PS2Recomp project; the wizard still writes the full project without it.'}
                  </Hint>
                </div>

                <div className="flex justify-end">
                  <Button
                    variant="primary"
                    onClick={() => void start()}
                    disabled={!outRoot || (runRecompiler && !recompiler)}
                  >
                    Build project
                  </Button>
                </div>
              </div>
            </Panel>
          )}
        </>
      )}

      {/* ---------------------------------------------------------------- 3 */}
      {step === 'running' && (
        <Panel
          title="Building…"
          actions={
            <Button variant="danger" onClick={() => void cancel()} disabled={cancelling}>
              {cancelling ? 'Stopping…' : 'Cancel'}
            </Button>
          }
        >
          <div className="space-y-3">
            <div className="h-2.5 overflow-hidden rounded-full bg-app-panel-soft">
              <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${pct}%` }} />
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="truncate text-fg-secondary">{progress?.message ?? 'Starting…'}</span>
              <span className="ml-3 font-mono text-fg">{pct}%</span>
            </div>
            {progress && progress.files_total > 0 && progress.stage === 'extract' && (
              <div className="font-mono text-xs text-fg-muted">
                {progress.files_done}/{progress.files_total} files · {fmtBytes(progress.bytes_done)} /{' '}
                {fmtBytes(progress.bytes_total)}
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* ---------------------------------------------------------------- 4 */}
      {step === 'done' && result && (
        <>
          <Panel
            title={`${result.display_name}${result.serial ? ` · ${result.serial}` : ''}`}
            actions={<Chip color="#10b981">Project ready</Chip>}
          >
            <div className="space-y-4">
              <StatGrid>
                <Stat label="Functions found" value={result.function_count.toLocaleString()} />
                <Stat label="SDK-named" value={result.sdk_named.toLocaleString()} />
                <Stat label="Files extracted" value={result.extracted_files.toLocaleString()} />
                <Stat label="Extracted size" value={fmtBytes(result.extracted_bytes)} />
              </StatGrid>

              <ul className="text-xs">
                <PathRow label="Workspace" value={result.workspace} />
                <PathRow label="Boot ELF" value={result.elf_path} />
                <PathRow label="ps2_recomp config" value={result.config_toml} />
                <PathRow label="Function map" value={result.functions_csv} />
                <PathRow label="Generated C++ goes to" value={result.recomp_output_dir} />
                <PathRow label="Extracted disc files" value={result.disc_dir} />
              </ul>

              <div className="flex flex-wrap gap-2">
                <Button variant="primary" onClick={() => void openInAura()}>
                  Open boot ELF in Aura
                </Button>
                <Button variant="ghost" onClick={() => void revealInFileManager(result.workspace)}>
                  Show folder
                </Button>
                <Button variant="ghost" onClick={reset}>
                  Another disc
                </Button>
              </div>
            </div>
          </Panel>

          {result.recompiler && (
            <Panel
              title="ps2_recomp run"
              actions={
                <Chip color={result.recompiler.success ? '#10b981' : '#ef4444'}>
                  {result.recompiler.success ? 'succeeded' : 'failed'}
                </Chip>
              }
            >
              <div className="space-y-2">
                <div className="text-xs text-fg-muted">
                  {result.recompiler.generated_files} file(s) in the output folder · log:{' '}
                  <span className="font-mono">{result.recompiler.log_path}</span>
                </div>
                {result.recompiler.error && <ErrorBox message={result.recompiler.error} />}
                {result.recompiler.log_tail.length > 0 && (
                  <pre className="max-h-48 overflow-auto rounded-lg border border-app-border bg-app-panel-soft p-3 font-mono text-[11px] text-fg-secondary">
                    {result.recompiler.log_tail.join('\n')}
                  </pre>
                )}
              </div>
            </Panel>
          )}

          {result.warnings.length > 0 && (
            <Panel title="Warnings">
              <ul className="list-inside list-disc space-y-1 text-sm text-amber-200">
                {result.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </Panel>
          )}

          <Panel title="What happens next">
            <ol className="list-inside list-decimal space-y-2 text-sm text-fg-secondary">
              {result.next_steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
            <div className="mt-3">
              <Hint>
                Aura prepares the project; turning it into a playable executable needs the upstream ps2recomp
                toolchain and runtime, which are experimental. The same steps are saved in README.md next to the
                config.
              </Hint>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
