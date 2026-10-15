import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Chip, ErrorBox, Hint, Kbd, Panel, Spinner, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { isBackendAvailable, pickOutputFolder } from '../lib/tauri';
import { fmtBytes } from '../lib/format';
import {
  cancelPs2Ingest,
  findAuraLauncher,
  findRecompiler,
  inspectDisc,
  onFileDrop,
  onIngestProgress,
  onPackageProgress,
  packageGame,
  pickDiscImage,
  pickRecompiler,
  pickRuntimeExe,
  playPackagedGame,
  revealInFileManager,
  runPs2Ingest,
  type DiscInfo,
  type ExtractMode,
  type IngestProgress,
  type IngestResult,
  type PackageProgress,
  type PackageResult,
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
const PREF_EXE = 'aura-wizard-runtime-exe';

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

  // Packaging (done step): turn the workspace + a built runtime into a game folder.
  const [exePath, setExePath] = useState(() => readPref(PREF_EXE));
  const [copyFiles, setCopyFiles] = useState(false);
  const [pkgBusy, setPkgBusy] = useState(false);
  const [pkgProgress, setPkgProgress] = useState<PackageProgress | null>(null);
  const [pkgResult, setPkgResult] = useState<PackageResult | null>(null);
  const [pkgError, setPkgError] = useState<string | null>(null);
  const [launcherFound, setLauncherFound] = useState<string | null>(null);

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
    let offPkg: (() => void) | undefined;
    void onPackageProgress((p) => setPkgProgress(p)).then((u) => {
      if (disposed) u();
      else offPkg = u;
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
      offPkg?.();
    };
  }, [inspect]);

  useEffect(() => {
    void findAuraLauncher().then(setLauncherFound);
  }, []);

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
    setPkgResult(null);
    setPkgProgress(null);
    setPkgError(null);
  };

  const browseExe = async () => {
    const p = await pickRuntimeExe();
    if (p) {
      setExePath(p);
      writePref(PREF_EXE, p);
    }
  };

  const makePackage = async () => {
    if (!result || !exePath) return;
    writePref(PREF_EXE, exePath);
    setPkgBusy(true);
    setPkgError(null);
    setPkgResult(null);
    setPkgProgress(null);
    try {
      setPkgResult(await packageGame(result.workspace, exePath, null, copyFiles));
    } catch (e) {
      const m = String(e);
      setPkgError(m.toLowerCase().includes('cancel') ? 'Cancelled.' : m);
    } finally {
      setPkgBusy(false);
    }
  };

  /** Re-run the ingest for the same disc, this time copying the whole disc. */
  const extractEverything = async () => {
    if (!result) return;
    setMode('all');
    setError(null);
    setPkgResult(null);
    setProgress(null);
    setCancelling(false);
    setStep('running');
    try {
      setResult(await runPs2Ingest(path, outRoot, 'all', null));
      setStep('done');
    } catch (e) {
      setError(String(e));
      setStep('done');
    }
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

  // Why the Build button is disabled, shown next to it (never a silent dead button).
  const blocker: string | null = !outRoot
    ? 'Choose an output folder first.'
    : runRecompiler && !recompiler
      ? 'Pick the ps2_recomp program, or turn off “Run it”.'
      : null;

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
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-sm font-medium text-fg">
                      Run the recompiler afterwards <span className="font-normal text-fg-muted">(optional)</span>
                    </span>
                    <label className="flex shrink-0 items-center gap-2 text-sm text-fg">
                      <input
                        type="checkbox"
                        checked={runRecompiler}
                        onChange={(e) => setRunRecompiler(e.target.checked)}
                      />
                      Run it
                    </label>
                  </div>
                  <p className="text-xs text-fg-muted">
                    <Kbd>ps2_recomp</Kbd> is a <b className="text-fg-secondary">separate program</b> from the open-source
                    PS2Recomp project that turns the config Aura writes into C++. You do <b className="text-fg-secondary">not</b>{' '}
                    need it to finish this wizard — leave this off and Aura still writes the whole project. You can run it
                    yourself later.
                  </p>
                  {runRecompiler && (
                    <>
                      <div className="flex gap-2">
                        <input
                          className="flex-1 rounded-lg border border-app-border bg-app-panel px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
                          placeholder="Path to ps2_recomp.exe (the compiled recompiler)"
                          value={recompiler}
                          onChange={(e) => setRecompiler(e.target.value)}
                        />
                        <Button variant="ghost" onClick={browseRecompiler}>
                          Browse…
                        </Button>
                      </div>
                      <Hint>
                        {detected
                          ? `Found ps2_recomp at ${detected}.`
                          : 'Not found on PATH. Pick the ps2_recomp program you built — not your game, the disc image or a config file.'}
                      </Hint>
                      {recompiler && !/ps2_?recomp/i.test(recompiler) && (
                        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs text-amber-200">
                          That file name does not look like ps2_recomp. It should be the compiled recompiler program.
                        </div>
                      )}
                    </>
                  )}
                </div>

                <div className="flex items-center justify-end gap-3">
                  {blocker && <span className="text-xs text-amber-200">{blocker}</span>}
                  <Button variant="primary" onClick={() => void start()} disabled={blocker !== null}>
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
                {result.stubbed.length > 0 && (
                  <PathRow label="BIOS routines stubbed" value={result.stubbed.join(', ')} />
                )}
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

          <Panel
            title="Make a double-click game folder"
            actions={
              <Chip color={result.extract_mode === 'all' ? '#10b981' : '#f59e0b'}>
                {result.extract_mode === 'all' ? 'full disc extracted' : 'executables only'}
              </Chip>
            }
          >
            <div className="space-y-3">
              <p className="text-sm text-fg-secondary">
                Once you have built the game runtime (the executable compiled from the files in{' '}
                <Kbd>recomp/generated</Kbd> plus upstream&apos;s runtime), Aura bundles it with the extracted disc and a
                launcher, so the game starts with a double-click instead of a command line.
              </p>

              {result.extract_mode !== 'all' && (
                <div className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                  <div>
                    Only the executables were extracted. The runtime reads the game&apos;s files from the extracted
                    disc, so a real game cannot run without the rest of it.
                  </div>
                  <Button variant="ghost" onClick={() => void extractEverything()} disabled={pkgBusy}>
                    Extract the entire disc now
                  </Button>
                </div>
              )}

              <div className="flex gap-2">
                <input
                  className="flex-1 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
                  placeholder="Path to the runtime exe you built (e.g. ps2EntryRunner.exe)"
                  value={exePath}
                  onChange={(e) => setExePath(e.target.value)}
                />
                <Button variant="ghost" onClick={() => void browseExe()} disabled={pkgBusy}>
                  Browse…
                </Button>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <label className="flex items-center gap-2 text-xs text-fg-muted">
                  <input type="checkbox" checked={copyFiles} onChange={(e) => setCopyFiles(e.target.checked)} />
                  Copy the disc files instead of linking them (uses more disk space)
                </label>
                <Button variant="primary" onClick={() => void makePackage()} disabled={pkgBusy || !exePath}>
                  {pkgBusy ? 'Packaging…' : 'Create game folder'}
                </Button>
              </div>
              {!exePath && <Hint>Choose the built executable first. Aura copies it; it does not modify it.</Hint>}
              <Hint>
                {launcherFound
                  ? 'Launcher program found: the folder gets a Play <game>.exe that opens without a console window.'
                  : 'Launcher program (aura-launch) not found next to Aura, so the folder gets a Play .cmd instead, which briefly shows a console window. Build it with `cargo build --release` in the cli folder.'}
              </Hint>

              {pkgBusy && pkgProgress && pkgProgress.bytes_total > 0 && (
                <div className="space-y-1">
                  <div className="h-2 overflow-hidden rounded-full bg-app-panel-soft">
                    <div
                      className="h-full rounded-full bg-accent transition-all"
                      style={{ width: `${Math.round((pkgProgress.bytes_done / pkgProgress.bytes_total) * 100)}%` }}
                    />
                  </div>
                  <div className="font-mono text-xs text-fg-muted">
                    {pkgProgress.files_done}/{pkgProgress.files_total} files · {fmtBytes(pkgProgress.bytes_done)} /{' '}
                    {fmtBytes(pkgProgress.bytes_total)}
                  </div>
                </div>
              )}
              {pkgBusy && <Spinner label="Assembling the game folder…" />}
              {pkgError && <ErrorBox message={pkgError} />}

              {pkgResult && (
                <div className="space-y-3 border-t border-app-border pt-3">
                  <StatGrid>
                    <Stat label="Disc files" value={pkgResult.disc_files.toLocaleString()} />
                    <Stat label="Disc data" value={fmtBytes(pkgResult.disc_bytes)} />
                    <Stat
                      label="Disc tree"
                      value={pkgResult.disc_method === 'hardlink' ? 'linked (no extra space)' : pkgResult.disc_method}
                    />
                    <Stat label="Launcher" value={pkgResult.launcher_kind === 'exe' ? '.exe' : '.cmd'} />
                  </StatGrid>
                  <ul className="text-xs">
                    <PathRow label="Game folder" value={pkgResult.package_dir} />
                    <PathRow label="Double-click this" value={pkgResult.launcher} />
                    <PathRow label="Boot file" value={pkgResult.boot_elf} />
                    {pkgResult.dlls.length > 0 && <PathRow label="DLLs bundled" value={pkgResult.dlls.join(', ')} />}
                  </ul>
                  {!pkgResult.complete && (
                    <ErrorBox message="This folder has no game data (executables only), so it cannot run a real game." />
                  )}
                  {pkgResult.warnings.map((w) => (
                    <div
                      key={w}
                      className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
                    >
                      {w}
                    </div>
                  ))}
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="primary"
                      onClick={() => void playPackagedGame(pkgResult.launcher).catch((e) => setPkgError(String(e)))}
                    >
                      Play
                    </Button>
                    <Button variant="ghost" onClick={() => void revealInFileManager(pkgResult.package_dir)}>
                      Show game folder
                    </Button>
                  </div>
                  <Hint>
                    This folder contains code translated from the game plus the game&apos;s own data. It is for this
                    computer only — do not share or upload it.
                  </Hint>
                </div>
              )}
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
