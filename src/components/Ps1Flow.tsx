import { useEffect, useState } from 'react';
import { Button, Chip, ErrorBox, Hint, Kbd, Panel, Spinner, Stat, StatGrid } from './ui';
import { pickOutputFolder } from '../lib/tauri';
import { fmtBytes } from '../lib/format';
import {
  buildPs1Game,
  cancelPs2Ingest,
  onBuildProgress,
  onIngestProgress,
  planPs1Build,
  playPs1Game,
  revealInFileManager,
  runPs1Ingest,
  type BuildProgress,
  type DiscInfo,
  type IngestProgress,
  type Ps1BuildPlan,
  type Ps1BuildResult,
  type Ps1IngestResult,
  type ToolStatus,
} from '../lib/ingest';

const PREF_OUT = 'aura-wizard-out';
const PREF_CACHE = 'aura-wizard-ps1-cache';

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

const hex = (n: number) => `0x${n.toString(16).toUpperCase().padStart(8, '0')}`;
const fmtClock = (secs: number) => {
  const s = Math.max(0, Math.round(secs));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};

function ToolChip({ tool }: { tool: ToolStatus }) {
  return (
    <li
      className={`rounded-lg border px-3 py-2 ${
        tool.found ? 'border-app-border bg-app-panel-soft' : 'border-red-500/40 bg-red-500/10'
      }`}
    >
      <span className={tool.found ? 'text-accent-bright' : 'text-red-300'}>{tool.found ? '✓' : '✗'}</span>{' '}
      <span className="font-medium text-fg">{tool.name}</span>
      <div className="truncate font-mono text-[11px] text-fg-muted">{tool.path ?? tool.detail}</div>
    </li>
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

/**
 * The PS1 path of the disc wizard: review the disc, prepare a workspace
 * (decompressing a CHD into the cue sheet PSXRecomp needs), show exactly what
 * a build downloads and asks for consent, then build and offer Play.
 */
export default function Ps1Flow({
  info,
  path,
  onChooseAnother,
}: {
  info: DiscInfo;
  path: string;
  onChooseAnother: () => void;
}) {
  const [outRoot, setOutRoot] = useState(() => readPref(PREF_OUT));
  const [cacheDir, setCacheDir] = useState(() => readPref(PREF_CACHE));
  const [prepared, setPrepared] = useState<Ps1IngestResult | null>(null);
  const [prepBusy, setPrepBusy] = useState(false);
  const [prepProgress, setPrepProgress] = useState<IngestProgress | null>(null);
  const [prepError, setPrepError] = useState<string | null>(null);

  const [plan, setPlan] = useState<Ps1BuildPlan | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [buildBusy, setBuildBusy] = useState(false);
  const [buildProgress, setBuildProgress] = useState<BuildProgress | null>(null);
  const [buildResult, setBuildResult] = useState<Ps1BuildResult | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  useEffect(() => {
    let disposed = false;
    let offIngest: (() => void) | undefined;
    let offBuild: (() => void) | undefined;
    void onIngestProgress((p) => setPrepProgress(p)).then((u) => (disposed ? u() : (offIngest = u)));
    void onBuildProgress((p) => setBuildProgress(p)).then((u) => (disposed ? u() : (offBuild = u)));
    return () => {
      disposed = true;
      offIngest?.();
      offBuild?.();
    };
  }, []);

  // Re-plan whenever the workspace, the cache folder or a finished build changes.
  const workspace = prepared?.workspace ?? '';
  const nonce = buildResult?.exe ?? '';
  useEffect(() => {
    if (!workspace) {
      setPlan(null);
      return;
    }
    let live = true;
    setPlanError(null);
    planPs1Build(workspace, cacheDir.trim() || null)
      .then((p) => live && setPlan(p))
      .catch((e) => live && setPlanError(String(e)));
    return () => {
      live = false;
    };
  }, [workspace, cacheDir, nonce]);

  const browseOut = async () => {
    const d = await pickOutputFolder();
    if (d) {
      setOutRoot(d);
      writePref(PREF_OUT, d);
    }
  };
  const browseCache = async () => {
    const d = await pickOutputFolder();
    if (d) {
      setCacheDir(d);
      writePref(PREF_CACHE, d);
    }
  };

  const prepare = async () => {
    if (!outRoot) return;
    writePref(PREF_OUT, outRoot);
    setPrepBusy(true);
    setPrepError(null);
    setPrepProgress(null);
    setCancelling(false);
    try {
      setPrepared(await runPs1Ingest(path, outRoot));
    } catch (e) {
      const m = String(e);
      setPrepError(m.toLowerCase().includes('cancel') ? 'Cancelled.' : m);
    } finally {
      setPrepBusy(false);
    }
  };

  const build = async () => {
    if (!prepared || !plan) return;
    writePref(PREF_CACHE, cacheDir);
    setBuildBusy(true);
    setBuildError(null);
    setBuildResult(null);
    setBuildProgress(null);
    setCancelling(false);
    try {
      // The button's label told the user what is downloaded; clicking it is the consent.
      setBuildResult(await buildPs1Game(prepared.workspace, cacheDir.trim() || null, plan.downloads.length > 0));
    } catch (e) {
      const m = String(e);
      setBuildError(m.toLowerCase().includes('cancel') ? 'Build cancelled. Cached downloads are kept.' : m);
    } finally {
      setBuildBusy(false);
    }
  };

  const cancel = async () => {
    setCancelling(true);
    try {
      await cancelPs2Ingest(); // the busy/cancel flags are shared by every long job
    } catch {
      /* the job will finish or fail on its own */
    }
  };

  const prepPct = Math.round((prepProgress?.fraction ?? 0) * 100);
  const buildPct = Math.round((buildProgress?.fraction ?? 0) * 100);
  const estMinutes = plan ? Math.max(1, Math.round(plan.estimate_secs / 60)) : 0;
  const tc = plan?.toolchain;

  return (
    <>
      <Panel
        title="2 · What Aura found"
        actions={
          <>
            <Chip color="#6366f1">PS1</Chip>
            <Button variant="ghost" onClick={onChooseAnother} disabled={prepBusy || buildBusy}>
              Choose another
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div>
            <div className="text-lg font-semibold text-fg">{prepared?.title ?? info.display_name}</div>
            <div className="font-mono text-xs text-fg-muted">{info.image_path}</div>
          </div>
          <StatGrid>
            <Stat label="Serial" value={info.serial ?? '—'} />
            <Stat label="Region" value={info.region} />
            <Stat label="Boot file" value={info.boot_file ?? '—'} />
            <Stat label="Program" value={info.psx_exe ? `PS-X EXE · ${fmtBytes(info.psx_exe.text_size)}` : '—'} />
            <Stat label="Loads at" value={info.psx_exe ? hex(info.psx_exe.load_addr) : '—'} />
            <Stat label="Starts at" value={info.psx_exe ? hex(info.psx_exe.entry_pc) : '—'} />
            <Stat label="Files" value={info.file_count.toLocaleString()} />
            <Stat label="Disc data" value={fmtBytes(info.total_bytes)} />
          </StatGrid>
          {info.warnings.map((w) => (
            <div key={w} className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
              {w}
            </div>
          ))}
          {!info.can_ingest && (
            <ErrorBox message="The boot file is not a PS-X EXE (it may be packed or use a custom loader), so this disc cannot be recompiled directly." />
          )}
        </div>
      </Panel>

      {info.can_ingest && !prepared && (
        <Panel title="3 · Prepare">
          <div className="space-y-4">
            <p className="text-sm text-fg-secondary">
              Aura reads your disc image (it is never modified) and, when it is a <Kbd>.chd</Kbd>, unpacks its data track
              into a cue/bin pair — the format PSXRecomp&apos;s project setup reads. Nothing is downloaded in this step.
            </p>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-fg-muted">Output folder</span>
              <div className="flex gap-2">
                <input
                  className="flex-1 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
                  placeholder="Where to create the game workspace"
                  value={outRoot}
                  onChange={(e) => setOutRoot(e.target.value)}
                />
                <Button variant="ghost" onClick={() => void browseOut()} disabled={prepBusy}>
                  Browse…
                </Button>
              </div>
              <span className="mt-1 block text-xs text-fg-muted">
                A <Kbd>{info.serial ?? 'game'}</Kbd> folder is created inside it.
              </span>
            </label>

            {prepBusy && (
              <div className="space-y-2">
                <div className="h-2.5 overflow-hidden rounded-full bg-app-panel-soft">
                  <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${prepPct}%` }} />
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="truncate text-fg-secondary">{prepProgress?.message ?? 'Starting…'}</span>
                  <span className="ml-3 shrink-0 font-mono text-fg">
                    {prepPct}%
                    {prepProgress && prepProgress.bytes_total > 0
                      ? ` · ${fmtBytes(prepProgress.bytes_done)} / ${fmtBytes(prepProgress.bytes_total)}`
                      : ''}
                  </span>
                </div>
              </div>
            )}
            {prepError && <ErrorBox message={prepError} />}

            <div className="flex flex-wrap items-center justify-end gap-3">
              {!outRoot && <span className="text-xs text-fg-muted">Choose an output folder first.</span>}
              {prepBusy && (
                <Button variant="danger" onClick={() => void cancel()} disabled={cancelling}>
                  {cancelling ? 'Stopping…' : 'Cancel'}
                </Button>
              )}
              <Button variant="primary" onClick={() => void prepare()} disabled={prepBusy || !outRoot}>
                {prepBusy ? 'Preparing…' : 'Prepare the game'}
              </Button>
            </div>
          </div>
        </Panel>
      )}

      {prepared && (
        <Panel
          title="4 · Build the game (one click)"
          actions={<Chip color="#10b981">{prepared.source_kind === 'original' ? 'cue sheet' : 'disc prepared'}</Chip>}
        >
          <div className="space-y-3">
            <p className="text-sm text-fg-secondary">
              Aura runs PSXRecomp&apos;s own project setup for <b className="text-fg">{prepared.title}</b>: it gets a
              portable compiler, generates C from the game&apos;s boot program, compiles it and gathers a game folder.
              The result asks for your disc image the first time it starts.
            </p>
            {prepared.warnings.map((w) => (
              <div key={w} className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                {w}
              </div>
            ))}

            {planError && <ErrorBox message={planError} />}
            {!plan && !planError && <Spinner label="Checking your build tools…" />}

            {plan && tc && (
              <>
                <ul className="grid grid-cols-2 gap-1 text-xs sm:grid-cols-5">
                  <ToolChip tool={tc.git} />
                  <ToolChip tool={tc.python} />
                  <ToolChip tool={tc.powershell} />
                  <ToolChip tool={tc.bash} />
                  <ToolChip tool={tc.build_tools} />
                </ul>
                {tc.problems.map((p) => (
                  <div key={p} className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-200">
                    {p}
                  </div>
                ))}

                {plan.downloads.length > 0 ? (
                  <div className="space-y-1 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
                    <div className="font-medium">This build downloads about {plan.download_mb.toLocaleString()} MB:</div>
                    <ul className="list-inside list-disc space-y-0.5">
                      {plan.downloads.map((d) => (
                        <li key={d.what}>
                          {d.what} <span className="text-amber-200/70">(~{d.approx_mb} MB, {d.from})</span>
                        </li>
                      ))}
                    </ul>
                    <div className="text-amber-200/80">
                      The toolchain is checked against its published SHA-256 before it is used.
                    </div>
                  </div>
                ) : (
                  <Hint>Everything needed is already cached: no downloads.</Hint>
                )}

                <StatGrid>
                  <Stat label="Estimated time" value={`~${estMinutes} min (${plan.cores} cores)`} />
                  <Stat
                    label="Disk (cache)"
                    value={`${fmtBytes(plan.free_bytes ?? 0)} free · ~${fmtBytes(plan.required_bytes)} needed`}
                  />
                  <Stat label="Framework" value={plan.pinned_commit.slice(0, 8)} />
                  <Stat label="Project" value={plan.project_dir.split(/[\\/]/).pop() ?? ''} />
                </StatGrid>

                <div className="flex gap-2">
                  <input
                    className="flex-1 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
                    placeholder={plan.cache_dir}
                    value={cacheDir}
                    onChange={(e) => setCacheDir(e.target.value)}
                    title="Where the toolchain and framework sources are cached"
                  />
                  <Button variant="ghost" onClick={() => void browseCache()} disabled={buildBusy}>
                    Cache folder…
                  </Button>
                </div>

                {plan.blockers
                  .filter((b) => !tc.problems.includes(b))
                  .map((b) => (
                    <ErrorBox key={b} message={b} />
                  ))}

                <div className="flex flex-wrap items-center justify-end gap-3">
                  {buildBusy && (
                    <Button variant="danger" onClick={() => void cancel()} disabled={cancelling}>
                      {cancelling ? 'Stopping…' : 'Cancel build'}
                    </Button>
                  )}
                  <Button variant="primary" onClick={() => void build()} disabled={buildBusy || !plan.can_build}>
                    {buildBusy
                      ? 'Building…'
                      : plan.downloads.length > 0
                        ? `Download ~${(plan.download_mb / 1000).toFixed(1)} GB and build`
                        : 'Build the game'}
                  </Button>
                </div>
              </>
            )}

            {buildBusy && (
              <div className="space-y-2">
                <div className="h-2.5 overflow-hidden rounded-full bg-app-panel-soft">
                  <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${buildPct}%` }} />
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="truncate text-fg-secondary">{buildProgress?.message ?? 'Starting…'}</span>
                  <span className="ml-3 shrink-0 font-mono text-fg">
                    {buildPct}% · {fmtClock(buildProgress?.elapsed_secs ?? 0)}
                  </span>
                </div>
                {buildProgress && buildProgress.log_tail.length > 0 && (
                  <pre className="max-h-40 overflow-auto rounded-lg border border-app-border bg-app-panel-soft p-2 font-mono text-[11px] text-fg-muted">
                    {buildProgress.log_tail.join('\n')}
                  </pre>
                )}
              </div>
            )}

            {buildError && <ErrorBox message={buildError} />}

            {buildResult && (
              <div className="space-y-3 border-t border-app-border pt-3">
                <StatGrid>
                  <Stat label="Built in" value={fmtClock(buildResult.elapsed_secs)} />
                  <Stat label="Game folder" value={buildResult.package ? `${buildResult.package.files} files` : 'not packaged'} />
                  <Stat label="Size" value={buildResult.package ? fmtBytes(buildResult.package.bytes) : '—'} />
                </StatGrid>
                <ul className="text-xs">
                  <PathRow label="Game" value={buildResult.exe} />
                  <PathRow label="Project" value={buildResult.project_dir} />
                  <PathRow label="Build log" value={buildResult.log_path} />
                </ul>
                <div className="flex flex-wrap gap-2">
                  {buildResult.package && (
                    <>
                      <Button
                        variant="primary"
                        onClick={() =>
                          void playPs1Game(buildResult.package!.exe, buildResult.source_image || null).catch((e) =>
                            setBuildError(String(e)),
                          )
                        }
                      >
                        Play
                      </Button>
                      <Button variant="ghost" onClick={() => void revealInFileManager(buildResult.package!.package_dir)}>
                        Show game folder
                      </Button>
                    </>
                  )}
                </div>
                {buildResult.warnings.map((w) => (
                  <div key={w} className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                    {w}
                  </div>
                ))}
                <Hint>
                  On first start the game asks for your disc image (your <Kbd>.chd</Kbd>, <Kbd>.cue</Kbd> or{' '}
                  <Kbd>.iso</Kbd>). This folder holds code translated from your disc: keep it on this computer and do
                  not share it. PSXRecomp is licensed for non-commercial use.
                </Hint>
              </div>
            )}
          </div>
        </Panel>
      )}
    </>
  );
}
