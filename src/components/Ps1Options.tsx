import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Button, Chip, ErrorBox, Hint, Panel, Spinner, Stat, StatGrid } from './ui';
import { fmtBytes } from '../lib/format';
import {
  applyPs1Options,
  playPs1Game,
  readPs1Options,
  resetPs1State,
  revealInFileManager,
  setPs1Mod,
  type Ps1Choice,
  type Ps1Finding,
  type Ps1OptionsInfo,
  type Ps1PlayOptions,
  type Ps1ResetReport,
} from '../lib/ingest';

const SEVERITY_COLOR: Record<Ps1Finding['severity'], string> = {
  error: '#ef4444',
  warn: '#f59e0b',
  info: '#38bdf8',
};

const sameOptions = (a: Ps1PlayOptions, b: Ps1PlayOptions) =>
  a.renderer === b.renderer &&
  a.internal_resolution === b.internal_resolution &&
  a.aspect_ratio === b.aspect_ratio &&
  a.fullscreen === b.fullscreen &&
  a.vsync === b.vsync &&
  a.window_width === b.window_width;

function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 border-b border-app-border/30 py-2.5 sm:flex-row sm:items-start sm:gap-4">
      <div className="w-40 shrink-0 pt-1.5">
        <div className="text-sm font-medium text-fg">{label}</div>
        {hint && <div className="text-[11px] text-fg-muted">{hint}</div>}
      </div>
      <div className="min-w-0 flex-1 space-y-1">{children}</div>
    </div>
  );
}

function Select({
  value,
  choices,
  onChange,
  disabled,
}: {
  value: string;
  choices: Ps1Choice[];
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  // A value the file already holds but the list does not offer (a hand edit,
  // "2x", 4K on a smaller list…) stays selectable so nothing is lost silently.
  const known = choices.some((c) => c.value === value);
  const detail = choices.find((c) => c.value === value)?.detail;
  return (
    <>
      <select
        className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 text-sm text-fg outline-none focus:border-accent disabled:opacity-60 sm:w-72"
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
      >
        {!known && <option value={value}>{value} (from the settings file)</option>}
        {choices.map((c) => (
          <option key={c.value} value={c.value}>
            {c.label}
          </option>
        ))}
      </select>
      {detail && <div className="text-xs text-fg-muted">{detail}</div>}
    </>
  );
}

/**
 * Tune a game folder Aura built: video choices, the optional enhancements,
 * what looks wrong with the folder, and a safe reset of what the game
 * generated while it was played. Everything shown is something the runtime
 * really supports; things people ask for that it does not have are listed
 * with the reason instead of being faked.
 */
export default function Ps1Options({ packageDir }: { packageDir: string }) {
  const [info, setInfo] = useState<Ps1OptionsInfo | null>(null);
  const [draft, setDraft] = useState<Ps1PlayOptions | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string[]>([]);
  const [includeSaves, setIncludeSaves] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [resetReport, setResetReport] = useState<Ps1ResetReport | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const i = await readPs1Options(packageDir);
      setInfo(i);
      setDraft(i.options);
      setError(null);
    } catch (e) {
      setError(String(e));
      setInfo(null);
      setDraft(null);
    } finally {
      setLoading(false);
    }
  }, [packageDir]);

  useEffect(() => {
    setNotice([]);
    setResetReport(null);
    setConfirmReset(false);
    void load();
  }, [load]);

  const dirty = useMemo(() => !!info && !!draft && !sameOptions(info.options, draft), [info, draft]);

  const patch = (p: Partial<Ps1PlayOptions>) => setDraft((d) => (d ? { ...d, ...p } : d));

  const applyPreset = (id: string) => {
    const p = info?.presets.find((x) => x.id === id);
    if (!p) return;
    patch({
      ...(p.renderer ? { renderer: p.renderer } : {}),
      internal_resolution: p.internal_resolution,
      ...(p.vsync ? { vsync: p.vsync } : {}),
    });
  };

  const run = async (job: () => Promise<string[] | void>) => {
    setBusy(true);
    setError(null);
    try {
      const lines = await job();
      setNotice(lines ?? []);
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const save = () =>
    draft &&
    run(async () => {
      const r = await applyPs1Options(packageDir, draft);
      return [
        r.changed.length ? `Saved: ${r.changed.join('; ')}` : 'Nothing needed changing.',
        ...(r.backup_path ? [`Your original settings.toml is kept as ${r.backup_path}`] : []),
        ...r.warnings,
      ];
    });

  const toggleMod = (packageId: string, featureId: string, enabled: boolean) =>
    run(async () => {
      const r = await setPs1Mod(packageDir, packageId, featureId, enabled);
      return [`${featureId}: ${r.changed ? (r.enabled ? 'switched on' : 'switched off') : 'already that way'}`];
    });

  const doReset = () =>
    run(async () => {
      const r = await resetPs1State(packageDir, includeSaves);
      setResetReport(r);
      setConfirmReset(false);
      return [];
    });

  if (loading && !info) {
    return (
      <Panel title="Game options">
        <Spinner label="Reading the game folder…" />
      </Panel>
    );
  }
  if (!info || !draft) {
    return (
      <Panel title="Game options">
        <ErrorBox message={error ?? 'Could not read the game folder.'} />
      </Panel>
    );
  }

  const s = info.state;
  const hasState = s.cache_files > 0 || s.overlay_captures || s.freeze_dumps > 0 || s.has_last_report;
  const aspectChoices: Ps1Choice[] = [
    { value: '4:3', label: '4:3 (original)', detail: '' },
    { value: '16:9', label: '16:9', detail: 'Widens the view through the game’s widescreen mod.' },
    { value: '21:9', label: '21:9', detail: 'Ultra-wide, if the mod supports it.' },
  ];

  return (
    <Panel
      title={`Game options · ${info.title}`}
      actions={
        <>
          {info.game_running && <Chip color="#f59e0b">running</Chip>}
          <Button variant="ghost" onClick={() => void revealInFileManager(info.package_dir)}>
            Show folder
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        {error && <ErrorBox message={error} />}
        {notice.length > 0 && (
          <div className="space-y-1 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-xs text-fg">
            {notice.map((n) => (
              <div key={n}>{n}</div>
            ))}
          </div>
        )}
        {info.game_running && (
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
            The game is running. It writes its own settings when it closes, which would overwrite a change made now:
            close it first.
          </div>
        )}

        {info.findings.length > 0 && (
          <section className="space-y-2">
            <h3 className="text-sm font-semibold text-fg">What looks wrong</h3>
            <ul className="space-y-2">
              {info.findings.map((f) => (
                <li key={f.code} className="rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 text-sm">
                  <div className="flex items-center gap-2">
                    <Chip color={SEVERITY_COLOR[f.severity]}>{f.severity}</Chip>
                    <span className="font-medium text-fg">{f.title}</span>
                  </div>
                  <div className="mt-1 text-xs text-fg-secondary">{f.detail}</div>
                  {f.fix && <div className="mt-1 text-xs text-accent-bright">Try: {f.fix}</div>}
                </li>
              ))}
            </ul>
          </section>
        )}

        <section>
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <h3 className="mr-2 text-sm font-semibold text-fg">Video</h3>
            {info.presets.map((p) => (
              <Button key={p.id} variant="ghost" onClick={() => applyPreset(p.id)} disabled={busy}>
                {p.label}
              </Button>
            ))}
          </div>
          <Hint>
            {info.presets.map((p) => `${p.label}: ${p.detail}`).join(' ')}
          </Hint>

          <Row label="Renderer" hint="How the picture is drawn">
            <Select
              value={draft.renderer}
              choices={info.choices.renderers}
              onChange={(v) => patch({ renderer: v })}
              disabled={busy}
            />
            {draft.renderer === 'vulkan' && !info.vulkan_offered && (
              <div className="text-xs text-amber-200">
                Saving will also set <span className="font-mono">offer_vulkan = true</span> in this game's game.toml;
                the runtime ignores Vulkan without it.
              </div>
            )}
          </Row>
          <Row label="Resolution" hint="Internal rendering scale">
            <Select
              value={draft.internal_resolution}
              choices={info.choices.resolutions}
              onChange={(v) => patch({ internal_resolution: v })}
              disabled={busy}
            />
            {!dirty && <div className="text-xs text-fg-muted">{info.resolution_label}</div>}
          </Row>
          <Row label="Window" hint="Windowed or fullscreen">
            <Select
              value={String(draft.fullscreen)}
              choices={info.choices.fullscreen}
              onChange={(v) => patch({ fullscreen: Number(v) })}
              disabled={busy}
            />
          </Row>
          <Row label="VSync" hint="Tearing vs. smoothness">
            <Select value={draft.vsync} choices={info.choices.vsync} onChange={(v) => patch({ vsync: v })} disabled={busy} />
          </Row>
          <Row label="Aspect ratio" hint="Picture shape">
            {info.widescreen_available ? (
              <Select
                value={draft.aspect_ratio}
                choices={aspectChoices}
                onChange={(v) => patch({ aspect_ratio: v })}
                disabled={busy}
              />
            ) : (
              <div className="text-sm text-fg-secondary">
                4:3 only. This game has no widescreen mod, and PSXRecomp only widens the picture through one.
              </div>
            )}
          </Row>

          <div className="flex flex-wrap items-center justify-end gap-2 pt-3">
            {dirty && (
              <Button variant="ghost" onClick={() => setDraft(info.options)} disabled={busy}>
                Revert
              </Button>
            )}
            <Button variant="primary" onClick={() => void save()} disabled={busy || !dirty}>
              {busy ? 'Working…' : 'Save settings'}
            </Button>
            <Button
              variant="ghost"
              onClick={() => void playPs1Game(info.exe, info.disc_path).catch((e) => setError(String(e)))}
              disabled={busy || dirty || info.game_running}
            >
              Play
            </Button>
          </div>
        </section>

        {info.mods.length > 0 && (
          <section className="space-y-1">
            <h3 className="text-sm font-semibold text-fg">Enhancements</h3>
            <Hint>
              Optional extras that change how the game behaves. If something goes wrong (audio, movies, freezes), switch
              them off one at a time to find the cause.
            </Hint>
            <ul>
              {info.mods.map((m) => (
                <li
                  key={`${m.package_id}/${m.feature_id}`}
                  className="flex items-start gap-3 border-b border-app-border/30 py-2"
                >
                  <input
                    type="checkbox"
                    className="mt-1 h-4 w-4 accent-[var(--accent,#10b981)]"
                    checked={m.enabled}
                    disabled={busy || info.game_running}
                    onChange={(e) => void toggleMod(m.package_id, m.feature_id, e.target.checked)}
                    aria-label={m.name}
                  />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-sm text-fg">
                      {m.name}
                      {m.deprecated && <Chip color="#f59e0b">deprecated heuristic</Chip>}
                    </div>
                    <div className="text-xs text-fg-muted">{m.description}</div>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        )}

        <section className="space-y-2">
          <h3 className="text-sm font-semibold text-fg">Reset what the game generated</h3>
          <StatGrid>
            <Stat label="Overlay cache" value={`${fmtBytes(s.cache_bytes)} · ${s.cache_files} files`} />
            <Stat label="Captured overlays" value={s.overlay_captures ? 'yes' : 'none'} />
            <Stat label="Freeze reports" value={s.freeze_dumps} />
            <Stat label="Saves" value={fmtBytes(s.saves_bytes)} />
          </StatGrid>
          <Hint>
            Moves the overlay cache, captured overlays and freeze reports into a timestamped backup folder inside the
            game folder, so the next start is from the program as built. Nothing is deleted, and your saves stay put
            unless you tick the box.
          </Hint>
          {!confirmReset ? (
            <div className="flex justify-end">
              <Button variant="ghost" onClick={() => setConfirmReset(true)} disabled={busy || !hasState || info.game_running}>
                {hasState ? 'Reset generated state…' : 'Nothing to reset'}
              </Button>
            </div>
          ) : (
            <div className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
              <label className="flex items-center gap-2 text-fg">
                <input type="checkbox" checked={includeSaves} onChange={(e) => setIncludeSaves(e.target.checked)} />
                Also move my save games ({fmtBytes(s.saves_bytes)}) into the backup
              </label>
              <div className="flex justify-end gap-2">
                <Button variant="ghost" onClick={() => setConfirmReset(false)} disabled={busy}>
                  Cancel
                </Button>
                <Button variant="danger" onClick={() => void doReset()} disabled={busy}>
                  Move to backup
                </Button>
              </div>
            </div>
          )}
          {resetReport && (
            <div className="rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 text-xs text-fg-secondary">
              {resetReport.backup_dir ? (
                <>
                  Moved {resetReport.moved.length} item(s) ({fmtBytes(resetReport.bytes)}) to{' '}
                  <span className="break-all font-mono text-accent-bright">{resetReport.backup_dir}</span>
                  {resetReport.skipped.length > 0 && (
                    <div className="mt-1 text-amber-200">Could not move: {resetReport.skipped.join('; ')}</div>
                  )}
                  <div className="mt-2">
                    <Button variant="ghost" onClick={() => void revealInFileManager(resetReport.backup_dir!)}>
                      Show backup folder
                    </Button>
                  </div>
                </>
              ) : (
                'Nothing to move: the game has not generated any state yet.'
              )}
            </div>
          )}
        </section>

        <section className="space-y-1">
          <h3 className="text-sm font-semibold text-fg">Not available for PS1 games</h3>
          <ul className="space-y-1 text-xs text-fg-secondary">
            {info.choices.unavailable.map((u) => (
              <li key={u.value}>
                <span className="font-medium text-fg">{u.label}.</span> {u.detail}
              </li>
            ))}
          </ul>
        </section>
      </div>
    </Panel>
  );
}
