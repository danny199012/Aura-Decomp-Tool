import { useEffect, useState } from 'react';
import { Button, Chip, ErrorBox, Panel, Spinner, Stat, StatGrid } from './ui';
import { useFile } from '../lib/FileContext';
import { newProject, loadProject, saveProject, runAuraScript } from '../lib/tauri';
import type { AuraProject, ScriptResult } from '../lib/tauri';
import { hex32 } from '../lib/format';

export default function ProjectView() {
  const { summary } = useFile();
  const [path, setPath] = useState(summary?.path ?? '');
  const [project, setProject] = useState<AuraProject | null>(null);
  // Undo/redo history: snapshots of project JSON.
  const [past, setPast] = useState<string[]>([]);
  const [future, setFuture] = useState<string[]>([]);
  const [projectPath, setProjectPath] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [script, setScript] = useState('-- Rename the first function\nfor _, f in ipairs(aura.functions) do\n  aura.rename(f.addr, "func_" .. string.format("%08X", f.addr))\n  break\nend\nreturn "done"');
  const [scriptResult, setScriptResult] = useState<ScriptResult | null>(null);

  /** Replace the current project and record history. `record=true` pushes the
   * old value onto the undo stack (skips the very first load). */
  const commitProject = (next: AuraProject, record: boolean) => {
    if (record && project) {
      setPast((p) => [...p.slice(-99), JSON.stringify(project)]);
      setFuture([]);
    }
    setProject(next);
  };

  const undo = () => {
    if (past.length === 0 || !project) return;
    setFuture((f) => [...f.slice(-99), JSON.stringify(project)]);
    const prev = JSON.parse(past[past.length - 1]) as AuraProject;
    setPast((p) => p.slice(0, -1));
    setProject(prev);
  };

  const redo = () => {
    if (future.length === 0 || !project) return;
    setPast((p) => [...p.slice(-99), JSON.stringify(project)]);
    const next = JSON.parse(future[future.length - 1]) as AuraProject;
    setFuture((f) => f.slice(0, -1));
    setProject(next);
  };

  const createNew = async () => {
    if (!path) return;
    setBusy(true); setError(null);
    try {
      setPast([]); setFuture([]);
      setProject(JSON.parse(await newProject(path, summary?.filename)));
      setScriptResult(null);
    } catch (e) { setError(String(e)); } finally { setBusy(false); }
  };

  const open = async () => {
    if (!projectPath) return;
    setBusy(true); setError(null);
    try {
      setPast([]); setFuture([]);
      setProject(JSON.parse(await loadProject(projectPath)));
      setScriptResult(null);
    } catch (e) { setError(String(e)); } finally { setBusy(false); }
  };

  const save = async () => {
    if (!project || !projectPath) return;
    setBusy(true); setError(null);
    try { await saveProject(JSON.stringify(project), projectPath); }
    catch (e) { setError(String(e)); } finally { setBusy(false); }
  };

  const runScript = async () => {
    if (!path || !script) return;
    setBusy(true); setError(null);
    try {
      const r = await runAuraScript(path, script, project ? JSON.stringify(project) : undefined);
      setScriptResult(r);
      if (r.success) {
        // Adopt the backend's updated project (annotations/patches the script made).
        const updated = JSON.parse(r.project_json) as AuraProject;
        commitProject(updated, true);
      }
    } catch (e) { setError(String(e)); } finally { setBusy(false); }
  };

  const annotationCount = project ? Object.keys(project.annotations).length : 0;
  const patchCount = project ? project.patches.length : 0;
  const canUndo = past.length > 0 && !!project;
  const canRedo = future.length > 0 && !!project;

  // Ctrl/Cmd+Z = undo, Ctrl/Cmd+Shift+Z = redo.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.key.toLowerCase() === 'z') {
        e.preventDefault();
        if (e.shiftKey) redo(); else undo();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [past, future, project]);

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">Project &amp; scripting</h1>
        <p className="text-sm text-fg-secondary">
          Persist your work in a <code>.aura</code> project (renames, comments, patches) and
          automate analysis with Lua scripts — the extensibility layer that makes Aura a real
          reverse-engineering tool, like Ghidra's project + GhidraScript.
        </p>
      </header>
      <Panel title="Project">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[240px]">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Binary path</span>
            <input className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={path} onChange={(e) => setPath(e.target.value)} />
          </label>
          <label className="flex-1 min-w-[200px]">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Project file (.aura)</span>
            <input className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={projectPath} placeholder="/path/to/game.aura" onChange={(e) => setProjectPath(e.target.value)} />
          </label>
          <Button variant="ghost" disabled={busy || !path} onClick={createNew}>New</Button>
          <Button variant="ghost" disabled={busy || !projectPath} onClick={open}>Open</Button>
          <Button variant="primary" disabled={busy || !project || !projectPath} onClick={save}>Save</Button>
          <Button variant="ghost" disabled={!canUndo} onClick={undo}>↩ Undo</Button>
          <Button variant="ghost" disabled={!canRedo} onClick={redo}>↪ Redo</Button>
        </div>
        {busy && <Spinner label="Working…" />}
        {error && <ErrorBox message={error} />}
      </Panel>
      {project && (
        <StatGrid>
          <Stat label="Binary" value={project.binary_name ?? project.binary_path} />
          <Stat label="Annotations" value={annotationCount} />
          <Stat label="Patches" value={patchCount} />
        </StatGrid>
      )}

      {project && annotationCount > 0 && (
        <Panel title={`Annotations (${annotationCount})`}>
          <div className="max-h-[35vh] overflow-auto rounded-lg border border-app-border">
            <table className="w-full font-mono text-[13px]">
              <thead className="sticky top-0 bg-app-panel text-xs uppercase tracking-wide text-fg-muted">
                <tr>
                  <th className="px-3 py-2 text-left">Address</th>
                  <th className="px-3 py-2 text-left">Name</th>
                  <th className="px-3 py-2 text-left">Comment</th>
                  <th className="px-3 py-2 text-left">Signature</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(project.annotations).map(([addr, a]) => (
                  <tr key={addr} className="border-t border-app-border/40 hover:bg-app-hover">
                    <td className="px-3 py-1 text-accent-bright">{hex32(Number(addr))}</td>
                    <td className="px-3 py-1">{a.name && <Chip color="#22d3ee">{a.name}</Chip>}</td>
                    <td className="px-3 py-1 text-fg-secondary">{a.comment ?? ''}</td>
                    <td className="px-3 py-1 text-fg-muted">{a.signature ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Panel title="Lua script">
        <p className="mb-2 text-xs text-fg-muted">
          API: <code>aura.functions</code>, <code>aura.rename(addr,name)</code>,{' '}
          <code>aura.comment(addr,text)</code>, <code>aura.name_at(addr)</code>,{' '}
          <code>aura.signature(addr,sig)</code>. Return a string for the output.
        </p>
        <textarea
          className="w-full rounded-lg border border-app-border bg-app-panel-soft p-3 font-mono text-[13px] text-fg outline-none focus:border-accent"
          rows={10} value={script} onChange={(e) => setScript(e.target.value)} spellCheck={false}
        />
        <div className="mt-2">
          <Button variant="primary" disabled={busy || !path} onClick={runScript}>Run script</Button>
        </div>
        {scriptResult && (
          <div className="mt-3">
            {scriptResult.success ? (
              <div className="rounded-lg border border-green-500/40 bg-green-500/10 p-3 text-sm">
                <span className="font-semibold text-green-300">OK</span> — {scriptResult.output}
                <span className="ml-2 text-fg-muted">({scriptResult.annotation_count} annotations, {scriptResult.patch_count} patches)</span>
              </div>
            ) : (
              <ErrorBox message={scriptResult.output} />
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}

