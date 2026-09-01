import { useEffect, useMemo, useState } from 'react';
import { Button, ErrorBox, Panel, Spinner } from './ui';
import { useFile } from '../lib/FileContext';
import { disassemblerFor, call } from '../lib/tauri';
import type { DisassembledInstruction, FunctionEntry } from '../types';
import { bytesToHex, hex32 } from '../lib/format';

export default function DisasmView() {
  const { summary } = useFile();
  const sections = useMemo(() => summary?.codeSections ?? summary?.sections ?? [], [summary]);

  const [section, setSection] = useState<string>('');
  const [insns, setInsns] = useState<DisassembledInstruction[]>([]);
  const [funcs, setFuncs] = useState<FunctionEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Windowing: render only the first `visible` instructions so large sections
  // (thousands of rows) don't freeze the UI. Grows in chunks via "Show more".
  const PAGE = 2000;
  const [visible, setVisible] = useState(PAGE);

  useEffect(() => {
    if (!summary) return;
    const first = summary.codeSections[0]?.name ?? '';
    setSection(first);
    setInsns([]);
    setVisible(PAGE);
  }, [summary]);

  useEffect(() => {
    if (!summary) return;
    setFuncs([]);
    if (summary.kind === 'elf' || summary.kind === 'ps1') {
      call<FunctionEntry[]>('detect_functions', { path: summary.path })
        .then(setFuncs)
        .catch(() => setFuncs([]));
    }
  }, [summary]);

  const disassemble = async (sectionName: string) => {
    if (!summary) return;
    setBusy(true);
    setError(null);
    try {
      const loader = disassemblerFor(summary);
      const out = await loader(summary.path, sectionName);
      setInsns(out);
      setVisible(PAGE);
    } catch (e) {
      setError(String(e));
      setInsns([]);
    } finally {
      setBusy(false);
    }
  };

  if (!summary) {
    return <div className="text-sm text-fg-muted">No file loaded. Open one from the home view first.</div>;
  }

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">Disassembly</h1>
        <p className="text-sm text-fg-secondary">
          {summary.kind === 'xbe' && '32-bit x86 (Original Xbox)'}
        {summary.kind === 'xex' && 'Big-endian PowerPC (Xenon)'}
        {summary.kind === 'wiiu' && 'Big-endian PowerPC64 (Cafe)'}
        {summary.kind === 'ps3' && 'Big-endian PowerPC (Cell BE)'}
        {summary.kind === 'ps4ps5' && '64-bit x86 (Orbis x86-64)'}
        {summary.kind === 'elf' && 'MIPS R3000 (PS1/PS2)'}
        {summary.kind === 'gameboy' && 'Z80 (GameBoy)'}
        </p>
      </header>

      <Panel title="Code sections">
        <div className="flex flex-wrap gap-2">
          {sections.length === 0 ? (
            <div className="text-sm text-fg-muted">
              No labeled code sections. {summary.kind === 'gameboy' ? 'Disassembling whole ROM.' : ''}
            </div>
          ) : (
            sections.map((s) => (
              <button
                key={s.name}
                onClick={() => {
                  setSection(s.name);
                  disassemble(s.name);
                }}
                className={`rounded-lg border px-3 py-1.5 font-mono text-sm transition-colors ${
                  section === s.name
                    ? 'border-accent bg-accent/15 text-fg'
                    : 'border-app-border bg-app-panel-soft text-fg-secondary hover:bg-app-hover'
                }`}
              >
                {s.name}
              </button>
            ))
          )}
          {sections.length === 0 && (
            <Button variant="primary" onClick={() => disassemble('')}>
              Disassemble
            </Button>
          )}
        </div>
        {busy && <Spinner label="Disassembling…" />}
        {error && <ErrorBox message={error} />}
      </Panel>

      {funcs.length > 0 && (
        <Panel title={`Detected functions (${funcs.length})`}>
          <div className="grid max-h-56 grid-cols-1 gap-x-4 overflow-auto sm:grid-cols-2 lg:grid-cols-3">
            {funcs.map((f) => (
              <div key={`${f.name}`} className="flex justify-between gap-2 border-b border-app-border/40 py-0.5 font-mono text-xs">
                <span className="truncate text-fg">{f.name}</span>
                <span className="text-fg-muted">0x{f.start.toString(16).toUpperCase()}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}

      <Panel title={`Instructions (${insns.length})`}>
        {busy ? (
          <Spinner />
        ) : insns.length === 0 ? (
          <div className="text-sm text-fg-muted">Select a code section to disassemble.</div>
        ) : (
          <>
            <div className="mb-2 flex flex-wrap items-center gap-3 text-xs text-fg-muted">
              <span>Showing {Math.min(visible, insns.length)} of {insns.length}</span>
              {visible < insns.length && (
                <Button variant="ghost" onClick={() => setVisible((v) => v + PAGE)}>
                  Show next {PAGE}
                </Button>
              )}
              {visible < insns.length && (
                <Button variant="ghost" onClick={() => setVisible(insns.length)}>
                  Show all
                </Button>
              )}
            </div>
            <div className="max-h-[55vh] overflow-auto rounded-lg border border-app-border bg-app-panel-soft">
              <table className="w-full font-mono text-[13px]">
                <thead className="sticky top-0 bg-app-panel text-xs uppercase tracking-wide text-fg-muted">
                  <tr>
                    <th className="px-3 py-2 text-left">Address</th>
                    <th className="px-3 py-2 text-left">Bytes</th>
                    <th className="px-3 py-2 text-left">Instruction</th>
                    <th className="px-3 py-2 text-left">Operands</th>
                  </tr>
                </thead>
                <tbody>
                  {insns.slice(0, visible).map((ins, i) => (
                    <tr key={i} className="border-t border-app-border/40 hover:bg-app-hover">
                      <td className="px-3 py-1 text-accent-bright">{hex32(ins.address)}</td>
                      <td className="px-3 py-1 text-fg-muted">
                        {ins.bytes && ins.bytes.length ? bytesToHex(ins.bytes) : '—'}
                      </td>
                      <td className="px-3 py-1 font-semibold text-fg">{ins.mnemonic || ins.text || '—'}</td>
                      <td className="px-3 py-1 text-fg-secondary">{ins.operands ?? ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
