import { useCallback, useEffect, useState } from 'react';
import { Button, Chip, ErrorBox, Panel, Spinner } from './ui';
import { useFile } from '../lib/FileContext';
import { scanStrings, searchBinary, getStringXrefs } from '../lib/tauri';
import type { FoundString, SearchResult, StringXrefResult } from '../lib/tauri';
import { hex32 } from '../lib/format';

type SearchKind = 'string' | 'pattern' | 'immediate';

export default function SearchView() {
  const { summary } = useFile();
  const [path, setPath] = useState(summary?.path ?? '');

  const [strings, setStrings] = useState<FoundString[]>([]);
  const [stringsSection, setStringsSection] = useState('*whole*');
  const [strBusy, setStrBusy] = useState(false);

  const [kind, setKind] = useState<SearchKind>('string');
  const [needle, setNeedle] = useState('');
  const [ignoreCase, setIgnoreCase] = useState(true);
  const [searchResult, setSearchResult] = useState<SearchResult | null>(null);
  const [searchBusy, setSearchBusy] = useState(false);

  const [xrefs, setXrefs] = useState<StringXrefResult | null>(null);
  const [xBusy, setXBusy] = useState(false);

  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (summary?.path) setPath(summary.path);
  }, [summary?.path]);

  const runScanStrings = useCallback(async () => {
    if (!path) return;
    setStrBusy(true); setError(null);
    try {
      const r = await scanStrings(path, undefined, 4);
      setStrings(r.strings);
      setStringsSection(r.section);
    } catch (e) { setError(String(e)); setStrings([]); }
    finally { setStrBusy(false); }
  }, [path]);

  const runSearch = useCallback(async () => {
    if (!path || !needle) return;
    setSearchBusy(true); setError(null);
    try { setSearchResult(await searchBinary(path, kind, needle, ignoreCase)); }
    catch (e) { setError(String(e)); setSearchResult(null); }
    finally { setSearchBusy(false); }
  }, [path, kind, needle, ignoreCase]);

  const runXrefs = useCallback(async () => {
    if (!path) return;
    setXBusy(true); setError(null);
    try { setXrefs(await getStringXrefs(path)); }
    catch (e) { setError(String(e)); setXrefs(null); }
    finally { setXBusy(false); }
  }, [path]);

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">Search &amp; strings</h1>
        <p className="text-sm text-fg-secondary">
          Find bytes, strings, and immediates in the binary; scan for printable strings;
          and see which code references each string (MIPS <code>lui</code>+<code>addiu</code> idiom).
        </p>
      </header>

      <Panel title="Source">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[240px]">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Binary path</span>
            <input className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={path} onChange={(e) => setPath(e.target.value)} />
          </label>
          <Button variant="ghost" disabled={strBusy || !path} onClick={runScanStrings}>Scan strings</Button>
          <Button variant="ghost" disabled={xBusy || !path} onClick={runXrefs}>String xrefs</Button>
        </div>
        {error && <ErrorBox message={error} />}
      </Panel>

      {strings.length > 0 && (
        <Panel title={`Strings (${strings.length}) — ${stringsSection}`}>
          <div className="max-h-[40vh] overflow-auto rounded-lg border border-app-border">
            <table className="w-full font-mono text-[13px]">
              <thead className="sticky top-0 bg-app-panel text-xs uppercase tracking-wide text-fg-muted">
                <tr>
                  <th className="px-3 py-2 text-left">Address</th>
                  <th className="px-3 py-2 text-left">Offset</th>
                  <th className="px-3 py-2 text-left">String</th>
                  <th className="px-3 py-2 text-left">Width</th>
                </tr>
              </thead>
              <tbody>
                {strings.map((s, i) => (
                  <tr key={i} className="border-t border-app-border/40 hover:bg-app-hover">
                    <td className="px-3 py-1 text-accent-bright">{hex32(s.address)}</td>
                    <td className="px-3 py-1 text-fg-muted">0x{s.offset.toString(16).toUpperCase()}</td>
                    <td className="px-3 py-1 text-fg">{s.text}{s.wide && '…'}</td>
                    <td className="px-3 py-1">{s.wide ? <Chip color="#a78bfa">wide</Chip> : <Chip color="#22d3ee">ascii</Chip>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    <Panel title="Search binary">
        <div className="flex flex-wrap items-end gap-3">
          <label>
            <span className="mb-1 block text-xs font-medium text-fg-muted">Kind</span>
            <select className="rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={kind} onChange={(e) => { setKind(e.target.value as SearchKind); setSearchResult(null); }}>
              <option value="string">String (ASCII)</option>
              <option value="pattern">Hex pattern</option>
              <option value="immediate">32-bit immediate</option>
            </select>
          </label>
          <label className="min-w-[240px] flex-1">
            <span className="mb-1 block text-xs font-medium text-fg-muted">
              {kind === 'pattern' ? 'Hex bytes (e.g. 1F 8B 08)' : kind === 'immediate' ? 'Number (e.g. 0x80123456)' : 'Text to find'}
            </span>
            <input className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={needle} placeholder={kind === 'string' ? 'HELLO' : kind === 'pattern' ? '1F 8B 08 00' : '0x80002000'}
              onChange={(e) => setNeedle(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') runSearch(); }} />
          </label>
          {kind === 'string' && (
            <label className="flex items-center gap-2 pb-2 text-sm text-fg-secondary">
              <input type="checkbox" checked={ignoreCase} onChange={(e) => setIgnoreCase(e.target.checked)} />
              ignore case
            </label>
          )}
          <Button variant="primary" disabled={searchBusy || !path || !needle} onClick={runSearch}>
            {searchBusy ? <Spinner /> : 'Search'}
          </Button>
        </div>
      </Panel>

      {searchResult && (
        <Panel title={`Search: ${searchResult.count} hits`}>
          {searchResult.count === 0 ? (
            <div className="text-sm text-fg-muted">No matches found.</div>
          ) : (
            <div className="max-h-[35vh] overflow-auto rounded-lg border border-app-border">
              <table className="w-full font-mono text-[13px]">
                <thead className="sticky top-0 bg-app-panel text-xs uppercase tracking-wide text-fg-muted">
                  <tr>
                    <th className="px-3 py-2 text-left">Address</th>
                    <th className="px-3 py-2 text-left">File offset</th>
                  </tr>
                </thead>
                <tbody>
                  {searchResult.hits.slice(0, 500).map((h, i) => (
                    <tr key={i} className="border-t border-app-border/40 hover:bg-app-hover">
                      <td className="px-3 py-1 text-accent-bright">{h.address != null ? hex32(h.address) : '—'}</td>
                      <td className="px-3 py-1 text-fg-muted">0x{h.offset.toString(16).toUpperCase()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {searchResult.hits.length > 500 && (
                <div className="p-2 text-xs text-fg-muted">... and {searchResult.hits.length - 500} more</div>
              )}
            </div>
          )}
        </Panel>
      )}

      {xrefs && (
        <Panel title={`String xrefs (${xrefs.count})`}>
          {xrefs.count === 0 ? (
            <div className="text-sm text-fg-muted">
              No MIPS <code>lui</code>+<code>addiu</code> references to strings found. The binary may not
              use that idiom (or has no discernible string table).
            </div>
          ) : (
            <div className="max-h-[40vh] overflow-auto rounded-lg border border-app-border">
              <table className="w-full font-mono text-[13px]">
                <thead className="sticky top-0 bg-app-panel text-xs uppercase tracking-wide text-fg-muted">
                  <tr>
                    <th className="px-3 py-2 text-left">Referenced from</th>
                    <th className="px-3 py-2 text-left">String addr</th>
                    <th className="px-3 py-2 text-left">String</th>
                  </tr>
                </thead>
                <tbody>
                  {xrefs.xrefs.slice(0, 500).map((x, i) => (
                    <tr key={i} className="border-t border-app-border/40 hover:bg-app-hover">
                      <td className="px-3 py-1 text-accent-bright">{hex32(x.from)}</td>
                      <td className="px-3 py-1 text-fg-muted">{hex32(x.to)}</td>
                      <td className="px-3 py-1 text-fg">{x.text}</td>
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