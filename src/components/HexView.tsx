import { useCallback, useEffect, useState } from 'react';
import { useFile } from '../lib/FileContext';
import { call } from '../lib/tauri';
import { Button, ErrorBox, Panel, Spinner } from './ui';

/** Bytes per page (16 columns x rows). A page = 16 KiB. */
const PAGE = 0x1000;
const COLS = 16;

interface FileMeta {
  success: boolean;
  filename: string | null;
  size: number | null;
  message: string;
}

function asciiChar(b: number): string {
  return b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
}

export default function HexView() {
  const { summary } = useFile();
  const [path, setPath] = useState(summary?.path ?? '');
  const [offset, setOffset] = useState(0);
  const [bytes, setBytes] = useState<number[]>([]);
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [jump, setJump] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (summary?.path) {
      setPath(summary.path);
      setOffset(0);
    }
  }, [summary?.path]);

  const load = useCallback(
    async (off: number) => {
      if (!path) return;
      setBusy(true);
      setError(null);
      try {
        const buf = await call<number[]>('read_raw_binary', { path, maxBytes: PAGE, offset: off });
        setBytes(buf);
        setOffset(off);
        const meta = await call<FileMeta>('open_file', { path });
        if (meta?.size !== null && meta?.size !== undefined) setFileSize(meta.size);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [path],
  );

  // Auto-load when the summary path arrives / changes.
  useEffect(() => {
    if (path) void load(0);
  }, [path, load]);

  const pageStart = offset;
  const pageEnd = offset + bytes.length;
  const totalPages = fileSize ? Math.ceil(fileSize / PAGE) : 0;
  const pageIndex = Math.floor(pageStart / PAGE);

  const next = () => {
    if (fileSize === null) return;
    void load(Math.min(pageStart + PAGE, Math.max(0, fileSize - 1)));
  };
  const prev = () => void load(Math.max(0, pageStart - PAGE));

  const doJump = () => {
    if (!jump) return;
    const v = parseInt(jump.startsWith('0x') ? jump : `0x${jump}`, 16);
    if (Number.isNaN(v) || v < 0) {
      setError('Enter a hex offset like 0x1000 (or 1000).');
      return;
    }
    void load(Math.floor(v / PAGE) * PAGE);
  };

  const clampPageStart = (() => {
    if (fileSize === null) return 0;
    return Math.max(0, Math.floor(Math.max(0, fileSize - 1) / PAGE) * PAGE);
  })();

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-bold text-fg">Hex view</h1>
        <p className="text-sm text-fg-secondary">
          Raw byte dump of the loaded file, paged in 16 KiB chunks. Use jump to go to an
          absolute offset (hex), or page with the arrow buttons.
        </p>
      </header>

      <Panel title="Source">
        <div className="space-y-3">
          <div className="flex flex-wrap items-end gap-2">
            <label className="min-w-[280px] flex-1">
              <span className="mb-1 block text-xs font-medium text-fg-muted">File path</span>
              <input
                className="w-full rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
                value={path}
                onChange={(e) => setPath(e.target.value)}
              />
            </label>
            <Button variant="primary" disabled={busy || !path} onClick={() => void load(offset)}>
              Reload
            </Button>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="ghost" disabled={busy || offset <= 0} onClick={prev}>
              ◀ Prev page
            </Button>
            <Button
              variant="ghost"
              disabled={busy || fileSize === null || pageEnd >= fileSize}
              onClick={next}
            >
              Next page ▶
            </Button>
            <span className="font-mono text-xs text-fg-muted">
              {fileSize === null
                ? 'unknown size'
                : `page ${pageIndex + 1} / ${Math.max(1, totalPages)} · 0x${pageStart.toString(16).toUpperCase()}–0x${pageEnd.toString(16).toUpperCase()} of 0x${fileSize.toString(16).toUpperCase()}`}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <input
              className="w-32 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent"
              value={jump}
              placeholder="offset (hex)"
              onChange={(e) => setJump(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') doJump();
              }}
            />
            <Button variant="ghost" disabled={busy || !jump} onClick={doJump}>
              Jump to
            </Button>
            {fileSize !== null && (
              <Button
                variant="ghost"
                disabled={busy || pageStart === clampPageStart}
                onClick={() => void load(clampPageStart)}
              >
                End ⏭
              </Button>
            )}
          </div>

          {busy && <Spinner label="Reading…" />}
          {error && <ErrorBox message={error} />}
        </div>
      </Panel>

      {bytes.length > 0 && (
        <Panel title={`Dump (${bytes.length.toLocaleString()} bytes shown)`}>
          <div className="overflow-x-auto">
            <div className="text-listing text-xs leading-[1.35]">
              {/* Column header */}
              <div className="flex items-center gap-3 border-b border-app-border/40 pb-1">
                <span className="w-24 text-fg-muted">Offset</span>
                <span className="font-mono text-fg-muted">
                  {Array.from({ length: COLS }, (_, i) =>
                    i.toString(16).toUpperCase().padStart(2, '0'),
                  ).join(' ')}
                </span>
              </div>
              {/* Rows */}
              {Array.from({ length: Math.ceil(bytes.length / COLS) }, (_, r) => {
                const base = r * COLS;
                const row = bytes.slice(base, base + COLS);
                const rowOffset = pageStart + base;
                return (
                  <div
                    key={r}
                    className="flex items-center gap-3 border-b border-app-border/20 py-0.5 hover:bg-app-hover"
                  >
                    <span className="w-24 shrink-0 select-none bg-app-panel-soft font-mono text-accent-bright">
                      {rowOffset.toString(16).toUpperCase().padStart(8, '0')}
                    </span>
                    <span className="font-mono">
                      {row.map((b, i) => (
                        <span
                          key={i}
                          className="mr-2 inline-block w-[1.9em] text-right"
                        >
                          {b.toString(16).toUpperCase().padStart(2, '0')}
                        </span>
                      ))}
                    </span>
                    <span className="font-mono">
                      {row.map((b, i) => (
                        <span key={i} className="inline-block w-[0.9em]">
                          {asciiChar(b)}
                        </span>
                      ))}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}