import { useState } from 'react';
import { THEMES, getTheme, setTheme, type ThemeName } from '../lib/themes';

/** Dropdown theme picker honoring the index.html <html data-theme> system. */
export default function ThemeSwitcher() {
  const [theme, setThemeState] = useState<ThemeName>(getTheme());
  const [open, setOpen] = useState(false);

  const apply = (t: ThemeName) => {
    setTheme(t);
    setThemeState(t);
    setOpen(false);
  };

  const current = THEMES.find((t) => t.id === theme) ?? THEMES[0];

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 rounded-lg border border-app-border bg-app-panel-soft px-3 py-2 text-sm text-fg hover:bg-app-hover"
      >
        <span
          className="h-3 w-3 rounded-full"
          style={{ backgroundColor: current.swatch }}
        />
        <span className="flex-1 text-left">{current.label}</span>
        <span className="text-fg-muted">▾</span>
      </button>
      {open && (
        <div className="absolute bottom-full left-0 z-20 mb-2 w-56 overflow-hidden rounded-lg border border-app-border bg-app-panel shadow-xl">
          {THEMES.map((t) => (
            <button
              key={t.id}
              onClick={() => apply(t.id)}
              className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-app-hover ${
                t.id === theme ? 'bg-accent/15' : ''
              }`}
            >
              <span className="h-3 w-3 rounded-full" style={{ backgroundColor: t.swatch }} />
              <span className="flex-1 font-medium text-fg">{t.label}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
