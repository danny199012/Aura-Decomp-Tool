export type ThemeName = 'midnight' | 'aurora' | 'synthwave' | 'carbon' | 'crimson';

export interface ThemeDef {
  id: ThemeName;
  label: string;
  swatch: string; // CSS color used in the picker swatch
  hint: string;
}

export const THEMES: ThemeDef[] = [
  { id: 'midnight', label: 'Midnight', swatch: '#6366f1', hint: 'Deep slate · indigo' },
  { id: 'aurora', label: 'Aurora', swatch: '#10b981', hint: 'Emerald · teal' },
  { id: 'synthwave', label: 'Synthwave', swatch: '#d946ef', hint: 'Neon purple · pink' },
  { id: 'crimson', label: 'Crimson', swatch: '#ef4444', hint: 'Dark · red accent' },
  { id: 'carbon', label: 'Carbon', swatch: '#4f46e5', hint: 'Clean · professional light' },
];

const STORAGE_KEY = 'aura-theme';
const VALID = new Set<ThemeName>(['midnight', 'aurora', 'synthwave', 'carbon', 'crimson']);

/** Read the current theme (surfaced via <html data-theme>). */
export function getTheme(): ThemeName {
  const attr = document.documentElement.getAttribute('data-theme');
  if (attr && VALID.has(attr as ThemeName)) return attr as ThemeName;
  return 'midnight';
}

/** Persist + apply a theme. Matches the index.html pre-paint bootstrap. */
export function setTheme(theme: ThemeName): void {
  document.documentElement.setAttribute('data-theme', theme);
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* localStorage blocked — in-memory theme still applies */
  }
}
