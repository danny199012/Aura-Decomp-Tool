/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Semantic color tokens backed by CSS variables.
        // `rgb(var(--x) / <alpha-value>)` keeps Tailwind's /50, /30, /10
        // opacity modifiers working with our theme-driven RGB triplets.
        // Each triplet is a space-separated "R G B" string (see index.css).
        app: {
          base: 'rgb(var(--app-base) / <alpha-value>)',
          panel: 'rgb(var(--app-panel) / <alpha-value>)',
          'panel-soft': 'rgb(var(--app-panel-soft) / <alpha-value>)',
          hover: 'rgb(var(--app-hover) / <alpha-value>)',
          'hover-strong': 'rgb(var(--app-hover-strong) / <alpha-value>)',
          // Border colors live under `app` so the border-color utility
          // resolves to `border-app-border` / `border-app-border-strong`
          // (a top-level `border` color key would collide with the `border`
          // width/utility shorthand and fail to compile).
          border: 'rgb(var(--app-border) / <alpha-value>)',
          'border-strong': 'rgb(var(--app-border-strong) / <alpha-value>)',
        },
        fg: {
          DEFAULT: 'rgb(var(--fg) / <alpha-value>)',
          secondary: 'rgb(var(--fg-secondary) / <alpha-value>)',
          muted: 'rgb(var(--fg-muted) / <alpha-value>)',
          faint: 'rgb(var(--fg-faint) / <alpha-value>)',
        },
        accent: {
          DEFAULT: 'rgb(var(--accent) / <alpha-value>)',
          bright: 'rgb(var(--accent-bright) / <alpha-value>)',
          strong: 'rgb(var(--accent-strong) / <alpha-value>)',
        },
        hex: {
          column: 'rgb(var(--hex-column) / <alpha-value>)',
        },
        // Legacy brand palette (still referenced by icon work); kept for
        // backwards compatibility but themes override accent at runtime.
        'aura-dark': {
          900: '#0f172a',
          800: '#1e293b',
          700: '#334155',
          600: '#475569',
        },
        'aura-accent': {
          DEFAULT: '#6366f1',
          light: '#818cf8',
          dark: '#4f46e5',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'Monaco', 'monospace'],
      },
    },
  },
  plugins: [],
};
