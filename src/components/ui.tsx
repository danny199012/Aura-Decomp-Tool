import type { ReactNode, MouseEventHandler } from 'react';

/** Reusable small UI primitives styled via the Aura semantic color tokens. */

export function Panel({ title, children, className = '', actions }: {
  title?: ReactNode;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <section className={`rounded-xl border border-app-border bg-app-panel ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-app-border px-4 py-2.5">
          <h3 className="text-sm font-semibold text-fg">{title}</h3>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Button({ children, onClick, variant = 'primary', disabled, className = '', type = 'button' }: {
  children: ReactNode;
  onClick?: MouseEventHandler<HTMLButtonElement>;
  variant?: 'primary' | 'ghost' | 'danger';
  disabled?: boolean;
  className?: string;
  type?: 'button' | 'submit';
}) {
  const base =
    'inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-40';
  const variants = {
    primary: 'bg-accent text-white hover:bg-accent-strong',
    ghost: 'border border-app-border bg-app-panel-soft text-fg hover:bg-app-hover',
    danger: 'bg-red-600/90 text-white hover:bg-red-700',
  };
  return (
    <button type={type} onClick={onClick} disabled={disabled} className={`${base} ${variants[variant]} ${className}`}>
      {children}
    </button>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 py-6 text-sm text-fg-muted">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-app-border border-t-accent" />
      {label ?? 'Working…'}
    </div>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
      <span className="font-semibold">Error:</span> {message}
    </div>
  );
}

export function Hint({ children }: { children: ReactNode }) {
  return <p className="text-xs text-fg-muted">{children}</p>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <code className="rounded border border-app-border bg-app-panel-soft px-1 py-0.5 font-mono text-xs text-fg-secondary">
      {children}
    </code>
  );
}

export function Chip({ children, color }: { children: ReactNode; color?: string }) {
  return (
    <span
      className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium"
      style={color ? { backgroundColor: `${color}22`, color } : undefined}
    >
      {children}
    </span>
  );
}

export function Card({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-app-border bg-app-panel-soft p-3">{children}</div>;
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-lg border border-app-border bg-app-panel-soft px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-fg-muted">{label}</div>
      <div className="mt-0.5 font-mono text-sm font-semibold text-fg">{value}</div>
    </div>
  );
}

export function StatGrid({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">{children}</div>;
}
