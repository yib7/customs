import { useEffect, useRef, useState, type ReactNode } from 'react';
import { btn, errorMessage } from './styles';
import { IconCheck, IconCopy, IconRefresh } from './Icons';

export function Card({
  title,
  description,
  actions,
  children,
  className = '',
  id,
  level = 2,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
  level?: 2 | 3;
}) {
  const headingId = id ? `${id}-title` : undefined;
  const Heading = level === 2 ? 'h2' : 'h3';
  return (
    <section
      className={`min-w-0 rounded-xl border border-line bg-surface shadow-card ${className}`}
      aria-labelledby={title ? headingId : undefined}
      id={id}
    >
      {title ? (
        <header className="flex flex-wrap items-start justify-between gap-2 px-4 pt-4 sm:px-5">
          <div className="min-w-0">
            <Heading id={headingId} className="text-sm font-semibold text-ink">
              {title}
            </Heading>
            {description ? <p className="mt-0.5 text-xs text-muted">{description}</p> : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </header>
      ) : null}
      <div className="px-4 pt-3 pb-4 sm:px-5">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-ink sm:text-2xl">{title}</h1>
        {subtitle ? <p className="mt-1 max-w-2xl text-sm text-ink-2">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-surface-3 ${className}`} aria-hidden="true" />;
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div role="status" className="flex flex-col gap-2 py-2">
      <span className="sr-only">{label}</span>
      <Skeleton className="h-4 w-2/3" />
      <Skeleton className="h-4 w-1/2" />
      <Skeleton className="h-4 w-3/4" />
    </div>
  );
}

export function ErrorBox({ error, onRetry, title = 'Something went wrong' }: { error: unknown; onRetry?: () => void; title?: string }) {
  return (
    <div role="alert" className="rounded-lg border border-block/40 bg-block-soft px-4 py-3 text-sm text-ink">
      <p className="font-medium text-block-ink">{title}</p>
      <p className="mt-1 break-words text-ink-2">{errorMessage(error)}</p>
      {onRetry ? (
        <button type="button" className={`${btn.secondary} mt-3`} onClick={onRetry}>
          <IconRefresh size={14} /> Retry
        </button>
      ) : null}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line-strong px-4 py-8 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      {children ? <div className="mt-1 text-sm text-muted">{children}</div> : null}
    </div>
  );
}

/** Copies `text` to the clipboard; the label announces success to screen readers. */
export function CopyButton({ text, label = 'Copy', className = '' }: { text: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);
  const onClick = async () => {
    let ok: boolean;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      // Clipboard API unavailable (insecure context): fall back to a hidden textarea.
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        ok = document.execCommand('copy');
      } catch {
        ok = false;
      }
      ta.remove();
    }
    if (ok) {
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1600);
    }
  };
  return (
    <button
      type="button"
      onClick={() => void onClick()}
      className={`inline-flex shrink-0 items-center gap-1 rounded-md border border-line px-1.5 py-1 text-xs text-ink-2 hover:bg-surface-2 hover:text-ink ${className}`}
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied' : label}
    >
      {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
      <span aria-live="polite" className="sr-only">
        {copied ? 'Copied to clipboard' : ''}
      </span>
    </button>
  );
}

/** A copyable shell command or config snippet. */
export function CommandBlock({ command, label }: { command: string; label: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-line bg-code px-3 py-2">
      <code className="min-w-0 flex-1 overflow-x-auto font-mono text-xs leading-relaxed whitespace-pre text-ink">{command}</code>
      <CopyButton text={command} label={label} />
    </div>
  );
}
