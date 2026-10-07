import { useId, useState, type KeyboardEvent } from 'react';
import { safeLabel } from '../lib/format';
import { IconPlus, IconX } from './Icons';
import { btn } from './styles';

/** Editable list of string chips with per-entry validation. */
export function ChipInput({
  label,
  description,
  values,
  onChange,
  validate,
  placeholder,
  error,
  tone = 'neutral',
}: {
  label: string;
  description?: string;
  values: string[];
  onChange: (next: string[]) => void;
  validate: (entry: string) => string | null;
  placeholder?: string;
  error?: string;
  tone?: 'neutral' | 'allow' | 'block';
}) {
  const id = useId();
  const [draft, setDraft] = useState('');
  const [entryError, setEntryError] = useState<string | null>(null);

  const add = () => {
    const entries = draft
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (entries.length === 0) return;
    const next = [...values];
    for (const entry of entries) {
      const err = validate(entry);
      if (err) {
        setEntryError(err);
        return;
      }
      if (next.some((v) => v.toLowerCase() === entry.toLowerCase())) {
        setEntryError(`${safeLabel(entry, 60)} is already on the list.`);
        return;
      }
      next.push(entry);
    }
    onChange(next);
    setDraft('');
    setEntryError(null);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      add();
    } else if (e.key === 'Backspace' && draft === '' && values.length > 0) {
      onChange(values.slice(0, -1));
    }
  };

  const chipCls =
    tone === 'allow'
      ? 'border-allow/40 bg-allow-soft text-allow-ink'
      : tone === 'block'
        ? 'border-block/40 bg-block-soft text-block-ink'
        : 'border-line-strong bg-surface-2 text-ink';
  const shownError = entryError ?? error;

  return (
    <div className="min-w-0">
      <label htmlFor={`${id}-input`} className="text-sm font-medium text-ink">
        {label}
      </label>
      {description ? (
        <p id={`${id}-desc`} className="mt-0.5 text-xs text-muted">
          {description}
        </p>
      ) : null}
      <ul className="mt-2 flex flex-wrap gap-1.5" aria-label={`${label} entries`}>
        {values.length === 0 ? <li className="text-xs text-muted italic">Empty</li> : null}
        {values.map((v, i) => (
          <li key={`${v}-${i}`} className={`inline-flex max-w-full items-center gap-1 rounded-full border py-0.5 pr-1 pl-2.5 font-mono text-xs ${chipCls}`}>
            <span className="truncate" title={v}>
              {safeLabel(v, 80)}
            </span>
            <button
              type="button"
              className="grid h-5 w-5 shrink-0 place-items-center rounded-full hover:bg-surface-3"
              aria-label={`Remove ${safeLabel(v, 80)}`}
              onClick={() => onChange(values.filter((_, j) => j !== i))}
            >
              <IconX size={12} />
            </button>
          </li>
        ))}
      </ul>
      <div className="mt-2 flex gap-2">
        <input
          id={`${id}-input`}
          className="w-full min-w-0 rounded-lg border border-line-strong bg-surface px-3 py-1.5 font-mono text-sm text-ink placeholder:text-muted focus:border-focus focus:outline-none aria-[invalid=true]:border-block"
          value={draft}
          placeholder={placeholder}
          onChange={(e) => {
            setDraft(e.target.value);
            setEntryError(null);
          }}
          onKeyDown={onKeyDown}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          maxLength={300}
          aria-invalid={shownError ? true : undefined}
          aria-describedby={[description ? `${id}-desc` : '', shownError ? `${id}-err` : ''].filter(Boolean).join(' ') || undefined}
        />
        <button type="button" className={btn.secondary} onClick={add} disabled={!draft.trim()}>
          <IconPlus size={14} /> Add
        </button>
      </div>
      {shownError ? (
        <p id={`${id}-err`} className="mt-1 text-xs text-block-ink" role="alert">
          {shownError}
        </p>
      ) : null}
    </div>
  );
}
