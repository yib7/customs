import { useTheme, type ThemePref } from '../lib/theme';
import { IconMonitor, IconMoon, IconSun } from './Icons';

const OPTIONS: { value: ThemePref; label: string; Icon: typeof IconSun }[] = [
  { value: 'system', label: 'Use system theme', Icon: IconMonitor },
  { value: 'light', label: 'Light theme', Icon: IconSun },
  { value: 'dark', label: 'Dark theme', Icon: IconMoon },
];

export function ThemeToggle() {
  const { pref, setPref } = useTheme();
  return (
    <div role="radiogroup" aria-label="Color theme" className="inline-flex rounded-lg border border-line bg-surface p-0.5">
      {OPTIONS.map(({ value, label, Icon }) => {
        const active = pref === value;
        return (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={label}
            title={label}
            onClick={() => setPref(value)}
            onKeyDown={(e) => {
              if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
              e.preventDefault();
              const i = OPTIONS.findIndex((o) => o.value === pref);
              const next = OPTIONS[(i + (e.key === 'ArrowRight' ? 1 : OPTIONS.length - 1)) % OPTIONS.length];
              if (next) {
                setPref(next.value);
                const group = e.currentTarget.parentElement;
                const btn = group?.querySelector<HTMLButtonElement>(`[data-theme-option="${next.value}"]`);
                btn?.focus();
              }
            }}
            tabIndex={active ? 0 : -1}
            data-theme-option={value}
            className={`rounded-md p-1.5 ${active ? 'bg-surface-3 text-ink' : 'text-muted hover:text-ink'}`}
          >
            <Icon size={15} />
          </button>
        );
      })}
    </div>
  );
}
