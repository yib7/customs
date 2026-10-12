import { useCallback, useEffect, useState } from 'react';

export type ThemePref = 'system' | 'light' | 'dark';

const KEY = 'customs-theme';

function readThemePref(): ThemePref {
  try {
    const v = window.localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

function writeThemePref(pref: ThemePref): void {
  try {
    if (pref === 'system') window.localStorage.removeItem(KEY);
    else window.localStorage.setItem(KEY, pref);
  } catch {
    // Storage blocked (private mode, sandbox): the choice lasts for this page only.
  }
}

function applyThemePref(pref: ThemePref): void {
  const root = document.documentElement;
  if (pref === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', pref);
}

function systemDark(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

export function useTheme(): { pref: ThemePref; resolved: 'light' | 'dark'; setPref: (p: ThemePref) => void } {
  const [pref, setPrefState] = useState<ThemePref>(readThemePref);
  const [sysDark, setSysDark] = useState<boolean>(systemDark);

  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => setSysDark(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    applyThemePref(pref);
  }, [pref]);

  const setPref = useCallback((p: ThemePref) => {
    writeThemePref(p);
    setPrefState(p);
  }, []);

  const resolved = pref === 'system' ? (sysDark ? 'dark' : 'light') : pref;
  return { pref, resolved, setPref };
}
