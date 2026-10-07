import { useEffect, useRef } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router';
import { useLive } from '../live/context';
import { ConnectionIndicator } from './ConnectionIndicator';
import { IconChip, IconGrid, IconList, IconSearch, IconShield, IconSliders } from './Icons';
import { ThemeToggle } from './ThemeToggle';

const NAV = [
  { to: '/', label: 'Overview', Icon: IconGrid, end: true },
  { to: '/activity', label: 'Activity', Icon: IconList, end: false },
  { to: '/check', label: 'Check a package', Icon: IconSearch, end: false },
  { to: '/policy', label: 'Policy', Icon: IconSliders, end: false },
  { to: '/model', label: 'Model', Icon: IconChip, end: false },
];

const MOCK = import.meta.env.VITE_MOCK === '1';

function Brand() {
  return (
    <NavLink to="/" className="flex items-center gap-2 rounded-md text-ink" aria-label="Customs, go to overview">
      <span className="grid h-7 w-7 place-items-center rounded-lg bg-accent text-accent-ink">
        <IconShield size={17} />
      </span>
      <span className="text-[15px] font-semibold tracking-tight">Customs</span>
    </NavLink>
  );
}

export function Layout() {
  const { status } = useLive();
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const first = useRef(true);

  // Move focus to the main region on navigation so keyboard and screen reader users land
  // on the new page content.
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    mainRef.current?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [location.pathname]);

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only-focusable fixed top-2 left-2 z-50 rounded-md bg-accent px-3 py-2 text-sm font-medium text-accent-ink"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-30 border-b border-line bg-surface/90 backdrop-blur supports-[backdrop-filter]:bg-surface/80">
        <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-3 px-4 sm:px-6">
          <Brand />
          {MOCK ? (
            <span
              className="hidden rounded-full border border-dashed border-line-strong px-2 py-0.5 text-[11px] font-medium text-muted sm:inline"
              title="The dashboard is running against the built-in mock API with sample data."
            >
              Demo data
            </span>
          ) : null}
          <div className="ml-auto flex items-center gap-2">
            <ConnectionIndicator status={status} />
            <ThemeToggle />
          </div>
        </div>
        <nav aria-label="Primary" className="border-t border-line md:hidden">
          <ul className="flex gap-1 overflow-x-auto px-3 py-1.5 [scrollbar-width:none]">
            {NAV.map(({ to, label, Icon, end }) => (
              <li key={to} className="shrink-0">
                <NavLink
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    `flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[13px] max-[430px]:px-2 font-medium whitespace-nowrap ${
                      isActive ? 'bg-accent-soft text-ink' : 'text-ink-2 hover:bg-surface-2'
                    }`
                  }
                >
                  <Icon size={15} className="max-[430px]:hidden" />
                  {label === 'Check a package' ? 'Check' : label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
      </header>
      <div className="mx-auto flex max-w-[1400px] gap-6 px-4 sm:px-6">
        <nav aria-label="Primary" className="sticky top-14 hidden h-[calc(100vh-3.5rem)] w-52 shrink-0 py-6 md:block">
          <ul className="flex flex-col gap-0.5">
            {NAV.map(({ to, label, Icon, end }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium ${
                      isActive
                        ? 'bg-accent-soft text-ink shadow-[inset_2px_0_0_var(--c-accent)]'
                        : 'text-ink-2 hover:bg-surface-2 hover:text-ink'
                    }`
                  }
                >
                  <Icon size={17} />
                  {label}
                </NavLink>
              </li>
            ))}
          </ul>
          <p className="mt-6 px-3 text-xs leading-relaxed text-muted">
            Customs inspects every package your tools and agents install, before it reaches this machine.
          </p>
        </nav>
        <main id="main" ref={mainRef} tabIndex={-1} className="min-w-0 flex-1 py-6 outline-none">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
