import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { AppRoutes } from '../App';
import { LiveProvider } from '../live/LiveProvider';
import { installMocks, type MockControls } from '../mock';

/** Renders the whole app at `path` against a fresh in-memory mock API. */
export function renderApp(path: string): MockControls {
  const mock = installMocks({ latencyMs: 0, autoEmitMs: 0, fresh: true });
  render(
    <MemoryRouter initialEntries={[path]}>
      <LiveProvider>
        <AppRoutes />
      </LiveProvider>
    </MemoryRouter>,
  );
  return mock;
}
