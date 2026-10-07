import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './index.css';

async function start() {
  // The mock API is only included in builds made with VITE_MOCK=1 (`--mode mock`).
  // In a production build this branch is removed and the mock module is not bundled.
  if (import.meta.env.VITE_MOCK === '1') {
    const { installMocks } = await import('./mock');
    installMocks();
  }
  const root = document.getElementById('root');
  if (!root) throw new Error('missing #root');
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

void start();
