import { BrowserRouter, Route, Routes } from 'react-router';
import { Layout } from './components/Layout';
import { LiveProvider } from './live/LiveProvider';
import { ActivityPage } from './pages/Activity';
import { CheckPage } from './pages/Check';
import { ModelPage } from './pages/Model';
import { NotFoundPage } from './pages/NotFound';
import { OverviewPage } from './pages/Overview';
import { PolicyPage } from './pages/Policy';
import { VerdictPage } from './pages/Verdict';

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<OverviewPage />} />
        <Route path="activity" element={<ActivityPage />} />
        <Route path="verdicts/:id" element={<VerdictPage />} />
        <Route path="check" element={<CheckPage />} />
        <Route path="policy" element={<PolicyPage />} />
        <Route path="model" element={<ModelPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <LiveProvider>
        <AppRoutes />
      </LiveProvider>
    </BrowserRouter>
  );
}
