import { expect, test, type Page } from '@playwright/test';

// Captures every page in light and dark mode at desktop and phone widths into
// web/screenshots/. These images are committed and used in the README.

const PAGES: { name: string; path: string; ready: (p: Page) => Promise<void> }[] = [
  { name: 'overview', path: '/', ready: async (p) => void (await p.getByTestId('live-feed').waitFor()) },
  { name: 'activity', path: '/activity', ready: async (p) => void (await p.getByTestId('events-table').waitFor()) },
  { name: 'verdict', path: '/verdicts/41', ready: async (p) => void (await p.getByTestId('verdict').waitFor()) },
  {
    name: 'check',
    path: '/check?ecosystem=npm&name=%40lodash-utils%2Fcore',
    ready: async (p) => {
      await p.getByRole('button', { name: 'Check', exact: true }).click();
      await p.getByTestId('verdict').waitFor();
    },
  },
  { name: 'policy', path: '/policy', ready: async (p) => void (await p.getByRole('heading', { name: 'Mode' }).waitFor()) },
  { name: 'model', path: '/model', ready: async (p) => void (await p.getByTestId('model-version').waitFor()) },
];

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
] as const;

test.describe('screenshots', () => {
  for (const vp of VIEWPORTS) {
    for (const scheme of ['light', 'dark'] as const) {
      for (const pg of PAGES) {
        test(`${pg.name} ${scheme} ${vp.name}`, async ({ page }) => {
          await page.setViewportSize({ width: vp.width, height: vp.height });
          await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
          await page.addInitScript(() => {
            window.__CUSTOMS_MOCK_NO_AUTO = true;
          });
          await page.goto(pg.path);
          await pg.ready(page);
          await expect(page.getByTestId('connection-status')).toHaveAttribute('data-status', 'live');
          // Grow the viewport to the full page height so sticky elements (header, policy
          // save bar) render where they rest instead of mid-page.
          const height = await page.evaluate(() => document.documentElement.scrollHeight);
          await page.setViewportSize({ width: vp.width, height: Math.max(vp.height, height) });
          // Let the charts measure their containers and animations settle.
          await page.waitForTimeout(400);
          await page.screenshot({
            path: `screenshots/${pg.name}-${scheme}-${vp.name}.png`,
            animations: 'disabled',
          });
        });
      }
    }
  }
});
