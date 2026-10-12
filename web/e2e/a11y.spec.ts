import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

// axe-core over every page in both themes: WCAG 2.1 A and AA, including text contrast and
// links told apart from the text around them by more than colour.

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.__CUSTOMS_MOCK_NO_AUTO = true;
  });
});

const PAGES: { name: string; path: string; ready?: (p: Page) => Promise<void> }[] = [
  { name: 'overview', path: '/' },
  { name: 'activity', path: '/activity', ready: async (p) => void (await p.getByTestId('event-row').first().waitFor()) },
  { name: 'blocked verdict', path: '/verdicts/41', ready: async (p) => void (await p.getByTestId('verdict').waitFor()) },
  { name: 'warned verdict', path: '/verdicts/43', ready: async (p) => void (await p.getByTestId('verdict').waitFor()) },
  {
    name: 'check result',
    path: '/check',
    ready: async (p) => {
      await p.getByLabel('Package name').fill('huggingface-cli');
      await p.getByRole('button', { name: 'Check', exact: true }).click();
      await p.getByTestId('nonexistent-result').waitFor();
    },
  },
  { name: 'policy', path: '/policy', ready: async (p) => void (await p.getByRole('heading', { name: 'Mode' }).waitFor()) },
  { name: 'model', path: '/model', ready: async (p) => void (await p.getByTestId('model-version').waitFor()) },
  { name: 'not found', path: '/no-such-page' },
];

for (const scheme of ['light', 'dark'] as const) {
  for (const { name, path, ready } of PAGES) {
    test(`${name} has no axe violations (${scheme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto(path);
      await page.getByRole('heading', { level: 1 }).first().waitFor();
      await ready?.(page);
      const { violations } = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      const summary = violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
      expect(summary).toEqual([]);
    });
  }
}
