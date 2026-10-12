import { expect, test, type Page } from '@playwright/test';

// End-to-end tests against the mock-mode build (npm run build:mock). The in-memory API is
// exposed as window.__customsMock so tests can push live events deterministically.

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.__CUSTOMS_MOCK_NO_AUTO = true;
  });
});

async function waitLive(page: Page) {
  await expect(page.getByTestId('connection-status')).toHaveAttribute('data-status', 'live');
}

test('navigates between all pages with the sidebar and keyboard', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  await expect(page).toHaveTitle('Overview | Customs');

  const nav = page.getByRole('navigation', { name: 'Primary' }).last();
  for (const [link, heading] of [
    ['Activity', 'Activity'],
    ['Check a package', 'Check a package'],
    ['Policy', 'Policy'],
    ['Model', 'Model'],
    ['Overview', 'Overview'],
  ] as const) {
    await nav.getByRole('link', { name: link }).click();
    await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible();
  }

  // After client-side navigation, focus moves to the main region.
  await expect(page.locator('main#main')).toBeFocused();

  // On a fresh load the skip link is the first tab stop.
  await page.goto('/activity');
  // goto resolves on the load event, which can fire before React's first render; a Tab
  // pressed then lands on an empty page.
  await expect(page.getByRole('heading', { level: 1, name: 'Activity' })).toBeVisible();
  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: 'Skip to content' });
  await expect(skip).toBeFocused();
  await expect(skip).toBeVisible();

  await page.goto('/does-not-exist');
  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible();
});

test('live feed shows new events as they stream in', async ({ page }) => {
  await page.goto('/');
  await waitLive(page);
  const feed = page.getByTestId('live-feed');
  await expect(feed.getByTestId('feed-row').first()).toBeVisible();
  const before = Number(await page.getByTestId('tile-total').locator('p').nth(1).textContent());

  const id = await page.evaluate(() => String(window.__customsMock?.emitBlocked().id));
  const first = feed.getByTestId('feed-row').first();
  await expect(first).toHaveAttribute('data-event-id', id);
  await expect(first).toContainText('reqeusts');
  await expect(first).toContainText('Blocked');
  // Aggregates refresh shortly after.
  await expect(page.getByTestId('tile-total').locator('p').nth(1)).toHaveText(String(before + 1));
});

test('reconnects after the stream drops', async ({ page }) => {
  await page.goto('/');
  await waitLive(page);
  await page.evaluate(() => window.__customsMock?.dropStream());
  await expect(page.getByTestId('connection-status')).toHaveAttribute('data-status', 'reconnecting');
  await waitLive(page);
  const id = await page.evaluate(() => String(window.__customsMock?.emit().id));
  await expect(page.getByTestId('live-feed').getByTestId('feed-row').first()).toHaveAttribute('data-event-id', id);
});

test('activity filters and links to a verdict', async ({ page }) => {
  await page.goto('/activity');
  await expect(page.getByTestId('event-row').first()).toBeVisible();
  await page.getByLabel('Decision').selectOption('block');
  await expect(page).toHaveURL(/decision=block/);
  const rows = page.getByTestId('event-row');
  await expect(rows.first()).toBeVisible();
  for (const text of await rows.allTextContents()) expect(text).toMatch(/Blocked|Not found/);

  await page.getByLabel('Package name').fill('lodash');
  await expect(page).toHaveURL(/q=lodash/);
  await expect(rows.first()).toContainText('@lodash-utils/core');
  await rows.first().getByRole('link').click();
  await expect(page).toHaveURL(/\/verdicts\/42$/);
  await expect(page.getByRole('heading', { level: 1 })).toContainText('@lodash-utils/core');

  await page.getByRole('button', { name: 'Back' }).click();
  await expect(page).toHaveURL(/q=lodash/);
  await page.getByRole('button', { name: 'Clear' }).click();
  await expect(page).toHaveURL(/\/activity$/);
  await page.getByRole('button', { name: 'Older' }).click();
  await expect(page).toHaveURL(/before=/);
  await page.getByRole('button', { name: 'Newer' }).click();
  await expect(page).not.toHaveURL(/before=/);
});

test('verdict detail renders evidence safely and explains the decision', async ({ page }) => {
  const dialogs: string[] = [];
  page.on('dialog', (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await page.goto('/verdicts/42');
  const verdict = page.getByTestId('verdict');
  await expect(verdict.getByRole('heading', { level: 1 })).toContainText('@lodash-utils/core');
  await expect(page.getByTestId('risk-gauge').getByRole('img')).toHaveAttribute('aria-label', /Risk 96.4%, above the block threshold/);
  await expect(page.getByText('Install scripts in a brand-new package')).toBeVisible();

  // The HTML payload is shown as text and never parsed.
  const snippets = page.getByTestId('evidence-snippet');
  await expect(snippets.filter({ hasText: '<img src=x onerror=alert(document.domain)>' })).toHaveCount(1);
  expect(await verdict.locator('img, script').count()).toBe(0);
  await expect(page.getByText(/<U\+202E>/).first()).toBeVisible();
  expect(dialogs).toEqual([]);

  const registry = page.getByRole('link', { name: /View on npm/ });
  await expect(registry).toHaveAttribute('href', 'https://www.npmjs.com/package/@lodash-utils/core');
  await expect(page.getByText('customs check npm:@lodash-utils/core@4.17.22')).toBeVisible();
});

test('verdict copy button copies the full sha256', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/verdicts/41');
  const short = await page.getByTestId('sha-short').textContent();
  await page.getByRole('button', { name: 'Copy full SHA-256' }).click();
  await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible();
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  expect(clip).toHaveLength(64);
  expect(clip.startsWith(short ?? 'x')).toBe(true);
});

test('check form shows the verdict inline and handles nonexistent packages', async ({ page }) => {
  await page.goto('/check');
  await page.getByLabel('Package name').fill('reqeusts==2.32.4');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  const verdict = page.getByTestId('verdict');
  await expect(verdict).toBeVisible();
  await expect(verdict.getByRole('heading', { level: 2 })).toContainText('reqeusts');
  await expect(verdict.getByText('Blocked').first()).toBeVisible();

  await page.getByText('npm', { exact: true }).click();
  await page.getByLabel('Package name').fill('left-pad');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('verdict').getByRole('heading', { level: 2 })).toContainText('left-pad');
  await expect(page.getByTestId('verdict').getByText('Allowed').first()).toBeVisible();

  await page.getByText('PyPI', { exact: true }).click();
  await page.getByLabel('Package name').fill('huggingface-cli');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('nonexistent-result')).toContainText('does not exist on PyPI');

  await page.getByLabel('Package name').fill('not a name');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByText(/Not a valid PyPI name/)).toBeVisible();
});

test('policy edits are validated and saved', async ({ page }) => {
  await page.goto('/policy');
  await expect(page.getByRole('heading', { name: 'Mode' })).toBeVisible();

  await page.getByRole('radio', { name: /Monitor/ }).check();
  const age = page.getByLabel('Minimum age (days)');
  await age.fill('400');
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.getByTestId('policy-server-error')).toContainText('invalid policy');
  await expect(page.getByText('min_age_days must be at most 365 (server limit)')).toBeVisible();

  await age.fill('7');
  const allow = page.getByRole('textbox', { name: 'Always allow' });
  await allow.fill('not-an-entry');
  await allow.press('Enter');
  await expect(page.getByText(/Use the form ecosystem:name/)).toBeVisible();
  await allow.fill('npm:left-pad@1.3.0');
  await allow.press('Enter');
  await page.getByRole('button', { name: 'Remove npm:react' }).click();

  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.getByTestId('policy-saved')).toBeVisible();
  const saved = await page.evaluate(() => window.__customsMock?.server.policy);
  expect(saved).toMatchObject({ mode: 'monitor', min_age_days: 7, allow: ['pypi:requests', 'npm:left-pad@1.3.0'] });

  // Reload: the server state is in memory per page, so verify the form reflects the save
  // by navigating away and back within the app.
  await page.getByRole('navigation', { name: 'Primary' }).last().getByRole('link', { name: 'Model' }).click();
  await page.getByRole('navigation', { name: 'Primary' }).last().getByRole('link', { name: 'Policy' }).click();
  await expect(page.getByLabel('Minimum age (days)')).toHaveValue('7');
  await expect(page.getByRole('radio', { name: /Monitor/ })).toBeChecked();
});

test('theme toggle persists and follows the system by default', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/model');
  await expect(page.locator('html')).not.toHaveAttribute('data-theme', /.+/);
  const bgDark = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await page.getByRole('radio', { name: 'Light theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  const bgLight = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(bgLight).not.toBe(bgDark);
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.getByRole('radio', { name: 'Use system theme' }).click();
  await expect(page.locator('html')).not.toHaveAttribute('data-theme', /.+/);
});

test('phone layout has no horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 780 });
  for (const path of ['/', '/activity', '/verdicts/42', '/check', '/policy', '/model']) {
    await page.goto(path);
    await page.getByRole('heading', { level: 1 }).first().waitFor();
    // Charts and fonts settle after the heading renders; poll instead of sleeping.
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), { message: path })
      .toBeLessThanOrEqual(0);
  }
});
