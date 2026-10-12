// Screenshots of the dashboard served by a running `customs serve`, with real verdicts
// from the trained models (unlike e2e/screenshots.spec.ts, which uses the mock API).
//
//   node scripts/live-screenshots.mjs [baseUrl] [outDir]
//
// Expects some traffic to exist already, including a blocked install (the README shots
// used the installs from the demo, see scripts/demo-gif.mjs). The Check page shot checks
// the made-up name `reqeusts`, which adds one check to the server's history.
import { mkdirSync } from 'node:fs';
import { chromium } from '@playwright/test';

const base = process.argv[2] ?? 'http://127.0.0.1:7878';
const out = process.argv[3] ?? '../docs/media';
mkdirSync(out, { recursive: true });

const events = await (await fetch(`${base}/api/events?limit=200`)).json();
const blocked = events.find((e) => e.decision === 'block' && e.kind === 'install')
  ?? events.find((e) => e.decision === 'block');

const shots = [
  { name: 'overview', path: '/', wait: 'live-feed' },
  {
    name: 'check',
    path: '/check?ecosystem=pypi&name=reqeusts',
    wait: 'nonexistent-result',
    before: (page) => page.getByRole('button', { name: 'Check', exact: true }).click(),
  },
  ...(blocked ? [{ name: 'verdict', path: `/verdicts/${blocked.verdict_id}`, wait: 'verdict' }] : []),
  { name: 'model', path: '/model', wait: 'model-version' },
];

const browser = await chromium.launch(
  process.env.CUSTOMS_CHROMIUM_PATH ? { executablePath: process.env.CUSTOMS_CHROMIUM_PATH } : {},
);
// Page by page, both themes of a page back to back, so the overview's live feed is the same
// in its light and dark shots (the Check page adds a check each time it runs).
const pages = {};
for (const scheme of ['light', 'dark']) {
  pages[scheme] = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await pages[scheme].emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
}
for (const s of shots) {
  for (const [scheme, page] of Object.entries(pages)) {
    await page.goto(base + s.path);
    if (s.before) await s.before(page);
    await page.getByTestId(s.wait).waitFor({ timeout: 15000 });
    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    await page.setViewportSize({ width: 1440, height: Math.max(900, height) });
    await page.waitForTimeout(500);
    await page.screenshot({ path: `${out}/${s.name}-${scheme}.png`, animations: 'disabled' });
    await page.setViewportSize({ width: 1440, height: 900 });
  }
}
await browser.close();
console.log(`wrote ${shots.length * 2} screenshots to ${out}`);
