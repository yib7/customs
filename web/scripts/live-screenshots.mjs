// Screenshots of the dashboard served by a running `customs serve`, with real verdicts
// from the trained models (unlike e2e/screenshots.spec.ts, which uses the mock API).
//
//   node scripts/live-screenshots.mjs [baseUrl] [outDir]
//
// Expects some traffic to exist already (scripts/demo.sh with KEEP=1 produces it).
import { mkdirSync } from 'node:fs';
import { chromium } from '@playwright/test';

const base = process.argv[2] ?? 'http://127.0.0.1:7878';
const out = process.argv[3] ?? '../docs/screenshots';
mkdirSync(out, { recursive: true });

const events = await (await fetch(`${base}/api/events?limit=200`)).json();
const blocked = events.find((e) => e.decision === 'block' && e.kind === 'install')
  ?? events.find((e) => e.decision === 'block');

const shots = [
  { name: 'overview', path: '/', wait: 'live-feed' },
  { name: 'activity', path: '/activity', wait: 'events-table' },
  ...(blocked ? [{ name: 'verdict', path: `/verdicts/${blocked.verdict_id}`, wait: 'verdict' }] : []),
  { name: 'model', path: '/model', wait: 'model-version' },
];

const browser = await chromium.launch(
  process.env.CUSTOMS_CHROMIUM_PATH ? { executablePath: process.env.CUSTOMS_CHROMIUM_PATH } : {},
);
for (const scheme of ['light', 'dark']) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
  for (const s of shots) {
    await page.goto(base + s.path);
    await page.getByTestId(s.wait).waitFor({ timeout: 15000 });
    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    await page.setViewportSize({ width: 1440, height: Math.max(900, height) });
    await page.waitForTimeout(500);
    await page.screenshot({ path: `${out}/${s.name}-${scheme}.png`, animations: 'disabled' });
    await page.setViewportSize({ width: 1440, height: 900 });
  }
  await page.close();
}
await browser.close();
console.log(`wrote ${shots.length * 2} screenshots to ${out}`);
