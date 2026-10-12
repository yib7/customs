// Records the dashboard part of the README demo (docs/media/demo.gif) from a running
// `customs serve`: the live feed, the verdict of a blocked install, and the Model page.
//
//   node scripts/demo-gif.mjs [baseUrl] [outDir]
//
// Frames come from the Chrome DevTools screencast (a frame each time the page paints, with
// its timestamp), written as PNGs plus an ffmpeg concat list, frames.txt, that keeps the
// real timing.
//
// Expects a blocked install to exist already. The README demo used the inert install-time
// stealer from python/scripts/demo.sh, installed with npm through the proxy. The terminal
// parts of the GIF are real shell sessions recorded byte for byte with their timings
// (asciinema v2 casts) and rendered frame by frame; the pieces are joined and encoded with
//   ffmpeg -f concat -i parts.txt -vf "fps=12.5,split[a][b];[a]palettegen=max_colors=192:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" demo.gif
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { chromium } from '@playwright/test';

const base = process.argv[2] ?? 'http://127.0.0.1:7878';
const out = process.argv[3] ?? 'demo-frames';
const size = { width: 1100, height: 690 };

const events = await (await fetch(`${base}/api/events?limit=200`)).json();
const blocked = events.find((e) => e.decision === 'block' && e.kind === 'install');
if (!blocked) throw new Error(`no blocked install at ${base}; install a blocked package through the proxy first`);

// A visible cursor and a caption bar, since the recording shows neither on its own.
const overlay = () => {
  window.addEventListener('DOMContentLoaded', () => {
    const cursor = document.createElement('div');
    cursor.id = 'demo-cursor';
    Object.assign(cursor.style, {
      position: 'fixed', left: '0', top: '0', width: '18px', height: '18px', zIndex: '99999',
      borderRadius: '50%', background: 'rgba(15, 118, 110, 0.55)', border: '2px solid #fff',
      boxShadow: '0 0 0 1px rgba(0,0,0,0.25)', pointerEvents: 'none', transform: 'translate(-50%, -50%)',
    });
    document.body.appendChild(cursor);
    window.addEventListener('mousemove', (e) => {
      cursor.style.left = `${e.clientX}px`;
      cursor.style.top = `${e.clientY}px`;
    });
    const caption = document.createElement('div');
    caption.id = 'demo-caption';
    Object.assign(caption.style, {
      position: 'fixed', left: '50%', bottom: '20px', transform: 'translateX(-50%)', zIndex: '99998',
      width: 'max-content', maxWidth: '1000px', padding: '10px 18px', borderRadius: '10px', background: 'rgba(17, 24, 39, 0.9)',
      color: '#fff', font: '500 17px system-ui, sans-serif', textAlign: 'center', pointerEvents: 'none',
      opacity: '0', transition: 'opacity 250ms',
    });
    document.body.appendChild(caption);
  });
};

async function caption(page, text) {
  await page.evaluate((t) => {
    const c = document.getElementById('demo-caption');
    c.textContent = t;
    c.style.opacity = t ? '1' : '0';
  }, text);
}

async function moveTo(page, locator) {
  const box = await locator.boundingBox();
  await page.mouse.move(box.x + Math.min(box.width / 2, 160), box.y + box.height / 2, { steps: 25 });
  await page.waitForTimeout(250);
}

async function scroll(page, pixels) {
  for (let i = 0; i < pixels / 40; i++) {
    await page.mouse.wheel(0, 40);
    await page.waitForTimeout(40);
  }
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
const browser = await chromium.launch(
  process.env.CUSTOMS_CHROMIUM_PATH ? { executablePath: process.env.CUSTOMS_CHROMIUM_PATH } : {},
);
const context = await browser.newContext({ viewport: size });
await context.addInitScript(overlay);
const page = await context.newPage();
await page.emulateMedia({ colorScheme: 'light' });

await page.goto(base + '/');
await page.getByTestId('live-feed').waitFor();
await page.evaluate(() => document.fonts.ready.then(() => undefined));
await page.mouse.move(700, 260);

// Record from here on: each painted frame and the time it was painted.
const frames = [];
const cdp = await context.newCDPSession(page);
cdp.on('Page.screencastFrame', async ({ data, metadata, sessionId }) => {
  const file = `${String(frames.length).padStart(5, '0')}.png`;
  frames.push({ file, t: metadata.timestamp });
  writeFileSync(`${out}/${file}`, Buffer.from(data, 'base64'));
  await cdp.send('Page.screencastFrameAck', { sessionId }).catch(() => {});
});
await cdp.send('Page.startScreencast', { format: 'png', maxWidth: size.width, maxHeight: size.height });
// Force one paint so the first frame arrives at once.
await page.mouse.move(701, 260);
await caption(page, 'The dashboard: every install and check from the terminals, live');
await page.waitForTimeout(3000);

// Scroll the live feed into view, then open the blocked install.
const row = page.locator(`[data-testid="feed-row"][data-event-id="${blocked.id}"]`);
const top = await row.evaluate((el) => el.getBoundingClientRect().top);
await scroll(page, Math.max(0, top - 330));
await page.waitForTimeout(800);
await caption(page, `${blocked.name}: blocked on the way in`);
await moveTo(page, row);
await page.waitForTimeout(1500);
await row.click();
await page.getByTestId('verdict').waitFor();
await page.mouse.move(820, 300, { steps: 10 });
await caption(page, 'Blocked: the model risk is past the block threshold');
await page.waitForTimeout(3000);
await caption(page, 'Why: the features that pushed the score up');
await scroll(page, 560);
await page.waitForTimeout(3500);
await caption(page, 'Evidence: the install-time code behind them, shown as text and never run');
await scroll(page, 520);
await page.waitForTimeout(4000);

await caption(page, '');
const model = page.getByRole('link', { name: 'Model' }).first();
await moveTo(page, model);
await model.click();
await page.getByTestId('model-version').waitFor();
await caption(page, 'Thresholds are set on validation data, then measured once on newer malware');
await page.waitForTimeout(2500);
await scroll(page, 480);
await page.waitForTimeout(3000);
await caption(page, '');
await page.waitForTimeout(400);
const end = Date.now() / 1000;
await cdp.send('Page.stopScreencast');
await context.close();
await browser.close();

// ffmpeg concat list: each frame lasts until the next one was painted.
const list = ['ffconcat version 1.0'];
frames.forEach((f, i) => {
  const next = i + 1 < frames.length ? frames[i + 1].t : end;
  list.push(`file '${f.file}'`, `duration ${Math.max(0.001, next - f.t).toFixed(4)}`);
});
list.push(`file '${frames.at(-1).file}'`);
writeFileSync(`${out}/frames.txt`, `${list.join('\n')}\n`);
console.log(`wrote ${frames.length} frames, ${(end - frames[0].t).toFixed(2)} s, to ${out}`);
