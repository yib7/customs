// Records the README demo: a walkthrough of the dashboard served by a running
// `customs serve`, while the Claude Code hook stops an agent's install.
//
//   node scripts/demo-gif.mjs [baseUrl] [out.webm]
//   ffmpeg -i out.webm -vf "fps=10,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" demo.gif
//
// Expects blocked installs to exist already (scripts/replay.py --keep produces them) and
// the release binary in ../target/release.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from '@playwright/test';

const base = process.argv[2] ?? 'http://127.0.0.1:7878';
const out = process.argv[3] ?? 'demo.webm';
const size = { width: 1280, height: 800 };

const events = await (await fetch(`${base}/api/events?limit=200`)).json();
const blocked = events.find((e) => e.decision === 'block' && e.kind === 'install');
if (!blocked) throw new Error(`no blocked install at ${base}; run scripts/replay.py --keep first`);

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
      position: 'fixed', left: '50%', bottom: '24px', transform: 'translateX(-50%)', zIndex: '99998',
      maxWidth: '900px', padding: '10px 18px', borderRadius: '10px', background: 'rgba(17, 24, 39, 0.88)',
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
    await page.waitForTimeout(30);
  }
}

function agentInstall(command) {
  const input = JSON.stringify({
    tool_name: 'Bash',
    tool_input: { command },
    cwd: tmpdir(),
    hook_event_name: 'PreToolUse',
  });
  spawnSync('../target/release/customs', ['hook', 'claude-code'], {
    input,
    env: { ...process.env, CUSTOMS_SERVER: base },
  });
}

const videoDir = mkdtempSync(join(tmpdir(), 'customs-demo-'));
const browser = await chromium.launch(
  process.env.CUSTOMS_CHROMIUM_PATH ? { executablePath: process.env.CUSTOMS_CHROMIUM_PATH } : {},
);
const context = await browser.newContext({ viewport: size, recordVideo: { dir: videoDir, size } });
await context.addInitScript(overlay);
const page = await context.newPage();
await page.emulateMedia({ colorScheme: 'light' });

await page.goto(base + '/');
await page.getByTestId('live-feed').waitFor();
await page.mouse.move(640, 300);
await caption(page, 'Every package pip or npm fetches goes through Customs and is scanned first');
await page.waitForTimeout(3000);

await caption(page, 'An agent runs: pip install reqeusts');
await page.waitForTimeout(1500);
agentInstall('pip install reqeusts');
await page.waitForTimeout(2500);
await caption(page, 'The hook denies the command: that package does not exist on PyPI');
await page.waitForTimeout(3000);

const row = page.locator(`[data-testid="feed-row"][data-event-id="${blocked.id}"]`);
await caption(page, `${blocked.name} is real malware from the held-out test set`);
if (await row.count()) {
  await moveTo(page, row);
  await page.waitForTimeout(1200);
  await row.click();
} else {
  await page.goto(`${base}/verdicts/${blocked.verdict_id}`);
}
await page.getByTestId('verdict').waitFor();
await page.waitForTimeout(1500);
await caption(page, 'Blocked, with the model reasons and the lines of code behind them');
await page.waitForTimeout(2000);
await scroll(page, 900);
await page.waitForTimeout(2500);

await caption(page, '');
const check = page.getByRole('link', { name: 'Check a package' });
await moveTo(page, check);
await check.click();
await page.locator('#check-name').waitFor();
await moveTo(page, page.locator('#check-name'));
await page.locator('#check-name').click();
await page.keyboard.type('reqeusts', { delay: 120 });
await page.keyboard.press('Enter');
await page.getByTestId('nonexistent-result').waitFor();
await caption(page, 'Names an LLM invents are caught before anything is downloaded');
await page.waitForTimeout(3500);

const model = page.getByRole('link', { name: 'Model' });
await moveTo(page, model);
await model.click();
await page.getByTestId('model-version').waitFor();
await caption(page, 'Thresholds are set on validation data, then measured once on newer malware');
await page.waitForTimeout(2000);
await scroll(page, 600);
await page.waitForTimeout(2500);
await caption(page, '');
await page.waitForTimeout(500);

await context.close();
await browser.close();
const [video] = readdirSync(videoDir);
renameSync(join(videoDir, video), out);
console.log(`wrote ${out}`);
