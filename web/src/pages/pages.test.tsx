import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderApp } from '../test/render';

describe('Policy page', () => {
  it('validates thresholds on the client before saving', async () => {
    const user = userEvent.setup();
    renderApp('/policy');
    await screen.findByRole('heading', { name: 'Mode' });
    const warnCustom = within(screen.getByRole('group', { name: 'Warn threshold' })).getByLabelText('Custom');
    await user.click(warnCustom);
    const warnInput = screen.getByRole('textbox', { name: /Warn threshold, custom value/ });
    await user.type(warnInput, '0.9');
    const blockCustom = within(screen.getByRole('group', { name: 'Block threshold' })).getByLabelText('Custom');
    await user.click(blockCustom);
    await user.type(screen.getByRole('textbox', { name: /Block threshold, custom value/ }), '0.5');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByText('Block threshold must be higher than the warn threshold.')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-saved')).toBeNull();
  });

  it('rejects invalid list entries and shows server validation errors', async () => {
    const user = userEvent.setup();
    renderApp('/policy');
    const allowInput = await screen.findByRole('textbox', { name: 'Always allow' });
    await user.type(allowInput, 'requests{Enter}');
    expect(await screen.findByText(/Use the form ecosystem:name/)).toBeInTheDocument();
    await user.clear(allowInput);
    await user.type(allowInput, 'pypi:httpx{Enter}');
    expect(screen.getByRole('button', { name: 'Remove pypi:httpx' })).toBeInTheDocument();

    const age = screen.getByRole('textbox', { name: 'Minimum age (days)' });
    await user.clear(age);
    await user.type(age, '400');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByTestId('policy-server-error')).toHaveTextContent('invalid policy');
    expect(screen.getByText('min_age_days must be at most 365 (server limit)')).toBeInTheDocument();

    await user.clear(age);
    await user.type(age, '7');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByTestId('policy-saved')).toBeInTheDocument();
    expect(window.__customsMock?.server.policy).toMatchObject({ min_age_days: 7, allow: ['pypi:requests', 'npm:react', 'pypi:httpx'] });
  });

  it('asks for the admin token when the server requires one', async () => {
    const mock = renderApp('/policy').server;
    mock.adminToken = 'team-token-0123456789';
    const put = vi.spyOn(mock, 'handle');
    try {
      const user = userEvent.setup();
      const age = await screen.findByRole('textbox', { name: 'Minimum age (days)' });
      // GET /api/policy said a token is needed, so the field is there before any save.
      const token = screen.getByLabelText('Admin token');
      await user.clear(age);
      await user.type(age, '5');
      await user.click(screen.getByRole('button', { name: 'Save policy' }));
      // An empty token is caught here, not by a refused request.
      expect(await screen.findByText('Enter the admin token to save.')).toBeInTheDocument();
      await waitFor(() => expect(token).toHaveFocus());
      expect(put.mock.calls.filter(([method]) => method === 'PUT')).toHaveLength(0);
      // After a save the page moves focus to the status message on the next frame; typing
      // before that lands in the message, not the field.
      const statusFocused = () => waitFor(() => expect(screen.getByTestId('policy-server-error').parentElement).toHaveFocus());
      await user.type(token, 'wrong-token');
      await user.click(screen.getByRole('button', { name: 'Save policy' }));
      expect(await screen.findByText('the admin token is not valid')).toBeInTheDocument();
      expect(mock.policy).toMatchObject({ min_age_days: 3 });
      await statusFocused();
      await user.clear(token);
      await user.type(token, 'team-token-0123456789');
      await user.click(screen.getByRole('button', { name: 'Save policy' }));
      expect(await screen.findByTestId('policy-saved')).toBeInTheDocument();
      expect(mock.policy).toMatchObject({ min_age_days: 5 });
      expect(sessionStorage.getItem('customs-admin-token')).toBe('team-token-0123456789');
      // The change heads the log; the refused attempts are not in it.
      const log = await screen.findByTestId('policy-changes');
      await waitFor(() => expect(log.querySelector('li')).toHaveTextContent('min_age_days: 3 -> 5'));
      expect(log.querySelector('li')).toHaveTextContent('with the admin token');
      expect(mock.policyChanges.filter((c) => c.changes.some((f) => f.field === 'min_age_days' && f.after === 5))).toHaveLength(1);
    } finally {
      sessionStorage.clear();
    }
  });

  it('says when policy changes are off on this server, and offers no save', async () => {
    const mock = renderApp('/policy').server;
    mock.changesDisabled = true;
    expect(await screen.findByTestId('policy-changes-disabled')).toHaveTextContent('CUSTOMS_ADMIN_TOKEN');
    expect(screen.getByRole('button', { name: 'Save policy' })).toBeDisabled();
    expect(screen.getByRole('textbox', { name: 'Minimum age (days)' })).toBeDisabled();
  });

  it("labels the model default with the model's own threshold, not the override", async () => {
    const mock = renderApp('/policy');
    mock.server.policy.block_threshold = 0.9;
    const block = await screen.findByRole('group', { name: 'Block threshold' });
    await waitFor(() => expect(within(block).getByText('Model default (0.80)')).toBeInTheDocument());
  });

  it('edits the release history rules', async () => {
    const user = userEvent.setup();
    renderApp('/policy');
    const provenance = await screen.findByRole('combobox', { name: 'Provenance dropped' });
    expect(provenance).toHaveValue('warn');
    expect(screen.getByRole('combobox', { name: 'Unusual version jump' })).toHaveValue('off');
    expect(screen.getByRole('combobox', { name: 'Install script added' })).toHaveValue('block');
    await user.selectOptions(provenance, 'block');
    await user.selectOptions(screen.getByRole('combobox', { name: 'New publisher' }), 'off');
    const dormant = screen.getByRole('textbox', { name: 'Dormancy period (days)' });
    await user.clear(dormant);
    await user.type(dormant, '0');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByText('Enter a whole number of days from 1 to 3650.')).toBeInTheDocument();
    await user.clear(dormant);
    await user.type(dormant, '180');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByTestId('policy-saved')).toBeInTheDocument();
    expect(window.__customsMock?.server.policy).toMatchObject({
      provenance_dropped: 'block',
      publisher_changed: 'off',
      install_script_added: 'block',
      dormant_days: 180,
    });
  });

  it('edits the established-package prior', async () => {
    const user = userEvent.setup();
    renderApp('/policy');
    const trust = await screen.findByRole('switch', { name: /Trust established releases of popular packages/ });
    expect(trust).toBeChecked();
    const age = screen.getByRole('textbox', { name: 'Release age (days)' });
    expect(age).toHaveValue('30');
    expect(screen.getByRole('textbox', { name: 'Popular packages counted' })).toHaveValue('5000');
    await user.clear(age);
    await user.type(age, '0');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByText('Enter a whole number of days from 1 to 3650.')).toBeInTheDocument();
    await user.clear(age);
    await user.type(age, '60');
    await user.click(trust);
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByTestId('policy-saved')).toBeInTheDocument();
    expect(window.__customsMock?.server.policy).toMatchObject({
      established: { enabled: false, top: 5000, min_age_days: 60 },
    });
  });

  it('edits the scanner rules, including hidden_code', async () => {
    const user = userEvent.setup();
    const mock = renderApp('/policy');
    const hidden = await screen.findByRole('combobox', { name: 'Code the interpreter reads differently from the scanner' });
    expect(hidden).toHaveValue('block');
    expect(screen.getByRole('combobox', { name: 'Code the scanner could not read' })).toHaveValue('block');
    await user.selectOptions(hidden, 'warn');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByTestId('policy-saved')).toBeInTheDocument();
    expect(mock.server.policy).toMatchObject({ hidden_code: 'warn', unread_code: 'block' });
  });

  it('sends redacted upstream credentials back unchanged, so the server keeps them', async () => {
    const user = userEvent.setup();
    const mock = renderApp('/policy');
    const upstream = mock.server.policy.upstream as Record<string, string>;
    upstream.npm = 'https://ci:s3cret@npm.mirror.example';
    const handle = vi.spyOn(mock.server, 'handle');
    const age = await screen.findByRole('textbox', { name: 'Minimum age (days)' });
    expect(await screen.findByText('https://***@npm.mirror.example')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('s3cret');
    await user.clear(age);
    await user.type(age, '5');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    expect(await screen.findByTestId('policy-saved')).toBeInTheDocument();
    const put = handle.mock.calls.find(([method]) => method === 'PUT');
    expect((put?.[2] as { upstream: Record<string, string> }).upstream.npm).toBe('https://***@npm.mirror.example');
    expect((mock.server.policy.upstream as Record<string, string>).npm).toBe('https://ci:s3cret@npm.mirror.example');
    expect(mock.server.policy.min_age_days).toBe(5);
    expect(screen.getByText('https://***@npm.mirror.example')).toBeInTheDocument();
  });
});

describe('Check page', () => {
  it('shows a verdict inline', async () => {
    const user = userEvent.setup();
    renderApp('/check');
    await user.type(screen.getByRole('textbox', { name: 'Package name' }), 'reqeusts');
    await user.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByTestId('verdict')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /reqeusts/ })).toBeInTheDocument();
    // A check installs nothing.
    expect(screen.getByText('Customs would block this package.')).toBeInTheDocument();
  });

  it('explains nonexistent packages', async () => {
    const user = userEvent.setup();
    renderApp('/check');
    await user.type(screen.getByRole('textbox', { name: 'Package name' }), 'huggingface-cli');
    await user.click(screen.getByRole('button', { name: 'Check' }));
    const card = await screen.findByTestId('nonexistent-result');
    expect(card).toHaveTextContent(/does not exist on PyPI/);
    // The server's own reason, from the verdict's block_nonexistent hit.
    expect(card).toHaveTextContent(/possibly a hallucinated or mistyped name/);
  });

  it('shows other 404s as errors, not as a nonexistent package', async () => {
    const user = userEvent.setup();
    const mock = renderApp('/check');
    // EngineError::NotFound for a missing file or version, not a missing package.
    vi.spyOn(mock.server, 'handle').mockReturnValue({ status: 404, body: { error: 'not found upstream' } });
    await user.type(screen.getByRole('textbox', { name: 'Package name' }), 'requests');
    await user.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByText('The check failed')).toBeInTheDocument();
    expect(screen.getByText('not found upstream')).toBeInTheDocument();
    expect(screen.queryByTestId('nonexistent-result')).toBeNull();
  });

  it('accepts version ranges and tags the check as coming from the dashboard', async () => {
    const user = userEvent.setup();
    const mock = renderApp('/check');
    const handle = vi.spyOn(mock.server, 'handle');
    await user.type(screen.getByRole('textbox', { name: 'Package name' }), 'requests');
    await user.type(screen.getByRole('textbox', { name: /Version/ }), '>=1,<2');
    await user.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByTestId('verdict')).toBeInTheDocument();
    expect(screen.queryByText(/Not a valid version/)).toBeNull();
    const call = handle.mock.calls.find(([method, url]) => method === 'POST' && url.pathname === '/api/check');
    expect(call?.[2]).toMatchObject({ ecosystem: 'pypi', name: 'requests', version: '>=1,<2', client: 'dashboard' });
  });

  it('validates the package name before sending', async () => {
    const user = userEvent.setup();
    renderApp('/check');
    await user.type(screen.getByRole('textbox', { name: 'Package name' }), 'bad name!');
    await user.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByText(/Not a valid PyPI name/)).toBeInTheDocument();
  });
});

describe('Activity page', () => {
  it('shows the search from the URL when navigation changes it', async () => {
    const user = userEvent.setup();
    renderApp('/activity?q=reqeusts');
    const box = await screen.findByRole('searchbox', { name: 'Package name' });
    expect(box).toHaveValue('reqeusts');
    await user.click(screen.getAllByRole('link', { name: 'Activity' })[0] as HTMLElement);
    await waitFor(() => expect(box).toHaveValue(''));
    // The stale text must not be written back into the URL by the search debounce.
    await new Promise((r) => setTimeout(r, 400));
    expect(box).toHaveValue('');
  });

  it('keeps the page cursors across leaving and coming back', async () => {
    const user = userEvent.setup();
    const mock = renderApp('/activity');
    const handle = vi.spyOn(mock.server, 'handle');
    const cursors = () =>
      handle.mock.calls
        // The Activity page asks for 25 at a time; the live feed's own requests ask for 50.
        .filter(([, url]) => url.pathname === '/api/events' && url.searchParams.get('limit') === '25')
        .map(([, url]) => url.searchParams.get('before'));
    const older = await screen.findByRole('button', { name: /Older/ });
    await waitFor(() => expect(older).toBeEnabled());
    await user.click(older);
    await waitFor(() => expect(older).toBeEnabled());
    await user.click(older);
    await waitFor(() => expect(older).toBeEnabled());
    const [first, second] = cursors().filter((c) => c !== null);
    expect(first).toBeTruthy();
    expect(second).toBeTruthy();
    // Open a verdict from the third page and come back with the verdict page's Back button.
    const row = screen.getAllByRole('link').find((a) => a.getAttribute('href')?.startsWith('/verdicts/'));
    await user.click(row as HTMLElement);
    await user.click(await screen.findByRole('button', { name: 'Back' }));
    await waitFor(() => expect(screen.getByRole('button', { name: /Newer/ })).toBeEnabled());
    expect(cursors().at(-1)).toBe(second);
    await user.click(screen.getByRole('button', { name: /Newer/ }));
    await waitFor(() => expect(cursors().at(-1)).toBe(first));
  });
});

describe('Verdict page', () => {
  it('treats a non-numeric id as a missing verdict without asking the server', async () => {
    const mock = renderApp('/verdicts/abc');
    const handle = vi.spyOn(mock.server, 'handle');
    expect(await screen.findByText('Verdict not found')).toBeInTheDocument();
    expect(screen.queryByText('Could not load this verdict')).toBeNull();
    expect(handle.mock.calls.some(([, url]) => url.pathname.startsWith('/api/verdicts/'))).toBe(false);
  });

  it('goes to Activity on Back when the verdict was opened directly', async () => {
    // Other pages in this tab's history (outside the app) must not count as "back".
    window.history.pushState({}, '', '/elsewhere');
    const user = userEvent.setup();
    renderApp('/verdicts/41');
    await screen.findByTestId('verdict');
    await user.click(screen.getByRole('button', { name: 'Back' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Activity' })).toBeInTheDocument();
  });

  it('compares the release with the one before it on request', async () => {
    const user = userEvent.setup();
    renderApp('/verdicts/43');
    const card = await screen.findByRole('region', { name: 'Changes since an earlier release' });
    expect(within(card).queryByTestId('release-diff')).toBeNull();
    await user.click(within(card).getByRole('button', { name: 'Compare' }));
    const diff = await within(card).findByTestId('release-diff');
    expect(diff).toHaveTextContent('0.0.2');
    expect(diff).toHaveTextContent('publisher: maintainer -> new-account');
    expect(diff).toHaveTextContent('+ dotenv-lite ^0.1.0');
    expect(within(diff).getByRole('list', { name: 'Modified files' })).toHaveTextContent('index.js (+7 -1 lines)');
    expect(within(diff).getByRole('list', { name: 'Evidence' })).toHaveTextContent('telemetry.envloader.dev');

    await user.type(within(card).getByRole('textbox', { name: 'Earlier version' }), '0.0.3');
    await user.click(within(card).getByRole('button', { name: 'Compare' }));
    expect(await within(card).findByRole('alert')).toHaveTextContent('name two different versions');
    expect(within(card).queryByTestId('release-diff')).toBeNull();
  });
});

describe('Model page', () => {
  it("shows the model's own thresholds when the policy overrides them", async () => {
    const mock = renderApp('/model');
    mock.server.policy.block_threshold = 0.9;
    expect(await screen.findByTestId('model-version')).toBeInTheDocument();
    expect(screen.getByTestId('model-block-threshold')).toHaveTextContent('0.80');
  });

  it('names a temporal split and its cutoff without nesting it in the heading', async () => {
    renderApp('/model');
    expect(await screen.findByRole('heading', { name: 'Held-out evaluation (temporal split)' })).toBeInTheDocument();
    expect(screen.getByText(/Trained on packages first seen before a cutoff date/)).toHaveTextContent(
      'Test set: malware found from 2026-02-13.',
    );
  });
});

describe('Overview page', () => {
  it('renders tiles and adds live events to the feed', async () => {
    const mock = renderApp('/');
    expect(await screen.findByTestId('tile-total')).toBeInTheDocument();
    const feed = await screen.findByTestId('live-feed');
    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveAttribute('data-status', 'live'));
    const before = within(feed).getAllByTestId('feed-row')[0]?.getAttribute('data-event-id');
    let id = '';
    act(() => {
      id = String(mock.emitBlocked().id);
    });
    await waitFor(() => expect(within(screen.getByTestId('live-feed')).getAllByTestId('feed-row')[0]).toHaveAttribute('data-event-id', id));
    expect(id).not.toBe(before);
  });

  it('recovers the feed when the server comes up after the dashboard', async () => {
    const mock = renderApp('/');
    mock.server.events = [];
    const handle = mock.server.handle.bind(mock.server);
    let down = true;
    vi.spyOn(mock.server, 'handle').mockImplementation((method, url, body, headers) =>
      down && url.pathname === '/api/events' ? { status: 503, body: '' } : handle(method, url, body, headers),
    );
    mock.setStreamAvailable(false);
    expect(await screen.findByText('Could not load events')).toBeInTheDocument();
    down = false;
    mock.setStreamAvailable(true);
    expect(await screen.findByText('No installs yet', {}, { timeout: 8000 })).toBeInTheDocument();
  }, 10000);
});
