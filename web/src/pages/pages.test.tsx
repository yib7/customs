import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup } from '@testing-library/react';
import { INITIAL_POLICY } from '../mock/fixtures';
import { renderApp } from '../test/render';

afterEach(() => {
  cleanup();
  if (window.__customsMock) window.__customsMock.server.policy = structuredClone(INITIAL_POLICY);
});

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
    const mock = window.__customsMock!.server;
    mock.adminToken = 'team-token-0123456789';
    try {
      const user = userEvent.setup();
      renderApp('/policy');
      const age = await screen.findByRole('textbox', { name: 'Minimum age (days)' });
      await user.clear(age);
      await user.type(age, '5');
      await user.click(screen.getByRole('button', { name: 'Save policy' }));
      expect(await screen.findByTestId('policy-server-error')).toHaveTextContent('The server refused the change');
      const token = screen.getByLabelText('Admin token');
      await user.type(token, 'wrong-token');
      await user.click(screen.getByRole('button', { name: 'Save policy' }));
      expect(await screen.findByText('the admin token is not valid')).toBeInTheDocument();
      expect(mock.policy).toMatchObject({ min_age_days: 3 });
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
      mock.adminToken = null;
      sessionStorage.clear();
    }
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
});

describe('Check page', () => {
  it('shows a verdict inline', async () => {
    const user = userEvent.setup();
    renderApp('/check');
    await user.type(screen.getByRole('textbox', { name: 'Package name' }), 'reqeusts');
    await user.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByTestId('verdict')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /reqeusts/ })).toBeInTheDocument();
  });

  it('explains nonexistent packages', async () => {
    const user = userEvent.setup();
    renderApp('/check');
    await user.type(screen.getByRole('textbox', { name: 'Package name' }), 'huggingface-cli');
    await user.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByTestId('nonexistent-result')).toHaveTextContent(/does not exist on PyPI/);
  });

  it('validates the package name before sending', async () => {
    const user = userEvent.setup();
    renderApp('/check');
    await user.type(screen.getByRole('textbox', { name: 'Package name' }), 'bad name!');
    await user.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByText(/Not a valid PyPI name/)).toBeInTheDocument();
  });
});

describe('Verdict page', () => {
  it('compares the release with the one before it on request', async () => {
    const user = userEvent.setup();
    renderApp('/verdicts/v_2b8e5f17');
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
});
