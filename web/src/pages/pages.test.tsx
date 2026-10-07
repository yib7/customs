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
