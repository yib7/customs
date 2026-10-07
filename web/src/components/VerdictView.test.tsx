import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { parseVerdict } from '../api/parse';
import { BLOCKED_SCOPE_SQUAT, BLOCKED_TYPOSQUAT } from '../mock/fixtures';
import { VerdictView } from './VerdictView';

const RLO = String.fromCharCode(0x202e);

function renderVerdict(raw: unknown) {
  const v = parseVerdict(raw);
  return render(
    <MemoryRouter>
      <VerdictView verdict={v} thresholds={{ warn: 0.35, block: 0.8 }} />
    </MemoryRouter>,
  );
}

describe('VerdictView', () => {
  it('renders attacker-controlled snippets as text, never as HTML', () => {
    const { container } = renderVerdict({
      ...BLOCKED_SCOPE_SQUAT,
      name: '<img src=x onerror=alert(1)>',
      evidence: [
        { indicator: 'dyn_code', file: '<b>index.js</b>', line: 1, snippet: '<script>alert(1)</script><img src=x onerror=alert(2)>' },
      ],
    });
    // No element was created from the payloads.
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    // The payloads are visible as literal text.
    const snippet = screen.getByTestId('evidence-snippet');
    expect(snippet.textContent).toBe('<script>alert(1)</script><img src=x onerror=alert(2)>');
    expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('<img src=x onerror=alert(1)>');
    expect(screen.getByText(/<b>index\.js<\/b>:1/)).toBeInTheDocument();
  });

  it('reveals bidi control characters in evidence', () => {
    renderVerdict(BLOCKED_SCOPE_SQUAT);
    const items = screen.getAllByTestId('evidence-item');
    const trojan = items.find((el) => el.textContent?.includes('<U+202E>'));
    expect(trojan).toBeDefined();
    expect(trojan?.textContent).not.toContain(RLO);
    expect(within(trojan as HTMLElement).getByText(/invisible or bidirectional control characters/)).toBeInTheDocument();
  });

  it('shows decision, risk, component scores, reasons, and next steps', () => {
    renderVerdict(BLOCKED_TYPOSQUAT);
    expect(screen.getAllByText('Blocked').length).toBeGreaterThan(0);
    expect(screen.getByTestId('risk-value').textContent).toBe('99.3%');
    expect(screen.getByRole('img', { name: /Risk 99.3%, above the block threshold/ })).toBeInTheDocument();
    expect(screen.getByRole('meter', { name: 'Code model score' })).toHaveAttribute('aria-valuenow', '0.996');
    // Reasons with a null label fall back to the feature label.
    expect(screen.getByText('Contacts a known exfiltration endpoint (webhooks, paste sites) at install time')).toBeInTheDocument();
    expect(screen.getByText('+1.84')).toBeInTheDocument();
    expect(screen.getByText('Version is newer than the minimum age')).toBeInTheDocument();
    expect(screen.getByText('customs check pypi:reqeusts@2.32.4')).toBeInTheDocument();
    expect(screen.getByText('allow = ["pypi:reqeusts@2.32.4"]')).toBeInTheDocument();
    const link = screen.getByRole('link', { name: /View on PyPI/ });
    expect(link).toHaveAttribute('href', 'https://pypi.org/project/reqeusts/');
    expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
    expect(screen.getByTestId('sha-short').textContent).toHaveLength(12);
  });

  it('does not link to the registry for invalid names', () => {
    renderVerdict({ ...BLOCKED_TYPOSQUAT, name: 'javascript:alert(1)' });
    expect(screen.queryByRole('link', { name: /View on PyPI/ })).toBeNull();
  });
});
