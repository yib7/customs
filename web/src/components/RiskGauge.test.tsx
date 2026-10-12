import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RiskGauge } from './RiskGauge';

// jsdom has no text metrics, so this bounds the label by its length: the 10.5px system
// sans-serif averages under 6.5px a character for these strings.
const CHAR_W = 6.5;

describe('RiskGauge', () => {
  it('keeps the threshold labels inside the drawing at the ends of the scale', () => {
    render(<RiskGauge risk={0.25} thresholds={{ warn: 0.01, block: 0.99 }} />);
    const svg = screen.getByRole('img');
    const [minX = 0, , width = 0] = (svg.getAttribute('viewBox') ?? '').split(/\s+/).map(Number);
    const maxX = minX + width;
    for (const text of svg.querySelectorAll('text')) {
      const label = text.textContent ?? '';
      if (!/^(warn|block) /.test(label)) continue;
      const x = Number(text.getAttribute('x'));
      const w = label.length * CHAR_W;
      const anchor = text.getAttribute('text-anchor');
      const [left, right] = anchor === 'end' ? [x - w, x] : anchor === 'start' ? [x, x + w] : [x - w / 2, x + w / 2];
      expect(left, label).toBeGreaterThanOrEqual(minX);
      expect(right, label).toBeLessThanOrEqual(maxX);
    }
  });
});
