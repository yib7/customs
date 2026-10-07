import type { Decision } from '../api/types';
import { IconAllow, IconBlock, IconWarn } from './Icons';

/** Decision presentation: every decision pairs a color with a distinct icon shape and a label. */
export const DECISION_META: Record<Decision, { label: string; Icon: typeof IconAllow; cls: string; swatch: string }> = {
  allow: { label: 'Allowed', Icon: IconAllow, cls: 'bg-allow-soft text-allow-ink', swatch: 'var(--c-allow)' },
  warn: { label: 'Warned', Icon: IconWarn, cls: 'bg-warn-soft text-warn-ink', swatch: 'var(--c-warn)' },
  block: { label: 'Blocked', Icon: IconBlock, cls: 'bg-block-soft text-block-ink', swatch: 'var(--c-block)' },
};
