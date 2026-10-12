import type { Thresholds } from '../api/types';
import { formatPercent } from '../lib/format';

const W = 320;
const H = 146;
const CX = W / 2;
const CY = 126;
const R = 88;
const STROKE = 14;
// Thin outer band showing the allow / warn / block zones.
const BAND_R = R + STROKE / 2 + 7;
const BAND_W = 5;
// Room beside the arc for a threshold label near either end ("block 0.99").
const PAD_X = 28;

function point(p: number, r: number = R): [number, number] {
  const theta = Math.PI * (1 - Math.min(1, Math.max(0, p)));
  return [CX + r * Math.cos(theta), CY - r * Math.sin(theta)];
}

function arc(from: number, to: number, r: number = R): string {
  const [x1, y1] = point(from, r);
  const [x2, y2] = point(to, r);
  return `M${x1.toFixed(2)},${y1.toFixed(2)} A${r},${r} 0 0 1 ${x2.toFixed(2)},${y2.toFixed(2)}`;
}

function zoneFor(risk: number, t: Thresholds | null): 'allow' | 'warn' | 'block' | null {
  if (!t) return null;
  if (risk >= t.block) return 'block';
  if (risk >= t.warn) return 'warn';
  return 'allow';
}

const ZONE_TEXT = {
  block: 'above the block threshold',
  warn: 'between the warn and block thresholds',
  allow: 'below the warn threshold',
} as const;

export function RiskGauge({ risk, thresholds }: { risk: number | null; thresholds: Thresholds | null }) {
  if (risk === null) {
    return (
      <div className="flex h-[146px] flex-col items-center justify-center text-center" role="img" aria-label="No risk score: no archive was scanned">
        <p className="text-sm font-medium text-ink">No risk score</p>
        <p className="mt-1 text-xs text-muted">No archive was scanned for this attempt.</p>
      </div>
    );
  }
  const zone = zoneFor(risk, thresholds);
  const label = `Risk ${formatPercent(risk)}, ${zone ? ZONE_TEXT[zone] : 'thresholds unavailable'}.${
    thresholds ? ` Warn at ${formatPercent(thresholds.warn)}, block at ${formatPercent(thresholds.block)}.` : ''
  }`;
  const [nx, ny] = point(risk, R - STROKE / 2 - 8);
  const zoneColor = zone ? `var(--c-${zone})` : 'var(--c-ink-2)';

  return (
    <figure className="flex flex-col items-center" data-testid="risk-gauge">
      <svg
        viewBox={`${-PAD_X} 0 ${W + 2 * PAD_X} ${H}`}
        width="100%"
        style={{ maxWidth: Math.round((340 * (W + 2 * PAD_X)) / W) }}
        role="img"
        aria-label={label}
      >
        <path d={arc(0, 1)} stroke="var(--c-surface-3)" strokeWidth={STROKE} fill="none" />
        <path d={arc(0, Math.max(0.002, risk))} stroke={zoneColor} strokeWidth={STROKE} fill="none" />
        {thresholds ? (
          <>
            <path d={arc(0, thresholds.warn, BAND_R)} stroke="var(--c-allow)" strokeWidth={BAND_W} fill="none" />
            <path d={arc(thresholds.warn, thresholds.block, BAND_R)} stroke="var(--c-warn)" strokeWidth={BAND_W} fill="none" />
            <path d={arc(thresholds.block, 1, BAND_R)} stroke="var(--c-block)" strokeWidth={BAND_W} fill="none" />
            {(
              [
                ['warn', thresholds.warn],
                ['block', thresholds.block],
              ] as const
            ).map(([name, t]) => {
              const [x1, y1] = point(t, R - STROKE / 2 - 3);
              const [x2, y2] = point(t, BAND_R + BAND_W / 2 + 3);
              const [lx, ly] = point(t, BAND_R + 15);
              return (
                <g key={name}>
                  <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--c-surface)" strokeWidth={5} />
                  <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--c-ink)" strokeWidth={2} strokeLinecap="round" />
                  <text
                    x={lx}
                    y={ly}
                    fontSize={10.5}
                    fill="var(--c-ink-2)"
                    textAnchor={t < 0.45 ? 'end' : t > 0.55 ? 'start' : 'middle'}
                    dominantBaseline="middle"
                  >
                    {name} {t.toFixed(2)}
                  </text>
                </g>
              );
            })}
          </>
        ) : null}
        <line x1={CX} y1={CY} x2={nx} y2={ny} stroke="var(--c-ink)" strokeWidth={2.5} strokeLinecap="round" />
        <circle cx={CX} cy={CY} r={5} fill="var(--c-ink)" stroke="var(--c-surface)" strokeWidth={2} />
        <text x={CX - R} y={CY + 16} fontSize={10} fill="var(--c-muted)" textAnchor="middle">
          0
        </text>
        <text x={CX + R} y={CY + 16} fontSize={10} fill="var(--c-muted)" textAnchor="middle">
          1
        </text>
      </svg>
      <figcaption className="mt-1 text-center">
        <span className="block text-3xl font-semibold tracking-tight text-ink" data-testid="risk-value">
          {formatPercent(risk)}
        </span>
        <span className="block text-xs text-muted">calibrated probability of malware ({risk.toFixed(3)})</span>
      </figcaption>
    </figure>
  );
}
