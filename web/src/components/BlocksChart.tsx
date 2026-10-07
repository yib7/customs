import { useState } from 'react';
import type { DayCount } from '../api/types';
import { formatCount, formatDay } from '../lib/format';
import { useWidth } from '../lib/hooks';

const HEIGHT = 190;
const PAD = { top: 22, right: 8, bottom: 26, left: 32 };

function niceMax(v: number): number {
  if (v <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (m * pow >= v) return m * pow;
  }
  return 10 * pow;
}

/** Column with a 4px rounded data end and a square baseline. */
function columnPath(x: number, y: number, w: number, h: number): string {
  const r = Math.min(4, h, w / 2);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

export function BlocksChart({ data }: { data: DayCount[] }) {
  const [ref, width] = useWidth<HTMLDivElement>(560);
  const [active, setActive] = useState<number | null>(null);
  const total = data.reduce((s, d) => s + d.count, 0);
  const max = niceMax(Math.max(0, ...data.map((d) => d.count)));
  const innerW = Math.max(10, width - PAD.left - PAD.right);
  const innerH = HEIGHT - PAD.top - PAD.bottom;
  const band = data.length > 0 ? innerW / data.length : innerW;
  const barW = Math.max(3, Math.min(24, band * 0.62));
  const y = (v: number) => PAD.top + innerH - (v / max) * innerH;
  const ticks = [0, max / 2, max].filter((t, i, a) => Number.isInteger(t) && a.indexOf(t) === i);
  const peakIdx = data.reduce((best, d, i) => (d.count > (data[best]?.count ?? -1) ? i : best), 0);
  const labelEvery = band < 46 ? Math.ceil(46 / band) : 1;
  const activeDay = active !== null ? data[active] : undefined;

  const summary =
    data.length === 0
      ? 'No data'
      : `Blocked installs per day from ${formatDay(data[0]?.date ?? '')} to ${formatDay(data[data.length - 1]?.date ?? '')}: ${formatCount(total)} in total, peak of ${data[peakIdx]?.count ?? 0} on ${formatDay(data[peakIdx]?.date ?? '')}.`;

  return (
    <div>
      <div
        ref={ref}
        className="relative"
        role="group"
        aria-label={`${summary} Use the left and right arrow keys to read each day.`}
        tabIndex={0}
        onKeyDown={(e) => {
          if (data.length === 0) return;
          if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
            e.preventDefault();
            const cur = active ?? (e.key === 'ArrowRight' ? -1 : data.length);
            const next = Math.min(data.length - 1, Math.max(0, cur + (e.key === 'ArrowRight' ? 1 : -1)));
            setActive(next);
          } else if (e.key === 'Escape') {
            setActive(null);
          }
        }}
        onBlur={() => setActive(null)}
        onMouseLeave={() => setActive(null)}
      >
        <svg width={width} height={HEIGHT} aria-hidden="true" className="block overflow-visible">
          {ticks.map((t) => (
            <g key={t}>
              <line x1={PAD.left} x2={PAD.left + innerW} y1={y(t)} y2={y(t)} stroke={t === 0 ? 'var(--c-axis)' : 'var(--c-grid)'} strokeWidth={1} />
              <text x={PAD.left - 8} y={y(t)} dy="0.32em" textAnchor="end" fontSize={11} fill="var(--c-muted)" className="tabular">
                {formatCount(t)}
              </text>
            </g>
          ))}
          {data.map((d, i) => {
            const cx = PAD.left + band * i + band / 2;
            const h = (d.count / max) * innerH;
            const isActive = active === i;
            return (
              <g key={d.date}>
                {isActive ? (
                  <rect x={PAD.left + band * i} y={PAD.top} width={band} height={innerH} fill="var(--c-surface-3)" opacity={0.6} />
                ) : null}
                {d.count > 0 ? (
                  <path d={columnPath(cx - barW / 2, y(d.count), barW, h)} fill="var(--c-block)" opacity={active === null || isActive ? 1 : 0.55} />
                ) : null}
                {i === peakIdx && d.count > 0 ? (
                  <text x={cx} y={y(d.count) - 6} textAnchor="middle" fontSize={11} fontWeight={600} fill="var(--c-ink-2)" className="tabular">
                    {d.count}
                  </text>
                ) : null}
                {(data.length - 1 - i) % labelEvery === 0 ? (
                  <text x={cx} y={HEIGHT - 8} textAnchor="middle" fontSize={11} fill="var(--c-muted)">
                    {formatDay(d.date)}
                  </text>
                ) : null}
                <rect
                  x={PAD.left + band * i}
                  y={PAD.top}
                  width={band}
                  height={innerH}
                  fill="transparent"
                  onMouseEnter={() => setActive(i)}
                />
              </g>
            );
          })}
        </svg>
        {activeDay && active !== null ? (
          <div
            className="pointer-events-none absolute z-10 -translate-x-1/2 rounded-md border border-line bg-surface px-2.5 py-1.5 text-xs whitespace-nowrap shadow-lg"
            style={{
              left: Math.min(Math.max(PAD.left + band * active + band / 2, 60), width - 60),
              top: Math.max(0, y(activeDay.count) - 44),
            }}
          >
            <div className="font-medium text-ink">{formatDay(activeDay.date)}</div>
            <div className="flex items-center gap-1.5 text-ink-2">
              <span className="inline-block h-2 w-2 rounded-sm" style={{ background: 'var(--c-block)' }} />
              <span className="tabular">{activeDay.count}</span> blocked
            </div>
          </div>
        ) : null}
        <div className="sr-only" aria-live="polite">
          {activeDay ? `${formatDay(activeDay.date)}: ${activeDay.count} blocked` : ''}
        </div>
      </div>
      <table className="sr-only">
        <caption>Blocked installs per day</caption>
        <thead>
          <tr>
            <th scope="col">Day</th>
            <th scope="col">Blocked</th>
          </tr>
        </thead>
        <tbody>
          {data.map((d) => (
            <tr key={d.date}>
              <td>{d.date}</td>
              <td>{d.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
