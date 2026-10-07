import type { ConnectionStatus } from '../api/stream';

const META: Record<ConnectionStatus, { label: string; help: string; color: string; shape: 'dot' | 'ring' | 'square' | 'cross' | 'half' }> = {
  live: { label: 'Live', help: 'Receiving events in real time over a stream.', color: 'var(--c-accent)', shape: 'dot' },
  connecting: { label: 'Connecting', help: 'Opening the live event stream.', color: 'var(--c-muted)', shape: 'ring' },
  reconnecting: { label: 'Reconnecting', help: 'The live stream dropped. Retrying with backoff.', color: 'var(--c-warn)', shape: 'half' },
  polling: { label: 'Polling', help: 'Live stream unavailable. Checking for new events every few seconds.', color: 'var(--c-allow)', shape: 'square' },
  offline: { label: 'Offline', help: 'Cannot reach the Customs server. Retrying.', color: 'var(--c-block)', shape: 'cross' },
};

function Shape({ shape, color }: { shape: (typeof META)[ConnectionStatus]['shape']; color: string }) {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" className={shape === 'dot' ? 'pulse' : undefined}>
      {shape === 'dot' && <circle cx="5" cy="5" r="4" fill={color} />}
      {shape === 'ring' && <circle cx="5" cy="5" r="3.5" fill="none" stroke={color} strokeWidth="1.6" />}
      {shape === 'half' && (
        <>
          <circle cx="5" cy="5" r="3.6" fill="none" stroke={color} strokeWidth="1.4" />
          <path d="M5 1.4a3.6 3.6 0 0 1 0 7.2z" fill={color} />
        </>
      )}
      {shape === 'square' && <rect x="1.5" y="1.5" width="7" height="7" rx="1.5" fill={color} />}
      {shape === 'cross' && <path d="M2 2l6 6M8 2l-6 6" stroke={color} strokeWidth="2" strokeLinecap="round" />}
    </svg>
  );
}

export function ConnectionIndicator({ status }: { status: ConnectionStatus }) {
  const m = META[status];
  return (
    <div
      className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 text-xs font-medium text-ink-2"
      title={m.help}
      data-testid="connection-status"
      data-status={status}
    >
      <Shape shape={m.shape} color={m.color} />
      <span>
        <span className="sr-only">Event feed connection: </span>
        {m.label}
      </span>
    </div>
  );
}
