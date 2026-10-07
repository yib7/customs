// Shape of the mock controls the mock-mode build exposes (see src/mock/index.ts).
export {};

interface MockEvent {
  id: number;
}

declare global {
  interface Window {
    __CUSTOMS_MOCK_NO_AUTO?: boolean;
    __customsMock?: {
      emit: () => MockEvent;
      emitBlocked: () => MockEvent;
      dropStream: () => void;
      setStreamAvailable: (ok: boolean) => void;
      server: { policy: Record<string, unknown> };
    };
  }
}
