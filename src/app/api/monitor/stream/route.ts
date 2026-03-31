/**
 * SSE stream for real-time health probes and attack logs
 */

import { store } from '@/lib/store';

export const dynamic = 'force-dynamic';

export async function GET() {
  const stream = new ReadableStream({
    start(controller) {
      store.addSSEClient(controller);

      // Send initial state
      const encoder = new TextEncoder();
      try {
        const state = store.getFullState();
        controller.enqueue(encoder.encode(`event: init\ndata: ${JSON.stringify(state)}\n\n`));
      } catch {
        // ignore
      }
    },
    cancel(controller) {
      store.removeSSEClient(controller);
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}
