/**
 * In-process event bus for streaming scan progress to SSE listeners.
 *
 * One bus instance per Node process. Emitter routes by scanId so multiple
 * SSE clients can listen to the same scan, and the runner doesn't need to
 * know who's listening.
 */

import { EventEmitter } from "node:events";
import type { ScanEvent } from "../types";

class ScanBus extends EventEmitter {
  emitEvent(event: ScanEvent) {
    this.emit(event.scanId, event);
    this.emit("*", event);
  }

  subscribe(scanId: string, handler: (event: ScanEvent) => void): () => void {
    this.on(scanId, handler);
    return () => this.off(scanId, handler);
  }
}

// Use a global so dev mode hot-reload doesn't shred listeners between requests.
declare global {
  // eslint-disable-next-line no-var
  var __mobaScanBus: ScanBus | undefined;
}

export const scanBus: ScanBus = globalThis.__mobaScanBus ?? new ScanBus();
scanBus.setMaxListeners(64);
if (!globalThis.__mobaScanBus) globalThis.__mobaScanBus = scanBus;
