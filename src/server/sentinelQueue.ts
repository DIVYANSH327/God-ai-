import {
  deduplicateNormalizedEvents,
  normalizeSentinelEvent,
  type AgentProvenanceContext,
  type RawSentinelEventInput,
} from '../shared/sentinelAnalytics.ts';
import type { SentinelEventRecord, SentinelQueueMetrics } from '../shared/sentinelTypes.ts';
import { persistNormalizedSentinelEvents } from '../db/sentinelRepository.ts';

interface QueuedBatchItem {
  userId: string;
  agent: AgentProvenanceContext;
  rawEvents: RawSentinelEventInput[];
  resolve: (result: { persisted: SentinelEventRecord[]; deduplicatedCount: number }) => void;
  reject: (err: Error) => void;
}

const MAX_QUEUE_DEPTH = 500;

/**
 * Scalable bounded event ingestion pipeline for GOD Sentinel telemetry.
 * Normalizes, scrubs secrets, deduplicates repeated fingerprints, stamps provenance,
 * and flushes in ordered batches to PostgreSQL while tracking queue telemetry.
 */
class SentinelEventQueue {
  private queue: QueuedBatchItem[] = [];
  private processing = false;
  private totalReceived = 0;
  private totalDeduplicated = 0;
  private totalPersisted = 0;
  private deadLetterCount = 0;

  public getMetrics(): SentinelQueueMetrics {
    return {
      pendingDepth: this.queue.length,
      totalReceived: this.totalReceived,
      totalDeduplicated: this.totalDeduplicated,
      totalPersisted: this.totalPersisted,
      deadLetterCount: this.deadLetterCount,
    };
  }

  public enqueueBatch(
    userId: string,
    agent: AgentProvenanceContext,
    rawEvents: RawSentinelEventInput[]
  ): Promise<{ persisted: SentinelEventRecord[]; deduplicatedCount: number }> {
    const boundedBatch = rawEvents.slice(0, 200);
    this.totalReceived += boundedBatch.length;

    if (this.queue.length >= MAX_QUEUE_DEPTH) {
      this.deadLetterCount += boundedBatch.length;
      return Promise.reject(
        new Error('Event ingestion queue capacity reached; agent should retain offline buffer and retry.')
      );
    }

    return new Promise((resolve, reject) => {
      this.queue.push({ userId, agent, rawEvents: boundedBatch, resolve, reject });
      void this.drain();
    });
  }

  private async drain(): Promise<void> {
    if (this.processing) return;
    this.processing = true;

    try {
      while (this.queue.length > 0) {
        const item = this.queue.shift()!;
        try {
          const nowIso = new Date().toISOString();
          const normalized = item.rawEvents.map((raw) =>
            normalizeSentinelEvent(raw, item.agent, nowIso)
          );
          const { deduplicated, collapsedCount } = deduplicateNormalizedEvents(normalized);
          const { persisted, deduplicatedInDb } = await persistNormalizedSentinelEvents(
            item.userId,
            deduplicated
          );

          const totalDedup = collapsedCount + deduplicatedInDb;
          this.totalDeduplicated += totalDedup;
          this.totalPersisted += persisted.length;
          item.resolve({ persisted, deduplicatedCount: totalDedup });
        } catch (err) {
          this.deadLetterCount += item.rawEvents.length;
          item.reject(
            err instanceof Error
              ? err
              : new Error('Sentinel event queue batch persistence failed.')
          );
        }
      }
    } finally {
      this.processing = false;
    }
  }
}

export const sentinelEventQueue = new SentinelEventQueue();
