/**
 * Seth Process Pool — Otomatik ölçeklenen paralel işlem havuzu
 * Görevleri kuyruğa alır, worker thread'lerle paralel çalıştırır.
 */

import { EventEmitter } from 'events';

export interface Task<T = unknown> {
  id: string;
  fn: () => Promise<T>;
}

export interface TaskResult<T = unknown> {
  id: string;
  status: 'completed' | 'failed' | 'queued' | 'running';
  result?: T;
  error?: string;
  executionMs?: number;
}

export interface PoolStats {
  activeWorkers: number;
  queueSize: number;
  activeTasks: number;
  completed: number;
  failed: number;
  avgExecutionMs: number;
}

export class ProcessPool extends EventEmitter {
  private queue: Array<Task & { resolve: (r: TaskResult) => void }> = [];
  private results = new Map<string, TaskResult>();
  private activeCount = 0;
  private stats = { completed: 0, failed: 0, totalMs: 0 };

  constructor(
    private readonly maxConcurrent: number = 8,
  ) {
    super();
  }

  /** Görevi kuyruğa ekler, tamamlanınca sonucu döner */
  submit<T>(task: Task<T>): Promise<TaskResult<T>> {
    return new Promise(resolve => {
      this.results.set(task.id, { id: task.id, status: 'queued' });
      this.queue.push({ ...task, resolve: resolve as (r: TaskResult) => void });
      this.emit('queued', task.id);
      this.drain();
    });
  }

  /** Birden fazla görevi paralel çalıştırır */
  async submitAll<T>(tasks: Task<T>[]): Promise<TaskResult<T>[]> {
    return Promise.all(tasks.map(t => this.submit(t)));
  }

  /** Anlık sonucu döner (tamamlanmamış olabilir) */
  getResult(id: string): TaskResult | undefined {
    return this.results.get(id);
  }

  /** Havuz istatistiklerini döner */
  getStats(): PoolStats {
    return {
      activeWorkers: this.activeCount,
      queueSize: this.queue.length,
      activeTasks: this.activeCount,
      completed: this.stats.completed,
      failed: this.stats.failed,
      avgExecutionMs: this.stats.completed > 0
        ? Math.round(this.stats.totalMs / this.stats.completed)
        : 0,
    };
  }

  private drain(): void {
    while (this.activeCount < this.maxConcurrent && this.queue.length > 0) {
      const item = this.queue.shift()!;
      this.run(item);
    }
  }

  private async run(item: Task & { resolve: (r: TaskResult) => void }): Promise<void> {
    this.activeCount++;
    const start = Date.now();
    this.results.set(item.id, { id: item.id, status: 'running' });
    this.emit('started', item.id);

    try {
      const result = await item.fn();
      const executionMs = Date.now() - start;
      const taskResult: TaskResult = { id: item.id, status: 'completed', result, executionMs };
      this.results.set(item.id, taskResult);
      this.stats.completed++;
      this.stats.totalMs += executionMs;
      this.emit('completed', item.id, result);
      item.resolve(taskResult);
    } catch (err) {
      const executionMs = Date.now() - start;
      const error = err instanceof Error ? err.message : String(err);
      const taskResult: TaskResult = { id: item.id, status: 'failed', error, executionMs };
      this.results.set(item.id, taskResult);
      this.stats.failed++;
      this.emit('failed', item.id, error);
      item.resolve(taskResult);
    } finally {
      this.activeCount--;
      this.drain();
    }
  }
}

/** Basit LRU + TTL cache */
export class AdvancedCache<V = unknown> {
  private store = new Map<string, { value: V; expiresAt: number; accessedAt: number }>();

  constructor(
    private readonly maxSize: number = 500,
    private readonly defaultTtlMs: number = 30 * 60 * 1000, // 30 dakika
  ) {}

  get(key: string): V | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) { this.store.delete(key); return undefined; }
    entry.accessedAt = Date.now();
    return entry.value;
  }

  set(key: string, value: V, ttlMs?: number): void {
    if (this.store.size >= this.maxSize && !this.store.has(key)) this.evictLru();
    this.store.set(key, {
      value,
      expiresAt: Date.now() + (ttlMs ?? this.defaultTtlMs),
      accessedAt: Date.now(),
    });
  }

  delete(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }

  getStats() {
    return { size: this.store.size, maxSize: this.maxSize };
  }

  private evictLru(): void {
    let oldest = Infinity;
    let oldestKey = '';
    for (const [k, v] of this.store) {
      if (v.accessedAt < oldest) { oldest = v.accessedAt; oldestKey = k; }
    }
    if (oldestKey) this.store.delete(oldestKey);
  }
}

export const processPool = new ProcessPool(8);
export const cache = new AdvancedCache(500);
