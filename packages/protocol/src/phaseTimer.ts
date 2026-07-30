export class PhaseTimer {
  private readonly startedAt = Date.now();
  private readonly phases: Record<string, number> = {};

  async time<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const start = Date.now();
    try {
      return await fn();
    } finally {
      this.phases[name] = Math.max(0, Date.now() - start);
    }
  }

  timeSync<T>(name: string, fn: () => T): T {
    const start = Date.now();
    try {
      return fn();
    } finally {
      this.phases[name] = Math.max(0, Date.now() - start);
    }
  }

  totalMs(): number {
    return Math.max(0, Date.now() - this.startedAt);
  }

  snapshot(): Record<string, number> {
    return { ...this.phases };
  }
}
