export function durationToMs(duration: string): number {
    const normalized = duration.trim().toLowerCase();
    const match = normalized.match(/^(\d+)(ms|s|m|h|d)$/);

    if (!match) {
        throw new Error(
            `Invalid duration format: "${duration}". Use one of: 500ms, 30s, 15m, 24h, 7d`,
        );
    }

    const value = Number(match[1]);
    const unit = match[2];

    const multipliers: Record<string, number> = {
        ms: 1,
        s: 1000,
        m: 60 * 1000,
        h: 60 * 60 * 1000,
        d: 24 * 60 * 60 * 1000,
    };

    return value * multipliers[unit];
}
