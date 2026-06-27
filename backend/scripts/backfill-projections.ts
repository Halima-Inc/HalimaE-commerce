#!/usr/bin/env ts-node
/*
  Backfill projections from historical OutboxEvent rows.

  Usage (dry-run, default):
    npx ts-node scripts/backfill-projections.ts --batch-size 200 --since 2025-01-01

  To actually apply changes to projection tables:
    npx ts-node scripts/backfill-projections.ts --apply --batch-size 500

*/
import { PrismaClient } from '@prisma/client';

function parseArgs(): Record<string, string | boolean> {
    const raw = process.argv.slice(2);
    const out: Record<string, string | boolean> = {};
    for (let i = 0; i < raw.length; i++) {
        const a = raw[i];
        if (!a.startsWith('--')) continue;
        const key = a.slice(2);
        const next = raw[i + 1];
        if (next && !next.startsWith('--')) {
            out[key] = next;
            i++;
        } else {
            out[key] = true;
        }
    }
    return out;
}

async function main() {
    const args = parseArgs();
    const apply = Boolean(args['apply']);
    const batchSize = Number(args['batch-size'] ?? args['batchSize'] ?? 500);
    const since = args['since'] ? new Date(String(args['since'])) : undefined;

    console.log(`Backfill projections — ${apply ? 'APPLY' : 'DRY-RUN'} mode`);
    console.log(`Batch size: ${batchSize}`);
    if (since) console.log(`Since: ${since.toISOString()}`);

    const prisma = new PrismaClient();

    // Import projectors and repository implementation dynamically to reuse existing logic
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { PrismaProjectionRepository } = require('../src/dashboard/infrastructure/repositories/prisma-projection.repository');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { OrderProjector } = require('../src/dashboard/infrastructure/projectors/order.projector');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { PaymentProjector } = require('../src/dashboard/infrastructure/projectors/payment.projector');

    const repo = new PrismaProjectionRepository(prisma as any);
    const orderProjector = new OrderProjector(repo as any);
    const paymentProjector = new PaymentProjector(repo as any);

    const orderEvents = ['OrderCreated', 'OrderCancelled', 'OrderStatusUpdated'];
    const paymentEvents = ['PaymentCaptured'];
    const allEvents = [...orderEvents, ...paymentEvents];

    let offset = 0;
    let processed = 0;
    while (true) {
        const where: any = { eventName: { in: allEvents } };
        if (since) where.occurredAt = { gte: since };

        const rows = await prisma.outboxEvent.findMany({
            where,
            orderBy: { occurredAt: 'asc' },
            skip: offset,
            take: batchSize,
        });

        if (!rows.length) break;

        console.log(`Fetched ${rows.length} events (offset ${offset})`);

        for (const r of rows) {
            const event = {
                eventName: r.eventName,
                eventId: r.eventId,
                version: r.version,
                occurredAt: r.occurredAt instanceof Date ? r.occurredAt.toISOString() : r.occurredAt,
                aggregateId: r.aggregateId,
                providerRef: r.providerRef,
                idempotencyKey: r.idempotencyKey,
                payload: r.payload,
            };

            processed++;
            try {
                if (!apply) {
                    console.log(`[DRY] would process ${event.eventName} ${event.eventId}`);
                    continue;
                }

                if (orderEvents.includes(event.eventName)) {
                    // projector handles idempotency at repo level
                    // eslint-disable-next-line @typescript-eslint/no-await-in-loop
                    await orderProjector.consume(event);
                }

                if (paymentEvents.includes(event.eventName)) {
                    // eslint-disable-next-line @typescript-eslint/no-await-in-loop
                    await paymentProjector.consume(event);
                }

                if (processed % 100 === 0) console.log(`Applied ${processed} events so far`);
            } catch (err) {
                console.error(`Error processing event ${event.eventId} (${event.eventName}):`, err);
            }
        }

        offset += rows.length;
    }

    console.log(`Done — processed ${processed} events (apply=${apply})`);
    await prisma.$disconnect();
}

main().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('Backfill failed:', err);
    process.exit(1);
});
