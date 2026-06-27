import { Cron } from '@nestjs/schedule';
import { Inject, Injectable } from '@nestjs/common';
import { LogService } from '../../../common/log.service';
import type { IOrderRepository } from '../../domain/interfaces';
import { ORDER_EVENT_PUBLISHER, ORDER_REPOSITORY } from '../../order.tokens';
import type { OrderEvent } from '../../application/events';
import type { IOrderEventPublisher } from '../../application/services';

@Injectable()
export class OrderOutboxDispatcherScheduler {
    private static readonly BATCH_SIZE = 50;
    private static readonly MAX_ATTEMPTS = 5;

    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
        @Inject(ORDER_EVENT_PUBLISHER)
        private readonly eventPublisher: IOrderEventPublisher,
        private readonly logger: LogService,
    ) {}

    @Cron('*/30 * * * * *', { name: 'order-outbox-dispatcher' })
    async dispatchPendingEvents(): Promise<void> {
        const pendingEvents =
            await this.orderRepository.fetchPendingOutboxEvents?.(
                OrderOutboxDispatcherScheduler.BATCH_SIZE,
            );

        if (!pendingEvents || pendingEvents.length === 0) {
            return;
        }

        for (const outboxEvent of pendingEvents) {
            const claimed = await this.orderRepository.claimOutboxEvent?.(
                outboxEvent.id,
            );

            if (!claimed) {
                continue;
            }

            try {
                const event: OrderEvent = {
                    eventName: outboxEvent.eventName as OrderEvent['eventName'],
                    eventId: outboxEvent.eventId,
                    version: outboxEvent.version,
                    occurredAt: outboxEvent.occurredAt.toISOString(),
                    aggregateId: outboxEvent.aggregateId,
                    idempotencyKey: outboxEvent.idempotencyKey,
                    payload: outboxEvent.payload,
                };

                await this.eventPublisher.publish(event);
                await this.orderRepository.markOutboxEventPublished?.(
                    outboxEvent.id,
                );
            } catch (error) {
                const attempts = outboxEvent.attempts + 1;
                const deadLetter =
                    attempts >= OrderOutboxDispatcherScheduler.MAX_ATTEMPTS;
                const nextAttemptAt = this.computeNextAttemptAt(attempts);

                await this.orderRepository.markOutboxEventFailed?.(
                    outboxEvent.id,
                    attempts,
                    this.toErrorMessage(error),
                    nextAttemptAt,
                    deadLetter,
                );

                this.logger.error(
                    deadLetter
                        ? `Outbox event ${outboxEvent.eventId} moved to dead-letter after ${attempts} attempts`
                        : `Outbox event ${outboxEvent.eventId} publish failed on attempt ${attempts}`,
                    error instanceof Error ? error.stack : undefined,
                    OrderOutboxDispatcherScheduler.name,
                );
            }
        }
    }

    private computeNextAttemptAt(attempts: number): Date {
        const delaySeconds = Math.min(15 * 2 ** (attempts - 1), 15 * 60);
        return new Date(Date.now() + delaySeconds * 1000);
    }

    private toErrorMessage(error: unknown): string {
        if (error instanceof Error) {
            return error.message.slice(0, 1000);
        }

        return 'Unknown outbox publish error';
    }
}
