import { Cron } from '@nestjs/schedule';
import { Inject, Injectable } from '@nestjs/common';
import { LogService } from '../../../common/log.service';
import type { IPaymentRepository } from '../../domain/interfaces';
import {
    PAYMENT_EVENT_PUBLISHER,
    PAYMENT_REPOSITORY,
} from '../../payment.tokens';
import type { PaymentEvent } from '../../application/events';
import type { IPaymentEventPublisher } from '../../application/services';

@Injectable()
export class OutboxDispatcherScheduler {
    private static readonly BATCH_SIZE = 50;
    private static readonly MAX_ATTEMPTS = 5;

    constructor(
        @Inject(PAYMENT_REPOSITORY)
        private readonly paymentRepository: IPaymentRepository,
        @Inject(PAYMENT_EVENT_PUBLISHER)
        private readonly eventPublisher: IPaymentEventPublisher,
        private readonly logger: LogService,
    ) {}

    @Cron('*/30 * * * * *', { name: 'payment-outbox-dispatcher' })
    async dispatchPendingEvents(): Promise<void> {
        const pendingEvents =
            await this.paymentRepository.fetchPendingOutboxEvents(
                OutboxDispatcherScheduler.BATCH_SIZE,
            );

        for (const outboxEvent of pendingEvents) {
            const claimed = await this.paymentRepository.claimOutboxEvent(
                outboxEvent.id,
            );

            if (!claimed) {
                continue;
            }

            try {
                const event: PaymentEvent = {
                    eventName:
                        outboxEvent.eventName as PaymentEvent['eventName'],
                    eventId: outboxEvent.eventId,
                    version: outboxEvent.version,
                    occurredAt: outboxEvent.occurredAt.toISOString(),
                    aggregateId: outboxEvent.aggregateId,
                    providerRef: outboxEvent.providerRef,
                    idempotencyKey: outboxEvent.idempotencyKey,
                    payload: outboxEvent.payload,
                };

                await this.eventPublisher.publish(event);
                await this.paymentRepository.markOutboxEventPublished(
                    outboxEvent.id,
                );
            } catch (error) {
                const attempts = outboxEvent.attempts + 1;
                const deadLetter =
                    attempts >= OutboxDispatcherScheduler.MAX_ATTEMPTS;
                const nextAttemptAt = this.computeNextAttemptAt(attempts);

                await this.paymentRepository.markOutboxEventFailed(
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
                    OutboxDispatcherScheduler.name,
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
