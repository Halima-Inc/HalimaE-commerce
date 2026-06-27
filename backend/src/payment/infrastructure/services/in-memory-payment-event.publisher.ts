import { Injectable } from '@nestjs/common';
import { LogService } from '../../../common/log.service';
import type { PaymentEvent } from '../../application/events';
import type { IPaymentEventPublisher } from '../../application/services';

@Injectable()
export class InMemoryPaymentEventPublisher implements IPaymentEventPublisher {
    private readonly subscribers: ((event: PaymentEvent) => Promise<void>)[] =
        [];

    constructor(private readonly logger: LogService) {}

    subscribe(callback: (event: PaymentEvent) => Promise<void>): void {
        this.subscribers.push(callback);
    }

    async publish(event: PaymentEvent): Promise<void> {
        this.logger.debug(
            `Payment event published: ${event.eventName} (${event.eventId})`,
            InMemoryPaymentEventPublisher.name,
        );

        for (const sub of this.subscribers) {
            await sub(event).catch((err) => {
                this.logger.error(
                    `Error in payment event subscriber: ${err.message}`,
                    err instanceof Error ? err.stack : undefined,
                    InMemoryPaymentEventPublisher.name,
                );
            });
        }
    }
}
