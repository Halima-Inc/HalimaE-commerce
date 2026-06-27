import { Inject, Injectable } from '@nestjs/common';
import type { PaymentEvent } from '../../application/events';
import type { IPaymentEventPublisher } from '../../application/services';
import type { IDashboardPaymentEventConsumer } from '../../../dashboard/application/services';
import { DASHBOARD_PAYMENT_EVENT_CONSUMER } from '../../../dashboard/dashboard.tokens';
import { InMemoryPaymentEventPublisher } from './in-memory-payment-event.publisher';

@Injectable()
export class CompositePaymentEventPublisher implements IPaymentEventPublisher {
    constructor(
        private readonly inMemoryPublisher: InMemoryPaymentEventPublisher,
        @Inject(DASHBOARD_PAYMENT_EVENT_CONSUMER)
        private readonly dashboardConsumer: IDashboardPaymentEventConsumer,
    ) {}

    async publish(event: PaymentEvent): Promise<void> {
        await this.inMemoryPublisher.publish(event);
        await this.dashboardConsumer.consume(event);
    }
}
