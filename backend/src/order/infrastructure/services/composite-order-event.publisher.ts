import { Inject, Injectable } from '@nestjs/common';
import type { OrderEvent } from '../../application/events';
import type { IOrderEventPublisher } from '../../application/services';
import type { IDashboardOrderEventConsumer } from '../../../dashboard/application/services';
import { DASHBOARD_ORDER_EVENT_CONSUMER } from '../../../dashboard/dashboard.tokens';
import { InMemoryOrderEventPublisher } from './in-memory-order-event.publisher';

@Injectable()
export class CompositeOrderEventPublisher implements IOrderEventPublisher {
    constructor(
        private readonly inMemoryPublisher: InMemoryOrderEventPublisher,
        @Inject(DASHBOARD_ORDER_EVENT_CONSUMER)
        private readonly dashboardConsumer: IDashboardOrderEventConsumer,
    ) {}

    async publish(event: OrderEvent): Promise<void> {
        await this.inMemoryPublisher.publish(event);
        await this.dashboardConsumer.consume(event);
    }
}
