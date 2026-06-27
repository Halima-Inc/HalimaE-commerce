import { Injectable } from '@nestjs/common';
import type { OrderEvent } from '../../../order/application/events';
import type { IDashboardOrderEventConsumer } from '../../application/services';
import { DashboardOrderEventConsumer } from './dashboard-order-event.consumer';
import { OrderProjector } from '../projectors/order.projector';

@Injectable()
export class CompositeDashboardOrderEventConsumer
    implements IDashboardOrderEventConsumer
{
    constructor(
        private readonly cacheConsumer: DashboardOrderEventConsumer,
        private readonly projector: OrderProjector,
    ) {}

    async consume(event: OrderEvent): Promise<void> {
        // run cache refresh and projector in parallel, but don't fail the whole chain
        await Promise.allSettled([
            this.cacheConsumer.consume(event),
            this.projector.consume(event),
        ]);
    }
}

export default CompositeDashboardOrderEventConsumer;
