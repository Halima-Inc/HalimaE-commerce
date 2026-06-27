import { Injectable } from '@nestjs/common';
import type { PaymentEvent } from '../../../payment/application/events';
import type { IDashboardPaymentEventConsumer } from '../../application/services';
import { DashboardPaymentEventConsumer } from './dashboard-payment-event.consumer';
import { PaymentProjector } from '../projectors/payment.projector';

@Injectable()
export class CompositeDashboardPaymentEventConsumer
    implements IDashboardPaymentEventConsumer
{
    constructor(
        private readonly cacheConsumer: DashboardPaymentEventConsumer,
        private readonly projector: PaymentProjector,
    ) {}

    async consume(event: PaymentEvent): Promise<void> {
        await Promise.allSettled([
            this.cacheConsumer.consume(event),
            this.projector.consume(event),
        ]);
    }
}

export default CompositeDashboardPaymentEventConsumer;
