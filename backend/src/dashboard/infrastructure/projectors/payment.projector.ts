import { Inject, Injectable } from '@nestjs/common';
import type { PaymentEvent } from '../../../payment/application/events';
import type { IDashboardPaymentEventConsumer } from '../../application/services';
import type IDashboardProjectionRepository from '../../application/services/projection-repository.interface';
import { DASHBOARD_PROJECTION_REPOSITORY } from '../../dashboard.tokens';

@Injectable()
export class PaymentProjector implements IDashboardPaymentEventConsumer {
    constructor(
        @Inject(DASHBOARD_PROJECTION_REPOSITORY)
        private readonly repo: IDashboardProjectionRepository,
    ) {}

    async consume(event: PaymentEvent): Promise<void> {
        try {
            if (event.eventName === 'PaymentCaptured') {
                const payload: any = event.payload as any;
                const occurred = new Date(event.occurredAt);
                const amount = Number(payload?.amount ?? 0);
                await this.repo.upsertRevenueSnapshot(occurred, amount, 1, 0);
                if (payload?.userId) {
                    await this.repo.upsertCustomerCounter(
                        payload.userId,
                        0,
                        amount,
                    );
                }
            }
        } catch {
            // swallow to allow dispatcher retries
        }
    }
}

export default PaymentProjector;
