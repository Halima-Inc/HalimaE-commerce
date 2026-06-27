import { Injectable, Inject } from '@nestjs/common';
import type { OrderEvent } from '../../../order/application/events';
import type { IDashboardOrderEventConsumer } from '../../application/services';
import type IDashboardProjectionRepository from '../../application/services/projection-repository.interface';
import { DASHBOARD_PROJECTION_REPOSITORY } from '../../dashboard.tokens';

@Injectable()
export class OrderProjector implements IDashboardOrderEventConsumer {
    constructor(
        @Inject(DASHBOARD_PROJECTION_REPOSITORY)
        private readonly repo: IDashboardProjectionRepository,
    ) {}

    async consume(event: OrderEvent): Promise<void> {
        try {
            const occurred = new Date(event.occurredAt);

            const payload: any = event.payload as any;
            switch (event.eventName) {
                case 'OrderCreated':
                    if (payload?.userId) {
                        await this.repo.upsertCustomerCounter(
                            payload.userId,
                            1,
                            0,
                        );
                    }
                    await this.repo.upsertOrdersByStatus(
                        'PENDING',
                        occurred,
                        1,
                    );
                    break;
                case 'OrderCancelled':
                    await this.repo.upsertOrdersByStatus(
                        'CANCELLED',
                        occurred,
                        1,
                    );
                    break;
                case 'OrderStatusUpdated':
                    if (payload?.status) {
                        await this.repo.upsertOrdersByStatus(
                            payload.status,
                            occurred,
                            1,
                        );
                    }
                    break;
                default:
                    break;
            }
        } catch {
            // projector should not throw
            // swallow and rely on dispatcher retry semantics
        }
    }
}
