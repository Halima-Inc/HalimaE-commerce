import { Injectable } from '@nestjs/common';
import { CacheService } from '../../../common/cache.service';
import { LogService } from '../../../common/log.service';
import { DashboardService } from '../../dashboard.service';
import type { PaymentEvent } from '../../../payment/application/events';
import type { IDashboardPaymentEventConsumer } from '../../application/services';

@Injectable()
export class DashboardPaymentEventConsumer
    implements IDashboardPaymentEventConsumer
{
    constructor(
        private readonly dashboardService: DashboardService,
        private readonly cacheService: CacheService,
        private readonly logger: LogService,
    ) {}

    async consume(event: PaymentEvent): Promise<void> {
        const metrics = await this.dashboardService.computeDashboardMetrics();
        await this.cacheService.set('dashboard-metrics', metrics, 60 * 10);

        this.logger.debug(
            `Dashboard updated from payment event: ${event.eventName} (${event.eventId})`,
            DashboardPaymentEventConsumer.name,
        );
    }
}
