import { Injectable } from '@nestjs/common';
import { CacheService } from '../../../common/cache.service';
import { LogService } from '../../../common/log.service';
import { DashboardService } from '../../dashboard.service';
import type { OrderEvent } from '../../../order/application/events';
import type { IDashboardOrderEventConsumer } from '../../application/services';

@Injectable()
export class DashboardOrderEventConsumer
    implements IDashboardOrderEventConsumer
{
    constructor(
        private readonly dashboardService: DashboardService,
        private readonly cacheService: CacheService,
        private readonly logger: LogService,
    ) {}

    async consume(event: OrderEvent): Promise<void> {
        const metrics = await this.dashboardService.computeDashboardMetrics();
        await this.cacheService.set('dashboard-metrics', metrics, 60 * 10);

        this.logger.debug(
            `Dashboard updated from order event: ${event.eventName} (${event.eventId})`,
            DashboardOrderEventConsumer.name,
        );
    }
}
