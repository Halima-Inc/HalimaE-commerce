import { Module } from '@nestjs/common';
import { DashboardService } from './dashboard.service';
import { DashboardController } from './dashboard.controller';
import { AuthModule } from '../auth/auth.module';
import { CacheService } from '../common/cache.service';
import { DashboardOrderEventConsumer } from './infrastructure/services/dashboard-order-event.consumer';
import { DashboardPaymentEventConsumer } from './infrastructure/services/dashboard-payment-event.consumer';
import { CompositeDashboardOrderEventConsumer } from './infrastructure/services/composite-dashboard-order-event.consumer';
import { CompositeDashboardPaymentEventConsumer } from './infrastructure/services/composite-dashboard-payment-event.consumer';
import { DASHBOARD_PROJECTION_REPOSITORY } from './dashboard.tokens';
import { PrismaProjectionRepository } from './infrastructure/repositories/prisma-projection.repository';
import {
    DASHBOARD_ORDER_EVENT_CONSUMER,
    DASHBOARD_PAYMENT_EVENT_CONSUMER,
} from './dashboard.tokens';
import { OrderProjector } from './infrastructure/projectors/order.projector';
import { PaymentProjector } from './infrastructure/projectors/payment.projector';

@Module({
    imports: [AuthModule],
    providers: [
        DashboardService,
        CacheService,
        DashboardOrderEventConsumer,
        DashboardPaymentEventConsumer,
        OrderProjector,
        PaymentProjector,
        {
            provide: DASHBOARD_ORDER_EVENT_CONSUMER,
            useClass: CompositeDashboardOrderEventConsumer,
        },
        {
            provide: DASHBOARD_PAYMENT_EVENT_CONSUMER,
            useClass: CompositeDashboardPaymentEventConsumer,
        },
        {
            provide: DASHBOARD_PROJECTION_REPOSITORY,
            useClass: PrismaProjectionRepository,
        },
    ],
    controllers: [DashboardController],
    exports: [
        DASHBOARD_ORDER_EVENT_CONSUMER,
        DASHBOARD_PAYMENT_EVENT_CONSUMER,
        DASHBOARD_PROJECTION_REPOSITORY,
    ],
})
export class DashboardModule {}
