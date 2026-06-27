import { Module } from '@nestjs/common';
import { OrderController } from './order.controller';
import { AuthModule } from '../auth/auth.module';
import { CartModule } from '../cart/cart.module';
import { PrismaModule } from '../prisma/prisma.module';
import { PaymentModule } from '../payment/payment.module';
import { ProductModule } from '../product/product.module';
import { DashboardModule } from '../dashboard/dashboard.module';
import {
    CreateOrderHandler,
    GetAllOrdersHandler,
    GetCustomerOrdersHandler,
    GetOrderByIdHandler,
    GetOrderByOrderNoHandler,
    CancelOrderHandler,
    UpdateFulfillmentStatusHandler,
    UpdateOrderStatusHandler,
    UpdatePaymentStatusHandler,
} from './application/handlers';
import { PrismaOrderRepository } from './infrastructure/repositories';
import { OrderOutboxDispatcherScheduler } from './infrastructure/schedulers';
import {
    CompositeOrderEventPublisher,
    InMemoryOrderEventPublisher,
} from './infrastructure/services';
import { OrderPaymentEventConsumer } from './infrastructure/services/order-payment-event.consumer';
import { ORDER_REPOSITORY, ORDER_EVENT_PUBLISHER } from './order.tokens';

@Module({
    imports: [
        AuthModule,
        PrismaModule,
        CartModule,
        PaymentModule,
        ProductModule,
        DashboardModule,
    ],
    providers: [
        CreateOrderHandler,
        GetAllOrdersHandler,
        GetCustomerOrdersHandler,
        GetOrderByIdHandler,
        GetOrderByOrderNoHandler,
        CancelOrderHandler,
        UpdateOrderStatusHandler,
        UpdatePaymentStatusHandler,
        UpdateFulfillmentStatusHandler,
        PrismaOrderRepository,
        {
            provide: ORDER_REPOSITORY,
            useExisting: PrismaOrderRepository,
        },
        {
            provide: ORDER_EVENT_PUBLISHER,
            useClass: CompositeOrderEventPublisher,
        },
        InMemoryOrderEventPublisher,
        CompositeOrderEventPublisher,
        OrderOutboxDispatcherScheduler,
        OrderPaymentEventConsumer,
    ],
    controllers: [OrderController],
    exports: [ORDER_REPOSITORY],
})
export class OrderModule {}
