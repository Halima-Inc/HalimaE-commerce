import { Module } from '@nestjs/common';
import { PaymentService } from './payment.service';
import { HttpModule } from '@nestjs/axios';
import { AuthModule } from '../auth/auth.module';
import { PaymobProvider } from './payment-provider';
import { PrismaModule } from '../prisma/prisma.module';
import { DashboardModule } from '../dashboard/dashboard.module';
import { PaymentController } from './payment.controller';
import {
    CreatePaymentIntentHandler,
    HandlePaymentWebhookHandler,
    RecordCashPaymentHandler,
    RefundPaymentHandler,
    SavePaymentHandler,
} from './application/handlers';
import { PrismaPaymentRepository } from './infrastructure/repositories';
import { OutboxDispatcherScheduler } from './infrastructure/schedulers';
import {
    CompositePaymentEventPublisher,
    InMemoryPaymentEventPublisher,
} from './infrastructure/services';
import {
    PAYMENT_EVENT_PUBLISHER,
    PAYMENT_PROVIDER,
    PAYMENT_REPOSITORY,
} from './payment.tokens';

@Module({
    imports: [HttpModule, AuthModule, PrismaModule, DashboardModule],
    controllers: [PaymentController],
    providers: [
        {
            provide: PAYMENT_PROVIDER,
            useClass: PaymobProvider,
        },
        {
            provide: PAYMENT_REPOSITORY,
            useClass: PrismaPaymentRepository,
        },
        {
            provide: PAYMENT_EVENT_PUBLISHER,
            useClass: CompositePaymentEventPublisher,
        },
        InMemoryPaymentEventPublisher,
        CompositePaymentEventPublisher,
        CreatePaymentIntentHandler,
        HandlePaymentWebhookHandler,
        SavePaymentHandler,
        RecordCashPaymentHandler,
        RefundPaymentHandler,
        OutboxDispatcherScheduler,
        PaymentService,
    ],
    exports: [PaymentService, InMemoryPaymentEventPublisher],
})
export class PaymentModule {}
