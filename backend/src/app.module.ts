import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { ProductModule } from './product/product.module';
import { CategoryModule } from './category/category.module';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { CartModule } from './cart/cart.module';
import { OrderModule } from './order/order.module';
import { PaymentModule } from './payment/payment.module';
import { CommonModule } from './common/common.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { ScheduleModule } from '@nestjs/schedule';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
        }),
        ThrottlerModule.forRoot({
            throttlers: [
                { name: 'short', ttl: 1000, limit: 3 },
                { name: 'medium', ttl: 10000, limit: 20 },
                { name: 'long', ttl: 60000, limit: 100 },
            ],
        }),
        ScheduleModule.forRoot(),
        PrismaModule,
        UsersModule,
        AuthModule,
        ProductModule,
        CategoryModule,
        CartModule,
        OrderModule,
        PaymentModule,
        CommonModule,
        DashboardModule,
    ],
    providers: [
        {
            provide: 'APP_NAME',
            useValue: 'HalimaE-commerce',
        },
        {
            provide: 'APP_VERSION',
            useValue: '1.0.0',
        },
        {
            provide: 'APP_DESCRIPTION',
            useValue: 'HalimaE-commerce',
        },
        {
            provide: APP_GUARD,
            useFactory: (configService: ConfigService) => {
                const nodeEnv = configService.get<string>('NODE_ENV');
                return nodeEnv === 'development' ? null : ThrottlerGuard;
            },
            inject: [ConfigService],
        },
    ],
})
export class AppModule {}
