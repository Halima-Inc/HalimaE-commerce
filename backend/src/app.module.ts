import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { ProductModule } from './product/product.module';
import { CategoryModule } from './category/category.module';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { CustomerModule } from './customer/customer.module';
import { LogModule } from './logger/log.module';
import { CartModule } from './cart/cart.module';
import { OrderModule } from './order/order.module';
import { PaymentModule } from './payment/payment.module';
import { EmailModule } from './email/email.module';
import { CommonModule } from './common/common.module';
import { DashboardModule } from './dashboard/dashboard.module';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
        }),
        PrismaModule,
        UsersModule,
        AuthModule,
        ProductModule,
        CategoryModule,
        ThrottlerModule.forRoot({
            throttlers: [
                { name: 'short', ttl: 1000, limit: 3 },
                { name: 'medium', ttl: 10000, limit: 20 },
                { name: 'long', ttl: 60000, limit: 100 },
            ],
        }),
        CustomerModule,
        LogModule,
        CartModule,
        OrderModule,
        PaymentModule,
        EmailModule,
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
            provide: 'APP_LICENSE',
            useValue: 'MIT',
        },
        {
            provide: 'APP_LICENSE_URL',
            useValue: 'https://opensource.org/licenses/MIT',
        },
        {
            provide: APP_GUARD,
            useFactory: (configService: ConfigService) => {
                const nodeEnv = configService.get<string>('NODE_ENV');
                return nodeEnv === 'test' ? null : ThrottlerGuard;
            },
            inject: [ConfigService],
        },
    ],
})
export class AppModule {}
