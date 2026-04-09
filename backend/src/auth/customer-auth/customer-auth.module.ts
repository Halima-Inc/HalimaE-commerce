import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CustomerAuthService } from './customer-auth.service';
import { JwtModule } from '@nestjs/jwt';
import { CustomerAuthController } from './customer-auth.controller';
import { CustomerModule } from '../../customer/customer.module';
import { JwtCustomerStrategy } from './strategies/jwt.customer.strategy';
import { GoogleCustomerStrategy } from './strategies/google.customer.strategy';
import { EmailModule } from '../../email/email.module';

@Module({
    imports: [
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_CUSTOMER_SECRET'),
                signOptions: { expiresIn: '1d' },
            }),
        }),
        EmailModule,
        CustomerModule,
    ],
    providers: [CustomerAuthService, JwtCustomerStrategy, GoogleCustomerStrategy],
    controllers: [CustomerAuthController]
})
export class CustomerAuthModule {}
