import { Global, InternalServerErrorException, Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { CacheService } from './cache.service';
import { ResponseInterceptor } from './interceptors/response.interceptor';
import { LogService } from './log.service';

@Global()
@Module({
    imports: [
        MailerModule.forRootAsync({
            useFactory: (configService: ConfigService) => {
                const host = configService.get('SMTP_HOST');
                const port = configService.get('SMTP_PORT');
                const user = configService.get('SMTP_USER');
                const pass = configService.get('SMTP_PASS');
                const env = configService.get('NODE_ENV');

                if (
                    env === 'production' &&
                    (!host || !port || !user || !pass)
                ) {
                    throw new InternalServerErrorException(
                        'Missing required SMTP configuration',
                    );
                }

                return {
                    transport: {
                        host: host || 'localhost',
                        port: Number(port) || 1025,
                        auth: user && pass ? { user, pass } : undefined,
                        secure: env === 'production',
                    },
                };
            },
            inject: [ConfigService],
        }),
    ],
    providers: [
        CacheService,
        LogService,
        {
            provide: APP_INTERCEPTOR,
            useClass: ResponseInterceptor,
        },
    ],
    exports: [CacheService, LogService, MailerModule],
})
export class CommonModule {}
