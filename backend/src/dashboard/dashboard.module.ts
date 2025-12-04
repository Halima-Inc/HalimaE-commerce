import { Module } from '@nestjs/common';
import { DashboardService } from './dashboard.service';
import { DashboardController } from './dashboard.controller';
import { ScheduleModule } from '@nestjs/schedule';
import { DashboardProcessor } from './dashboard.processor';
import { BullModule } from '@nestjs/bull';
import { ConfigService } from '@nestjs/config';
import { DashboardScheduler } from './dashboard.scheduler';
import { CacheService } from '../common/cache.service';

@Module({
    imports: [
        ScheduleModule.forRoot(),
        BullModule.registerQueueAsync({
            name: 'dashboard-queue',
            useFactory: (configService: ConfigService) => ({
                redis: {
                    host: configService.get('REDIS_HOST') ?? '127.0.0.1',
                    port: configService.get<number>('REDIS_PORT') ?? 6379,
                },
            }),
            inject: [ConfigService],
        }),
    ],
    providers: [
        DashboardService,
        DashboardProcessor,
        DashboardScheduler,
        CacheService,
    ],
    controllers: [DashboardController],
})
export class DashboardModule {}
