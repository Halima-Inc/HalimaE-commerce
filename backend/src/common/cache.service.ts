import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import IORedis, { type Redis } from 'ioredis';


@Injectable()
export class CacheService implements OnModuleDestroy {
    private readonly redisClient: Redis;

    constructor(
        private readonly configService: ConfigService
    ) {
        this.redisClient = new IORedis({
            host    : this.configService.get<string>('REDIS_HOST') ?? 'localhost',
            port    : this.configService.get<number>('REDIS_PORT') ?? 6379,
            password: this.configService.get<string>('REDIS_PASSWORD'),
        });
    }

    async set(key: string, val: any, ttlSec?: number) {
        const v = JSON.stringify(val);

        if (ttlSec) {
            await this.redisClient.set(key, v, 'EX', ttlSec);
        } else { 
            await this.redisClient.set(key, v);
        }
    }
    
    async get<T>(key: string): Promise<T | null> {
        const val = await this.redisClient.get(key);

        return val ? JSON.parse(val) as T : null;
    }

    async del(key: string) {
        await this.redisClient.del(key);
    }

    onModuleDestroy() {
        this.redisClient.disconnect();
    }
}
