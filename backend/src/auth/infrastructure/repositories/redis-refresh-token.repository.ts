import { Injectable } from '@nestjs/common';
import { RefreshToken } from '../../domain';
import { IRefreshTokenRepository } from '../../domain/interfaces';
import { CacheService } from '../../../common/cache.service';

interface RefreshTokenCacheDto {
    id: string;
    tokenHash: string;
    userId: string;
    expiresAt: string;
    isRevoked: boolean;
    device?: string;
    ip?: string;
    createdAt?: string;
}

@Injectable()
export class RedisRefreshTokenRepository implements IRefreshTokenRepository {
    private readonly tokenHashPrefix = 'refresh_token:hash:';
    private readonly tokenIdPrefix = 'refresh_token:id:';
    private readonly userTokensPrefix = 'refresh_token:user:';

    constructor(private readonly cacheService: CacheService) {}

    async save(token: RefreshToken): Promise<void> {
        const ttlSec = this.getTtlSeconds(token.getExpiresAt());
        if (ttlSec <= 0) {
            return;
        }

        const payload = this.toCacheDto(token);
        const hashKey = this.getHashKey(token.getTokenHash());
        const idKey = this.getIdKey(token.getId());
        const userSetKey = this.getUserSetKey(token.getUserId());

        await this.cacheService.set(hashKey, payload, ttlSec);
        await this.cacheService.set(idKey, token.getTokenHash(), ttlSec);
        await this.cacheService.addToSet(userSetKey, token.getTokenHash());
        await this.cacheService.setExpire(userSetKey, ttlSec);
    }

    async findByTokenHash(tokenHash: string): Promise<RefreshToken | null> {
        const payload = await this.cacheService.get<RefreshTokenCacheDto>(
            this.getHashKey(tokenHash),
        );

        if (!payload) {
            return null;
        }

        return this.toDomain(payload);
    }

    async findByUserId(userId: string): Promise<RefreshToken[]> {
        const userSetKey = this.getUserSetKey(userId);
        const tokenHashes = await this.cacheService.getSetMembers(userSetKey);

        if (!tokenHashes.length) {
            return [];
        }

        const hashKeys = tokenHashes.map((tokenHash) =>
            this.getHashKey(tokenHash),
        );

        const payloads =
            await this.cacheService.getMany<RefreshTokenCacheDto>(hashKeys);

        const missingTokenHashes: string[] = [];
        const tokens: RefreshToken[] = [];

        payloads.forEach((payload, index) => {
            if (!payload) {
                missingTokenHashes.push(tokenHashes[index]);
                return;
            }

            tokens.push(this.toDomain(payload));
        });

        if (missingTokenHashes.length) {
            await Promise.all(
                missingTokenHashes.map((tokenHash) =>
                    this.cacheService.removeFromSet(userSetKey, tokenHash),
                ),
            );
        }

        return tokens;
    }

    async update(token: RefreshToken): Promise<void> {
        await this.save(token);
    }

    async delete(id: string): Promise<void> {
        const idKey = this.getIdKey(id);
        const tokenHash = await this.cacheService.get<string>(idKey);

        if (!tokenHash) {
            return;
        }

        const token = await this.findByTokenHash(tokenHash);
        if (token) {
            await this.cacheService.removeFromSet(
                this.getUserSetKey(token.getUserId()),
                tokenHash,
            );
        }

        await this.cacheService.del(this.getHashKey(tokenHash));
        await this.cacheService.del(idKey);
    }

    private getTtlSeconds(expiresAt: Date): number {
        const ttlMs = expiresAt.getTime() - Date.now();
        return Math.max(0, Math.floor(ttlMs / 1000));
    }

    private toCacheDto(token: RefreshToken): RefreshTokenCacheDto {
        return {
            id: token.getId(),
            tokenHash: token.getTokenHash(),
            userId: token.getUserId(),
            expiresAt: token.getExpiresAt().toISOString(),
            isRevoked: token.getIsRevoked(),
            device: token.getDevice(),
            ip: token.getIp(),
            createdAt: token.getCreatedAt()?.toISOString(),
        };
    }

    private toDomain(payload: RefreshTokenCacheDto): RefreshToken {
        return RefreshToken.create(
            payload.id,
            payload.tokenHash,
            payload.userId,
            new Date(payload.expiresAt),
            payload.isRevoked,
            payload.device,
            payload.ip,
            payload.createdAt ? new Date(payload.createdAt) : undefined,
        );
    }

    private getHashKey(tokenHash: string): string {
        return `${this.tokenHashPrefix}${tokenHash}`;
    }

    private getIdKey(id: string): string {
        return `${this.tokenIdPrefix}${id}`;
    }

    private getUserSetKey(userId: string): string {
        return `${this.userTokensPrefix}${userId}`;
    }
}
