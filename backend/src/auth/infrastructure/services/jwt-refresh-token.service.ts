import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomUUID } from 'crypto';
import { User } from '../../domain';
import type { IRefreshTokenService } from '../../application/services';
import type { IRefreshTokenRepository } from '../../domain/interfaces';
import { RefreshToken } from '../../domain';
import { REFRESH_TOKEN_REPOSITORY } from '../../auth.tokens';
import { durationToMs } from '../../common/duration.util';

@Injectable()
export class JwtRefreshTokenService implements IRefreshTokenService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        @Inject(REFRESH_TOKEN_REPOSITORY)
        private readonly refreshTokenRepository: IRefreshTokenRepository,
    ) {}

    async generateRefreshToken(user: User): Promise<string> {
        const tokenId = randomUUID();
        const refreshTokenTtl = this.configService.get<string>(
            'JWT_REFRESH_EXPIRES_IN',
            '7d',
        );
        const refreshSecret =
            this.configService.get<string>('JWT_REFRESH_SECRET');

        const payload = {
            sub: user.getId(),
            email: user.getEmail().getValue(),
            tokenId,
        };

        const token = await this.jwtService.signAsync(payload, {
            expiresIn: refreshTokenTtl as any,
            secret: refreshSecret,
        });

        const tokenHash = createHash('sha256').update(token).digest('hex');

        const refreshTokenTtlMs = durationToMs(refreshTokenTtl);
        const expiresAt = new Date();
        expiresAt.setTime(expiresAt.getTime() + refreshTokenTtlMs);

        const refreshToken = RefreshToken.create(
            tokenId,
            tokenHash,
            user.getId(),
            expiresAt,
            false,
        );

        await this.refreshTokenRepository.save(refreshToken);

        return token;
    }

    async validateRefreshToken(token: string): Promise<any | null> {
        const refreshSecret =
            this.configService.get<string>('JWT_REFRESH_SECRET');

        try {
            const payload = await this.jwtService.verifyAsync(token, {
                secret: refreshSecret,
            });

            const tokenHash = createHash('sha256').update(token).digest('hex');
            const storedToken =
                await this.refreshTokenRepository.findByTokenHash(tokenHash);

            if (
                !storedToken ||
                storedToken.getIsRevoked() ||
                storedToken.getExpiresAt().getTime() <= Date.now()
            ) {
                return null;
            }

            return payload;
        } catch {
            return null;
        }
    }

    async revokeToken(token: string): Promise<void> {
        const tokenHash = createHash('sha256').update(token).digest('hex');

        const storedToken =
            await this.refreshTokenRepository.findByTokenHash(tokenHash);

        if (storedToken) {
            const revokedToken = RefreshToken.create(
                storedToken.getId(),
                storedToken.getTokenHash(),
                storedToken.getUserId(),
                storedToken.getExpiresAt(),
                true,
                storedToken.getDevice(),
                storedToken.getIp(),
                storedToken.getCreatedAt(),
            );

            await this.refreshTokenRepository.update(revokedToken);
        }
    }
}
