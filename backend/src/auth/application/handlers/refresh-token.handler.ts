import { Inject, Injectable } from '@nestjs/common';
import { RefreshTokenCommand } from '../commands';
import { InvalidTokenException, UserNotFoundException } from '../../domain';
import type { IUserRepository } from '../../domain/interfaces';
import type { ITokenService } from '../services/token.service.interface';
import type { IRefreshTokenService } from '../services/refresh-token.service.interface';
import {
    REFRESH_TOKEN_SERVICE,
    TOKEN_SERVICE,
    USER_REPOSITORY,
} from '../../auth.tokens';

@Injectable()
export class RefreshTokenHandler {
    constructor(
        @Inject(USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
        @Inject(TOKEN_SERVICE)
        private readonly tokenService: ITokenService,
        @Inject(REFRESH_TOKEN_SERVICE)
        private readonly refreshTokenService: IRefreshTokenService,
    ) {}

    async execute(
        command: RefreshTokenCommand,
    ): Promise<{ accessToken: string; refreshToken: string }> {
        const tokenPayload =
            await this.refreshTokenService.validateRefreshToken(
                command.refreshToken,
            );

        if (!tokenPayload || !tokenPayload.sub) {
            throw new InvalidTokenException('Invalid refresh token');
        }

        const user = await this.userRepository.findById(tokenPayload.sub);
        if (!user) {
            throw new UserNotFoundException('User not found');
        }

        await this.refreshTokenService.revokeToken(command.refreshToken);

        const accessToken = await this.tokenService.generateAccessToken(user);
        const refreshToken =
            await this.refreshTokenService.generateRefreshToken(user);

        return {
            accessToken,
            refreshToken,
        };
    }
}
