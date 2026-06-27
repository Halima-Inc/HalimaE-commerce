import { Inject, Injectable } from '@nestjs/common';
import { LoginUserCommand } from '../commands';
import {
    User,
    InvalidCredentialsException,
    UserNotFoundException,
} from '../../domain';
import type { IUserRepository } from '../../domain/interfaces';
import type { IPasswordService } from '../services/password.service.interface';
import type { ITokenService } from '../services/token.service.interface';
import type { IRefreshTokenService } from '../services/refresh-token.service.interface';
import {
    PASSWORD_SERVICE,
    REFRESH_TOKEN_SERVICE,
    TOKEN_SERVICE,
    USER_REPOSITORY,
} from '../../auth.tokens';

@Injectable()
export class LoginUserHandler {
    constructor(
        @Inject(USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
        @Inject(PASSWORD_SERVICE)
        private readonly passwordService: IPasswordService,
        @Inject(TOKEN_SERVICE)
        private readonly tokenService: ITokenService,
        @Inject(REFRESH_TOKEN_SERVICE)
        private readonly refreshTokenService: IRefreshTokenService,
    ) {}

    async execute(
        command: LoginUserCommand,
    ): Promise<{ accessToken: string; refreshToken: string; user: User }> {
        const user = await this.userRepository.findByEmail(command.email);
        if (!user) {
            throw new UserNotFoundException(
                'User not found with provided email',
            );
        }

        const isPasswordValid = await this.passwordService.comparePassword(
            command.password,
            user.getPasswordHash().getHashedPassword(),
        );

        if (!isPasswordValid) {
            throw new InvalidCredentialsException('Invalid email or password');
        }

        const accessToken = await this.tokenService.generateAccessToken(user);
        const refreshToken =
            await this.refreshTokenService.generateRefreshToken(user);

        return {
            accessToken,
            refreshToken,
            user,
        };
    }
}
