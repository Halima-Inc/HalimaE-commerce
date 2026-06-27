import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaService } from '../prisma/prisma.service';

// Presentation
import {
    AuthController,
    RolesController,
    JwtAccessTokenGuard,
    RolesGuard,
    PermissionsGuard,
    JwtAccessTokenStrategy,
} from './presentation';

// Application
import {
    RegisterUserHandler,
    LoginUserHandler,
    RefreshTokenHandler,
    ResetPasswordHandler,
    CreateRoleHandler,
    UpdateRolePermissionsHandler,
    DeleteRoleHandler,
    GetRolesHandler,
} from './application/handlers';

// Infrastructure
import {
    PrismaUserRepository,
    PrismaRoleRepository,
    RedisRefreshTokenRepository,
    PrismaPasswordResetTokenRepository,
} from './infrastructure/repositories';

import {
    Argon2PasswordService,
    JwtAccessTokenService,
    JwtRefreshTokenService,
    MailerEmailService,
} from './infrastructure/services';

import { CleanupTokensService } from './infrastructure/schedulers/cleanup-tokens.service';

import {
    USER_REPOSITORY,
    ROLE_REPOSITORY,
    REFRESH_TOKEN_REPOSITORY,
    PASSWORD_RESET_TOKEN_REPOSITORY,
    PASSWORD_SERVICE,
    TOKEN_SERVICE,
    REFRESH_TOKEN_SERVICE,
    EMAIL_SERVICE,
} from './auth.tokens';

@Module({
    imports: [
        ConfigModule,
        PassportModule,
        JwtModule.registerAsync({
            inject: [ConfigService],
            useFactory: (configService: ConfigService): JwtModuleOptions => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: {
                    expiresIn: configService.get(
                        'JWT_ACCESS_EXPIRES_IN',
                        '15m',
                    ),
                },
            }),
        }),
    ],
    controllers: [AuthController, RolesController],
    providers: [
        // Strategies
        JwtAccessTokenStrategy,

        // Guards
        JwtAccessTokenGuard,
        RolesGuard,
        PermissionsGuard,

        // Handlers (Use Cases)
        RegisterUserHandler,
        LoginUserHandler,
        RefreshTokenHandler,
        ResetPasswordHandler,
        CreateRoleHandler,
        UpdateRolePermissionsHandler,
        DeleteRoleHandler,
        GetRolesHandler,

        // Schedulers
        CleanupTokensService,

        // Services
        {
            provide: PASSWORD_SERVICE,
            useClass: Argon2PasswordService,
        },
        {
            provide: TOKEN_SERVICE,
            useClass: JwtAccessTokenService,
        },
        {
            provide: REFRESH_TOKEN_SERVICE,
            useClass: JwtRefreshTokenService,
        },
        {
            provide: EMAIL_SERVICE,
            useClass: MailerEmailService,
        },

        // Repositories
        {
            provide: USER_REPOSITORY,
            useClass: PrismaUserRepository,
        },
        {
            provide: ROLE_REPOSITORY,
            useClass: PrismaRoleRepository,
        },
        {
            provide: REFRESH_TOKEN_REPOSITORY,
            useClass: RedisRefreshTokenRepository,
        },
        {
            provide: PASSWORD_RESET_TOKEN_REPOSITORY,
            useClass: PrismaPasswordResetTokenRepository,
        },

        // External Services
        PrismaService,
    ],
    exports: [
        JwtAccessTokenGuard,
        RolesGuard,
        PermissionsGuard,
        JwtAccessTokenStrategy,
        TOKEN_SERVICE,
        USER_REPOSITORY,
        ROLE_REPOSITORY,
    ],
})
export class AuthModule {}
