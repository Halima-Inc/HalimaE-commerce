import {
    Controller,
    Post,
    Body,
    HttpCode,
    HttpStatus,
    Res,
    Req,
    UseGuards,
    UnauthorizedException,
} from '@nestjs/common';
import {
    ApiTags,
    ApiOperation,
    ApiBearerAuth,
    ApiCookieAuth,
} from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import {
    RegisterUserHandler,
    LoginUserHandler,
    RefreshTokenHandler,
} from '../../application/handlers';
import {
    LoginUserCommand,
    RegisterUserCommand,
    RefreshTokenCommand,
} from '../../application/commands';
import {
    RegisterUserRequestDto,
    LoginUserRequestDto,
    AuthResponseDto,
    UserResponseDto,
} from '../dtos';
import { Public } from '../decorators';
import { JwtAccessTokenGuard } from '../guards';
import { durationToMs } from '../../common/duration.util';
import {
    ApiStandardErrorResponse,
    ApiStandardResponse,
} from '../../../common/swagger/api-response.decorator';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    private readonly refreshTokenTtlMs: number;

    constructor(
        private readonly registerUserHandler: RegisterUserHandler,
        private readonly loginUserHandler: LoginUserHandler,
        private readonly refreshTokenHandler: RefreshTokenHandler,
        private readonly configService: ConfigService,
    ) {
        const refreshTokenTtl = this.configService.get<string>(
            'JWT_REFRESH_EXPIRES_IN',
            '7d',
        );
        this.refreshTokenTtlMs = durationToMs(refreshTokenTtl);
    }

    @Post('register')
    @Public()
    @HttpCode(HttpStatus.CREATED)
    @ApiOperation({ summary: 'Register a new user' })
    @ApiStandardResponse(AuthResponseDto, 'User registered successfully', 201)
    @ApiStandardErrorResponse(400, 'Invalid registration payload')
    @ApiStandardErrorResponse(409, 'User already exists')
    @ApiStandardErrorResponse(404, 'Customer role not found')
    async register(
        @Body() dto: RegisterUserRequestDto,
        @Res({ passthrough: true }) res: Response,
    ): Promise<AuthResponseDto> {
        const user = await this.registerUserHandler.execute(
            new RegisterUserCommand(
                dto.email,
                dto.name,
                dto.password,
                undefined,
                dto.phone,
            ),
        );

        const { accessToken, refreshToken } =
            await this.loginUserHandler.execute(
                new LoginUserCommand(dto.email, dto.password),
            );

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: this.refreshTokenTtlMs,
            path: '/api/auth',
        });

        return {
            accessToken,
            refreshToken,
            user: this.mapUserToDto(user),
        };
    }

    @Post('login')
    @Public()
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Login user' })
    @ApiStandardResponse(AuthResponseDto, 'User logged in successfully')
    @ApiStandardErrorResponse(400, 'Invalid login payload')
    @ApiStandardErrorResponse(401, 'Invalid credentials')
    @ApiStandardErrorResponse(404, 'User not found')
    async login(
        @Body() dto: LoginUserRequestDto,
        @Res({ passthrough: true }) res: Response,
    ): Promise<AuthResponseDto> {
        const { accessToken, refreshToken, user } =
            await this.loginUserHandler.execute(
                new LoginUserCommand(dto.email, dto.password),
            );

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: this.refreshTokenTtlMs,
            path: '/api/auth',
        });

        return {
            accessToken,
            refreshToken,
            user: this.mapUserToDto(user),
        };
    }

    @Post('refresh-token')
    @Public()
    @HttpCode(HttpStatus.OK)
    @ApiCookieAuth('refresh_token')
    @ApiOperation({ summary: 'Refresh access token' })
    @ApiStandardResponse(Object, 'Access token refreshed successfully')
    @ApiStandardErrorResponse(401, 'Invalid or missing refresh token')
    @ApiStandardErrorResponse(404, 'User not found')
    async refreshToken(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ): Promise<{ accessToken: string }> {
        const refreshToken = req.cookies?.refresh_token;

        if (!refreshToken) {
            throw new UnauthorizedException('Refresh token not found');
        }

        const { accessToken, refreshToken: newRefreshToken } =
            await this.refreshTokenHandler.execute(
                new RefreshTokenCommand(refreshToken),
            );

        res.cookie('refresh_token', newRefreshToken, {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: this.refreshTokenTtlMs,
            path: '/api/auth',
        });

        return { accessToken };
    }

    @Post('logout')
    @UseGuards(JwtAccessTokenGuard)
    @HttpCode(HttpStatus.OK)
    @ApiBearerAuth('JWT-auth')
    @ApiOperation({ summary: 'Logout user' })
    @ApiStandardResponse(Object, 'User logged out successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized')
    async logout(
        @Res({ passthrough: true }) res: Response,
    ): Promise<{ message: string }> {
        res.clearCookie('refresh_token', {
            httpOnly: true,
            sameSite: 'strict',
            path: '/api/auth',
        });

        return { message: 'Logged out successfully' };
    }

    private mapUserToDto(user: any): UserResponseDto {
        return {
            id: user.getId(),
            email: user.getEmail().getValue(),
            name: user.getName(),
            phone: user.getPhone(),
        };
    }
}
