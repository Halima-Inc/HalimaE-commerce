import {
    Controller,
    Post,
    Body,
    HttpCode,
    HttpStatus,
    Res,
    Req,
    UnauthorizedException,
    UseGuards,
    Get,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiExtraModels, ApiBearerAuth, ApiCookieAuth, ApiExcludeEndpoint, ApiResponse } from '@nestjs/swagger';
import { ApiStandardResponse, ApiStandardErrorResponse } from '../../../common/swagger/api-response.decorator';
import { CustomerAuthService } from './customer-auth.service';
import { CreateCustomerDto } from '../../customer/dto';
import { AuthCustomerDto, ResponseAuthCustomerDto } from './dto';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import type { RequestWithCustomer } from '../../../common/types/request-with-customer.type';
import { JwtCustomerGuard } from './guards/jwt.customer.guard';
import { ResetPasswordDto, ResetPasswordRequestDto } from '../dto';
import { Throttle } from '@nestjs/throttler';
import { AuthGuard } from '@nestjs/passport';



@ApiTags('customer-auth')
@ApiExtraModels(CreateCustomerDto, AuthCustomerDto, ResponseAuthCustomerDto, ResetPasswordDto, ResetPasswordRequestDto)
@Controller('customers/auth')
export class CustomerAuthController {
    constructor(
        private readonly customerAuthService: CustomerAuthService,
        private readonly configService: ConfigService,
    ) { }

    @Post('signup')
    @ApiOperation({
        summary: 'Customer signup',
        description: 'Register a new customer account and receive an access token. Returns access token in response body and sets refresh token as httpOnly cookie for secure token rotation.'
    })
    @ApiStandardResponse(ResponseAuthCustomerDto, 'Customer registered successfully', 201)
    @ApiStandardErrorResponse(400, 'Invalid registration data', 'Validation failed for customer registration')
    @ApiStandardErrorResponse(409, 'Email already exists', 'A customer with this email already exists')
    @HttpCode(HttpStatus.CREATED)
    async signup(@Body() dto: CreateCustomerDto, @Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<ResponseAuthCustomerDto> {
        const { refresh_token, ...result } = await this.customerAuthService.signup(
            dto,
            req.headers['user-agent'],
            req.ip
        );

        res.cookie('refresh_token', refresh_token, {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days
            path: '/api/customers/auth'
        });

        return result;
    }

    @Get('google')
    @UseGuards(AuthGuard('google'))
    @ApiOperation({
        summary: 'Initiate Google OAuth login',
        description: 'Initiates Google OAuth 2.0 authentication flow. Redirects user to Google\'s consent screen where they can sign in with their Google account. After successful authentication, Google redirects back to the callback endpoint with user profile information.'
    })
    @ApiResponse({
        status: 302,
        description: 'Redirects to Google OAuth consent screen'
    })
    @ApiStandardErrorResponse(500, 'Internal Server Error', 'Failed to initiate Google OAuth flow')
    googleAuth() {
        // Guard handles redirect to Google
    }

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    @ApiOperation({
        summary: 'Google OAuth callback (Internal)',
        description: 'Internal endpoint called by Google after successful authentication. Processes the OAuth response, creates or links the customer account, generates custom JWT tokens (access & refresh), sets refresh token as httpOnly cookie, and redirects to frontend with access token. This endpoint should not be called directly.'
    })
    @ApiResponse({
        status: 302,
        description: 'Redirects to frontend with access_token query parameter. Refresh token is set as httpOnly cookie.'
    })
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Google OAuth authentication failed')
    @ApiStandardErrorResponse(500, 'Internal Server Error', 'Failed to process Google OAuth callback')
    @ApiExcludeEndpoint() // Hide from Swagger as it's called by Google
    async googleAuthRedirect(
        @Req() req: Request & { user: any },
        @Res() res: Response
    ) {
        const { refresh_token, ...result } = await this.customerAuthService.googleLogin(
            req.user,
            req.headers['user-agent'],
            req.ip
        );

        // Set refresh token as httpOnly cookie
        res.cookie('refresh_token', refresh_token, {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/api/customers/auth'
        });

        // Redirect to frontend with access token
        const frontendUrl = this.configService.get('FRONTEND_URL') || 'http://localhost:3000';
        const redirectUrl = `${frontendUrl}/auth/google/callback?access_token=${result.access_token}`;
        
        res.redirect(redirectUrl);
    }

    @Post('login')
    @ApiOperation({
        summary: 'Customer login',
        description: 'Authenticate a customer and receive an access token. Returns access token in response body and sets refresh token as httpOnly cookie for secure token rotation.'
    })
    @ApiStandardResponse(ResponseAuthCustomerDto, 'Customer logged in successfully')
    @ApiStandardErrorResponse(400, 'Invalid credentials', 'Email or password is incorrect')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication failed')
    @HttpCode(HttpStatus.OK)
    async login(@Body() dto: AuthCustomerDto, @Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<ResponseAuthCustomerDto> {
        const { refresh_token, ...result } = await this.customerAuthService.login(
            dto,
            req.headers['user-agent'],
            req.ip
        );

        res.cookie('refresh_token', refresh_token, {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/api/customers/auth'
        });

        return result;
    }

    @Post('refresh-token')
    @HttpCode(HttpStatus.CREATED)
    @ApiOperation({
        summary: 'Refresh access token',
        description: 'Get a new access token using the refresh token from httpOnly cookie. The old refresh token is revoked and a new one is set (token rotation).'
    })
    @ApiCookieAuth('refresh_token')
    @ApiStandardResponse(Object, 'Token refreshed successfully', 201)
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Invalid, expired, or missing refresh token')
    async refreshToken(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<{ access_token: string }> {
        const refresh_token = req.cookies?.refresh_token;

        if (!refresh_token) {
            throw new UnauthorizedException('Refresh token not found');
        }

        const { access_token, refresh_token: new_refresh_token } = await this.customerAuthService.refreshToken(refresh_token);

        res.cookie('refresh_token', new_refresh_token, {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/api/customers/auth'
        });

        return { access_token };
    }

    @Post('logout')
    @UseGuards(JwtCustomerGuard)
    @HttpCode(HttpStatus.OK)
    @ApiBearerAuth('JWT-auth')
    @ApiOperation({
        summary: 'Logout from current device',
        description: 'Revoke the refresh token for the current session/device only. Requires Bearer token authentication. Clears the refresh token httpOnly cookie.'
    })
    @ApiStandardResponse(Object, 'Logged out from current device successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required - missing or invalid access token')
    async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<{ message: string }> {
        const refresh_token = req.cookies?.refresh_token;

        if (refresh_token) {
            await this.customerAuthService.logout(refresh_token);
        }

        res.clearCookie('refresh_token', {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            path: '/api/customers/auth'
        });

        return { message: 'Logged out from current device successfully' };
    }

    @Post('logout-all')
    @UseGuards(JwtCustomerGuard)
    @HttpCode(HttpStatus.OK)
    @ApiBearerAuth('JWT-auth')
    @ApiOperation({
        summary: 'Logout from all devices',
        description: 'Revoke all refresh tokens for the authenticated customer across all devices. Requires Bearer token authentication. Clears the refresh token httpOnly cookie on the current device.'
    })
    @ApiStandardResponse(Object, 'Logged out from all devices successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required - missing or invalid access token')
    async logoutAll(@Req() req: RequestWithCustomer, @Res({ passthrough: true }) res: Response): Promise<{ message: string }> {
        await this.customerAuthService.logoutAll(req.customer.sub);

        res.clearCookie('refresh_token', {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
            path: '/api/customers/auth'
        });

        return { message: 'Logged out from all devices successfully' };
    }

    @Post('reset-password-request')
    @HttpCode(HttpStatus.OK)
    @Throttle({ default: { limit: 3, ttl: 60000 } }) // 3 requests per minute per IP
    @ApiOperation({
        summary: 'Request password reset',
        description: 'Send a password reset link to the provided email address. Rate limited to 3 requests per minute. Returns same message whether email exists or not to prevent user enumeration.'
    })
    @ApiStandardResponse(Object, 'Password reset email sent if account exists')
    @ApiStandardErrorResponse(429, 'Too Many Requests', 'Rate limit exceeded. Please try again later.')
    async resetPassword(@Body() dto: ResetPasswordRequestDto): Promise<{ message: string }> {
        return this.customerAuthService.resetPassword(dto.email);
    }

    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute per IP
    @ApiOperation({
        summary: 'Confirm password reset',
        description: 'Reset password using the token received via email. Token expires after 5 minutes. All active sessions will be invalidated after successful reset.'
    })
    @ApiStandardResponse(Object, 'Password reset successfully')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Invalid or expired password reset token')
    @ApiStandardErrorResponse(429, 'Too Many Requests', 'Rate limit exceeded. Please try again later.')
    async resetPasswordConfirm(
        @Body() resetPasswordDto: ResetPasswordDto
    ): Promise<{ message: string }> {
        return this.customerAuthService.resetPasswordConfirm(resetPasswordDto);
    }
}