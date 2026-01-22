import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CustomerService } from '../../customer/customer.service';
import {
    CreateCustomerDto,
} from '../../customer/dto';
import { AuthCustomerDto, ResponseAuthCustomerDto } from './dto';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { Status } from '@prisma/client';
import { LogService } from '../../logger/log.service';
import { randomBytes, randomUUID } from 'node:crypto';
import { ConfigService } from '@nestjs/config';
import { EmailService } from '../../email/email.service';
import { ResetPasswordDto } from '../dto/reset-password.dto';


@Injectable()
export class CustomerAuthService {
    constructor(
        private readonly customerService: CustomerService,
        private readonly jwtService: JwtService,
        private readonly logger: LogService,
        private readonly configService: ConfigService,
        private readonly emailService: EmailService,
    ) { }

    async signup(dto: CreateCustomerDto, device?: string, ip?: string): Promise<ResponseAuthCustomerDto & { refresh_token: string }> {
        const customer = await this.customerService.create({
            ...dto,
        });
        return this.login({
            email: customer.email,
            password: dto.password,
            status: dto.status
        }, device, ip);
    }

    async login(dto: AuthCustomerDto, device?: string, ip?: string): Promise<ResponseAuthCustomerDto & { refresh_token: string }> {
        this.logger.debug(`Attempting to log in customer: ${dto.email}`, CustomerAuthService.name);
        const customer = await this.customerService.findByEmail(dto.email);
        if (!customer) {
            this.logger.warn(`Login failed. Customer not found: ${dto.email}`, CustomerAuthService.name);
            throw new UnauthorizedException('Invalid credentials');
        }
        
        if (! (await argon2.verify(customer.passwordHash ?? '', dto.password) )) {
            this.logger.warn(`Login failed. Invalid credentials for customer: ${dto.email}`, CustomerAuthService.name);
            throw new UnauthorizedException('Invalid credentials');
        }

        if (customer.status === Status.INACTIVE) {
            this.logger.warn(`Login failed. Account is inactive for customer: ${dto.email}`, CustomerAuthService.name);
            throw new UnauthorizedException('Account is inactive');
        }

        this.logger.log(`Customer logged in successfully: ${customer.email} (ID: ${customer.id})`, CustomerAuthService.name);

        const payload = {
            sub: customer.id,
            email: customer.email,
        }

        const access_token = await this.jwtService.signAsync(payload, {
            secret: this.configService.get<string>('JWT_CUSTOMER_SECRET')!,
            expiresIn: this.configService.get<string>('JWT_CUSTOMER_EXPIRES_IN') ?? '15m' as any,
        }
        );

        const refresh_token = await this.jwtService.signAsync(
            {
                ...payload,
                jti: randomUUID(), // Add unique identifier
            },
            {
                secret: this.configService.get<string>('JWT_CUSTOMER_REFRESH_SECRET')!,
                expiresIn: this.configService.get<string>('JWT_CUSTOMER_REFRESH_EXPIRES_IN') ?? '7d' as any,
            }
        );

        this.customerService.storeRefreshToken(
            customer.id,
            await argon2.hash(refresh_token),
            device,
            ip
        );

        return {
            name: customer.name,
            email: customer.email,
            phone: customer.phone ?? '',
            status: customer.status ?? Status.ACTIVE,
            access_token,
            refresh_token,
        };
    }

    async refreshToken(refresh_token: any): Promise<{ access_token: any; refresh_token: any; }> {
        let payload;
        try {
            payload = await this.jwtService.verifyAsync(refresh_token, {
                secret: this.configService.get<string>('JWT_CUSTOMER_REFRESH_SECRET')!,
            });
        } catch (e) {
            this.logger.warn(`Refresh token verification failed`, CustomerAuthService.name);
            throw new UnauthorizedException('Invalid refresh token');
        }

        const customerTokens = await this.customerService.findRefreshTokensByCustomerId(payload.sub);

        if (!customerTokens || customerTokens.length === 0) {
            this.logger.warn(`No valid refresh tokens found for customer: ${payload.sub}`, CustomerAuthService.name);
            throw new UnauthorizedException('Invalid refresh token');
        }

        let matchedToken = null;
        for (const storedToken of customerTokens) {
            if (await argon2.verify(storedToken.tokenHash, refresh_token)) {
                matchedToken = storedToken;
                break;
            }
        }

        if (!matchedToken) {
            this.logger.warn(`Refresh token hash not found for customer: ${payload.sub}`, CustomerAuthService.name);
            throw new UnauthorizedException('Invalid refresh token');
        }

        this.customerService.revokeRefreshToken(matchedToken.id);

        const newPayload = {
            sub: matchedToken.customerId,
            email: matchedToken.customer.email,
        }

        const access_token = await this.jwtService.signAsync(newPayload, {
            secret: this.configService.get<string>('JWT_CUSTOMER_SECRET')!,
            expiresIn: this.configService.get<string>('JWT_CUSTOMER_EXPIRES_IN') ?? '15m' as any,
        }
        );

        const new_refresh_token = await this.jwtService.signAsync(
            {
                ...newPayload,
                jti: randomUUID(),
            },
            {
                secret: this.configService.get<string>('JWT_CUSTOMER_REFRESH_SECRET')!,
                expiresIn: this.configService.get<string>('JWT_CUSTOMER_REFRESH_EXPIRES_IN') ?? '7d' as any,
            }
        );

        await this.customerService.storeRefreshToken(
            matchedToken.customerId,
            await argon2.hash(new_refresh_token),
            matchedToken.device,
            matchedToken.ip
        );

        this.logger.log(`Refresh token rotated successfully for customer: ${matchedToken.customer.email} (ID: ${matchedToken.customerId})`, CustomerAuthService.name);

        return {
            access_token,
            refresh_token: new_refresh_token,
        };
    }

    async logout(refresh_token: string) {
        let payload;
        try {
            payload = await this.jwtService.verifyAsync(refresh_token, {
                secret: this.configService.get<string>('JWT_CUSTOMER_REFRESH_SECRET')!,
            });
        } catch (e) {
            this.logger.warn(`Refresh token verification failed during logout`, CustomerAuthService.name);
            throw new UnauthorizedException('Invalid refresh token');
        }

        const customerTokens = await this.customerService.findRefreshTokensByCustomerId(payload.sub);

        if (!customerTokens || customerTokens.length === 0) {
            this.logger.warn(`No valid refresh tokens found for customer during logout: ${payload.sub}`, CustomerAuthService.name);
            throw new UnauthorizedException('Invalid refresh token');
        }

        for (const storedToken of customerTokens) {
            if (await argon2.verify(storedToken.tokenHash, refresh_token)) {
                await this.customerService.revokeRefreshToken(storedToken.id);
                this.logger.log(`Customer logged out successfully: ${storedToken.customer.email} (ID: ${storedToken.customerId})`, CustomerAuthService.name);
                return;
            }
        }

        this.logger.warn(`Refresh token hash not found for customer during logout: ${payload.sub}`, CustomerAuthService.name);
    }

    async logoutAll(refresh_token: any) {
        this.logger.log(`Revoking all refresh tokens for customer`, CustomerAuthService.name);
        await this.customerService.revokeAllCustomerRefreshTokens(refresh_token);
    }

    async resetPassword(email: string): Promise<{ message: string }> {
        const customer = await this.customerService.findByEmail(email);
        if (!customer) {
            this.logger.warn(`Password reset requested for non-existent email: ${email}`, CustomerAuthService.name);
        }

        const resetToken = randomBytes(32).toString('hex');
        if (customer) {
            // Invalidate any existing reset tokens for this customer
            await this.customerService.invalidateAllCustomerResetTokens(customer.id);
            
            await this.customerService.storePasswordResetToken(customer.id, resetToken);
            await this.emailService.sendResetPasswordEmail(
                'Reset Your Password',
                email,
                resetToken
            );
        }

        return {
            message: 'If an account with that email exists, a password reset link has been sent.'
        }
    }

     async resetPasswordConfirm(resetPasswordDto: ResetPasswordDto){
        const resetToken = await this.customerService.findPasswordResetToken(resetPasswordDto.token);
        if (!resetToken) {
            this.logger.warn(`Invalid or expired password reset token used`, CustomerAuthService.name);
            throw new ForbiddenException('Invalid or expired password reset token');
        }

        if (resetToken.customerId === null) {
            this.logger.error(`Password reset token has no associated customer`, CustomerAuthService.name);
            throw new ForbiddenException('Invalid password reset token');
        }
        
        // Update password
        await this.customerService.updatePassword(resetToken.customerId, resetPasswordDto.newPassword);
        
        // Invalidate the used token
        await this.customerService.invalidatePasswordResetToken(resetToken.id);
        
        // Revoke all active sessions for security (force re-login on all devices)
        await this.customerService.revokeAllCustomerRefreshTokens(resetToken.customerId);
        
        this.logger.log(`Password reset successfully for customer ID: ${resetToken.customerId}`, CustomerAuthService.name);
        return {
            message: 'Password has been reset successfully. Please log in with your new password.'
        };
    }

    async googleLogin(profile: { providerId: string; email: string; name: string }, device?: string, ip?: string): Promise<ResponseAuthCustomerDto & { refresh_token: string }> {
        this.logger.debug(`Google login attempt for email: ${profile.email}`, CustomerAuthService.name);

        // Find or create customer by Google profile
        const customer = await this.customerService.findOrCreateByGoogle(profile);

        if (customer.status === Status.INACTIVE) {
            this.logger.warn(`Google login failed. Account is inactive: ${customer.email}`, CustomerAuthService.name);
            throw new UnauthorizedException('Account is inactive');
        }

        this.logger.log(`Google customer authenticated successfully: ${customer.email} (ID: ${customer.id})`, CustomerAuthService.name);

        // Generate JWT tokens (same as regular login)
        const payload = {
            sub: customer.id,
            email: customer.email,
        };

        const access_token = await this.jwtService.signAsync(payload, {
            secret: this.configService.get<string>('JWT_CUSTOMER_SECRET')!,
            expiresIn: this.configService.get<string>('JWT_CUSTOMER_EXPIRES_IN') ?? '15m' as any,
        });

        const refresh_token = await this.jwtService.signAsync(
            {
                ...payload,
                jti: randomUUID(),
            },
            {
                secret: this.configService.get<string>('JWT_CUSTOMER_REFRESH_SECRET')!,
                expiresIn: this.configService.get<string>('JWT_CUSTOMER_REFRESH_EXPIRES_IN') ?? '7d' as any,
            }
        );

        // Store refresh token
        await this.customerService.storeRefreshToken(
            customer.id,
            await argon2.hash(refresh_token),
            device,
            ip
        );

        return {
            name: customer.name,
            email: customer.email,
            phone: customer.phone ?? '',
            status: customer.status ?? Status.ACTIVE,
            access_token,
            refresh_token,
        };
    }
}
