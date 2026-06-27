import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { IEmailService } from '../../application/services';

@Injectable()
export class MailerEmailService implements IEmailService {
    constructor(private readonly mailerService: MailerService) {}

    /// TODO: Use Customer Email Templates for better user experience
    async sendPasswordResetEmail(email: string, token: string): Promise<void> {
        const resetUrl = `${process.env.FRONTEND_URL}/auth/reset-password?token=${token}`;

        await this.mailerService.sendMail({
            to: email,
            subject: 'Password Reset Request',
            template: 'password-reset',
            context: {
                resetUrl,
            },
        });
    }

    async sendWelcomeEmail(email: string, name: string): Promise<void> {
        await this.mailerService.sendMail({
            to: email,
            subject: 'Welcome to our platform',
            template: 'welcome',
            context: {
                name,
            },
        });
    }
}
