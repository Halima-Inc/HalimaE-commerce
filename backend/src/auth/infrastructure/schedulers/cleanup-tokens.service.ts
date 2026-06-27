import { Injectable } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { LogService } from '../../../common/log.service';
import { PrismaService } from '../../../prisma/prisma.service';

@Injectable()
export class CleanupTokensService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly logger: LogService,
    ) {}

    @Cron('0 1 * * *', { name: 'cleanupResetTokens' }) // Runs every day at 1 AM
    async cleanupResetTokens() {
        this.logger.log(
            'Starting cleanup of expired password reset tokens',
            CleanupTokensService.name,
        );
        await this.prisma.passwordResetToken.deleteMany({
            where: {
                expiresAt: { lt: new Date() },
            },
        });
        this.logger.log(
            'Finished cleanup of expired password reset tokens',
            CleanupTokensService.name,
        );
    }
}
