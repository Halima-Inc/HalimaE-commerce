import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { PasswordResetToken } from '../../domain';
import { IPasswordResetTokenRepository } from '../../domain/interfaces';

@Injectable()
export class PrismaPasswordResetTokenRepository
    implements IPasswordResetTokenRepository
{
    constructor(private readonly prisma: PrismaService) {}

    async save(token: PasswordResetToken): Promise<void> {
        await this.prisma.passwordResetToken.create({
            data: {
                id: token.getId(),
                tokenHash: token.getTokenHash(),
                userId: token.getUserId(),
                expiresAt: token.getExpiresAt(),
            },
        });
    }

    async findByTokenHash(
        tokenHash: string,
    ): Promise<PasswordResetToken | null> {
        const tokenRecord = await this.prisma.passwordResetToken.findUnique({
            where: { tokenHash },
        });

        if (!tokenRecord) return null;

        return this.toDomain(tokenRecord);
    }

    async findByUserId(userId: string): Promise<PasswordResetToken | null> {
        const tokenRecord = await this.prisma.passwordResetToken.findFirst({
            where: { userId },
        });

        if (!tokenRecord) return null;

        return this.toDomain(tokenRecord);
    }

    async delete(id: string): Promise<void> {
        await this.prisma.passwordResetToken.delete({
            where: { id },
        });
    }

    private toDomain(tokenRecord: any): PasswordResetToken {
        return PasswordResetToken.create(
            tokenRecord.id,
            tokenRecord.tokenHash,
            tokenRecord.userId,
            tokenRecord.expiresAt,
            tokenRecord.createdAt,
        );
    }
}
