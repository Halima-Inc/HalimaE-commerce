import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { RefreshToken } from '../../domain';
import { IRefreshTokenRepository } from '../../domain/interfaces';

@Injectable()
export class PrismaRefreshTokenRepository implements IRefreshTokenRepository {
    constructor(private readonly prisma: PrismaService) {}

    async save(token: RefreshToken): Promise<void> {
        await this.prisma.refreshToken.create({
            data: {
                id: token.getId(),
                tokenHash: token.getTokenHash(),
                userId: token.getUserId(),
                expiresAt: token.getExpiresAt(),
                isRevoked: token.getIsRevoked(),
                device: token.getDevice(),
                ip: token.getIp(),
            },
        });
    }

    async findByTokenHash(tokenHash: string): Promise<RefreshToken | null> {
        const tokenRecord = await this.prisma.refreshToken.findFirst({
            where: { tokenHash },
        });

        if (!tokenRecord) return null;

        return this.toDomain(tokenRecord);
    }

    async findByUserId(userId: string): Promise<RefreshToken[]> {
        const tokenRecords = await this.prisma.refreshToken.findMany({
            where: { userId },
        });

        return tokenRecords.map((record) => this.toDomain(record));
    }

    async update(token: RefreshToken): Promise<void> {
        await this.prisma.refreshToken.update({
            where: { id: token.getId() },
            data: {
                tokenHash: token.getTokenHash(),
                userId: token.getUserId(),
                expiresAt: token.getExpiresAt(),
                isRevoked: token.getIsRevoked(),
                device: token.getDevice(),
                ip: token.getIp(),
            },
        });
    }

    async delete(id: string): Promise<void> {
        await this.prisma.refreshToken.delete({
            where: { id },
        });
    }

    private toDomain(tokenRecord: any): RefreshToken {
        return RefreshToken.create(
            tokenRecord.id,
            tokenRecord.tokenHash,
            tokenRecord.userId,
            tokenRecord.expiresAt,
            tokenRecord.isRevoked,
            tokenRecord.device,
            tokenRecord.ip,
            tokenRecord.createdAt,
        );
    }
}
