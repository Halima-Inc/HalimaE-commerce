import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { User, Email, EncryptedPassword } from '../../domain';
import { IUserRepository } from '../../domain/interfaces';
import { PROVIDER, Status } from '@prisma/client';

@Injectable()
export class PrismaUserRepository implements IUserRepository {
    constructor(private readonly prisma: PrismaService) {}

    async save(user: User): Promise<void> {
        const provider = user.getProvider() as PROVIDER | null | undefined;

        await this.prisma.user.create({
            data: {
                id: user.getId(),
                email: user.getEmail().getValue(),
                name: user.getName(),
                passwordHash: user.getPasswordHash().getHashedPassword(),
                roleId: user.getRoleId() || undefined,
                provider,
                providerId: user.getProviderId(),
                status: (user.getStatus() as Status) || Status.ACTIVE,
            },
        });
    }

    async findById(id: string): Promise<User | null> {
        const userRecord = await this.prisma.user.findUnique({
            where: { id },
            select: {
                id: true,
                email: true,
                name: true,
                passwordHash: true,
                roleId: true,
                phone: true,
                provider: true,
                providerId: true,
                status: true,
                createdAt: true,
                updatedAt: true,
            },
        });

        if (!userRecord) return null;

        return this.toDomain(userRecord);
    }

    async findByEmail(email: string): Promise<User | null> {
        const userRecord = await this.prisma.user.findUnique({
            where: { email },
            select: {
                id: true,
                email: true,
                name: true,
                passwordHash: true,
                roleId: true,
                phone: true,
                provider: true,
                providerId: true,
                status: true,
                createdAt: true,
                updatedAt: true,
            },
        });

        if (!userRecord) return null;

        return this.toDomain(userRecord);
    }

    async update(user: User): Promise<void> {
        const provider = user.getProvider() as PROVIDER | null | undefined;

        await this.prisma.user.update({
            where: { id: user.getId() },
            data: {
                email: user.getEmail().getValue(),
                name: user.getName(),
                passwordHash: user.getPasswordHash().getHashedPassword(),
                roleId: user.getRoleId() || undefined,
                provider,
                providerId: user.getProviderId(),
                status: (user.getStatus() as Status) || Status.ACTIVE,
            },
        });
    }

    async delete(id: string): Promise<void> {
        await this.prisma.user.delete({
            where: { id },
        });
    }

    private toDomain(userRecord: any): User {
        return User.create(
            userRecord.id,
            Email.create(userRecord.email),
            userRecord.name,
            EncryptedPassword.create(userRecord.passwordHash),
            userRecord.roleId,
            userRecord.phone,
            userRecord.provider,
            userRecord.providerId,
            userRecord.status,
            userRecord.createdAt,
            userRecord.updatedAt,
        );
    }
}
