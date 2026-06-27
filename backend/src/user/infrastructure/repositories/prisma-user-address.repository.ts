import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import type {
    CreateUserAddressInput,
    IUserAddressRepository,
    UpdateUserAddressInput,
} from '../../domain';

@Injectable()
export class PrismaUserAddressRepository implements IUserAddressRepository {
    private static readonly addressSelect = {
        id: true,
        userId: true,
        firstName: true,
        lastName: true,
        phone: true,
        line1: true,
        line2: true,
        city: true,
        postalCode: true,
        country: true,
        isDefault: true,
        createdAt: true,
        updatedAt: true,
    } as const;

    constructor(private readonly prisma: PrismaService) {}

    async findById(userId: string, addressId: string) {
        const address = await this.prisma.address.findFirst({
            where: { id: addressId, userId },
            select: PrismaUserAddressRepository.addressSelect,
        });

        if (!address) {
            throw new NotFoundException('Address not found');
        }

        return address;
    }

    async findAll(userId: string) {
        return this.prisma.address.findMany({
            where: { userId },
            orderBy: { isDefault: 'desc' },
            select: PrismaUserAddressRepository.addressSelect,
        });
    }

    async create(userId: string, data: CreateUserAddressInput) {
        return this.prisma.address.create({
            data: {
                userId,
                ...data,
            },
            select: PrismaUserAddressRepository.addressSelect,
        });
    }

    async update(
        userId: string,
        addressId: string,
        data: UpdateUserAddressInput,
    ) {
        const updated = await this.prisma.address.updateMany({
            where: { id: addressId, userId },
            data,
        });

        if (updated.count === 0) {
            throw new NotFoundException('Address not found');
        }

        const address = await this.prisma.address.findFirst({
            where: { id: addressId, userId },
            select: PrismaUserAddressRepository.addressSelect,
        });

        if (!address) {
            throw new NotFoundException('Address not found');
        }

        return address;
    }
}
