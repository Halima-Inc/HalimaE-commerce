import {
    ConflictException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { LogService } from '../../../common/log.service';
import type {
    IUserProfileRepository,
    SortOrder,
    UpdateUserProfileInput,
    UserListResponse,
    UserSortField,
} from '../../domain';

@Injectable()
export class PrismaUserProfileRepository implements IUserProfileRepository {
    private static readonly DEFAULT_LIMIT = 10;
    private static readonly MAX_LIMIT = 100;

    constructor(
        private readonly prisma: PrismaService,
        private readonly logger: LogService,
    ) {}

    async findById(userId: string): Promise<{
        id: string;
        name: string;
        email: string;
        phone: string | null;
        createdAt?: Date;
    } | null> {
        return this.prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                name: true,
                email: true,
                phone: true,
                createdAt: true,
            },
        });
    }

    async update(
        userId: string,
        data: UpdateUserProfileInput,
    ): Promise<{
        id: string;
        name: string;
        email: string;
        phone: string | null;
    }> {
        if (data.email) {
            const existingUser = await this.prisma.user.findFirst({
                where: {
                    email: data.email,
                    NOT: { id: userId },
                },
                select: { id: true },
            });

            if (existingUser) {
                throw new ConflictException('Email already exists');
            }
        }

        try {
            return await this.prisma.user.update({
                where: { id: userId },
                data: {
                    ...data,
                },
                select: {
                    id: true,
                    name: true,
                    email: true,
                    phone: true,
                },
            });
        } catch (error: unknown) {
            if (
                error &&
                typeof error === 'object' &&
                'code' in error &&
                error.code === 'P2025'
            ) {
                throw new NotFoundException('User not found');
            }

            const stack =
                error instanceof Error ? error.stack : JSON.stringify(error);
            this.logger.error(
                `Failed to update user ${userId}`,
                stack,
                PrismaUserProfileRepository.name,
            );
            throw error;
        }
    }

    async findAll(
        page = 1,
        limit = 10,
        search = '',
        sort: UserSortField = 'name',
        order: SortOrder = 'asc',
    ): Promise<UserListResponse> {
        const safePage = Number.isFinite(page) && page > 0 ? page : 1;
        const safeLimit =
            Number.isFinite(limit) && limit > 0
                ? Math.min(limit, PrismaUserProfileRepository.MAX_LIMIT)
                : PrismaUserProfileRepository.DEFAULT_LIMIT;

        const skip = (safePage - 1) * safeLimit;

        if (sort === 'totalSpent' || sort === 'orderCount') {
            return this.findAllWithPurchaseStats(
                search,
                skip,
                safeLimit,
                sort,
                order,
            );
        }

        const where: Prisma.UserWhereInput = {
            role: { name: 'customer' },
        };

        if (search) {
            where.OR = [
                { name: { contains: search, mode: 'insensitive' } },
                { email: { contains: search, mode: 'insensitive' } },
            ];
        }

        const [total, users] = await this.prisma.$transaction([
            this.prisma.user.count({ where }),
            this.prisma.user.findMany({
                where,
                take: safeLimit,
                skip,
                orderBy: {
                    [sort]: order,
                },
                select: {
                    id: true,
                    name: true,
                    email: true,
                    phone: true,
                    createdAt: true,
                },
            }),
        ]);

        return {
            data: users,
            meta: {
                total,
                totalPages: Math.ceil(total / safeLimit),
            },
        };
    }

    private async findAllWithPurchaseStats(
        search: string,
        skip: number,
        limit: number,
        sort: 'totalSpent' | 'orderCount',
        order: 'asc' | 'desc',
    ): Promise<UserListResponse> {
        const sortColumn =
            sort === 'totalSpent' ? 'total_spent' : 'order_count';
        const orderDirection = order === 'desc' ? 'DESC' : 'ASC';
        const searchPattern = search ? `%${search}%` : null;

        const usersWithStats = search
            ? await this.prisma.$queryRaw<
                  Array<{
                      id: string;
                      name: string;
                      email: string;
                      phone: string | null;
                      created_at: Date;
                      total_spent: number;
                      order_count: number;
                  }>
              >`
            SELECT
                u.id,
                u.name,
                u.email,
                u.phone,
                u."createdAt" as created_at,
                COALESCE(SUM(oi."unitPrice" * oi.qty), 0)::numeric as total_spent,
                COUNT(DISTINCT o.id)::integer as order_count
            FROM users u
            LEFT JOIN roles r ON r.id = u."roleId"
            LEFT JOIN orders o ON o."userId" = u.id AND o."paymentStatus" = 'PAID' AND o."deletedAt" IS NULL
            LEFT JOIN order_items oi ON oi."orderId" = o.id
            WHERE r.name = 'customer' AND (u.name ILIKE ${searchPattern} OR u.email ILIKE ${searchPattern})
            GROUP BY u.id, u.name, u.email, u.phone, u."createdAt"
            ORDER BY ${Prisma.raw(sortColumn)} ${Prisma.raw(orderDirection)}
            LIMIT ${limit}
            OFFSET ${skip}
          `
            : await this.prisma.$queryRaw<
                  Array<{
                      id: string;
                      name: string;
                      email: string;
                      phone: string | null;
                      created_at: Date;
                      total_spent: number;
                      order_count: number;
                  }>
              >`
            SELECT
                u.id,
                u.name,
                u.email,
                u.phone,
                u."createdAt" as created_at,
                COALESCE(SUM(oi."unitPrice" * oi.qty), 0)::numeric as total_spent,
                COUNT(DISTINCT o.id)::integer as order_count
            FROM users u
            LEFT JOIN roles r ON r.id = u."roleId"
            LEFT JOIN orders o ON o."userId" = u.id AND o."paymentStatus" = 'PAID' AND o."deletedAt" IS NULL
            LEFT JOIN order_items oi ON oi."orderId" = o.id
            WHERE r.name = 'customer'
            GROUP BY u.id, u.name, u.email, u.phone, u."createdAt"
            ORDER BY ${Prisma.raw(sortColumn)} ${Prisma.raw(orderDirection)}
            LIMIT ${limit}
            OFFSET ${skip}
          `;

        const countResult = search
            ? await this.prisma.$queryRaw<[{ count: bigint }]>`
                SELECT COUNT(*) as count
                FROM users u
                LEFT JOIN roles r ON r.id = u."roleId"
                WHERE r.name = 'customer' AND (u.name ILIKE ${searchPattern} OR u.email ILIKE ${searchPattern})
              `
            : await this.prisma.$queryRaw<[{ count: bigint }]>`
                SELECT COUNT(*) as count
                FROM users u
                LEFT JOIN roles r ON r.id = u."roleId"
                WHERE r.name = 'customer'
              `;

        const total = Number(countResult[0].count);

        return {
            data: usersWithStats.map((u) => ({
                id: u.id,
                name: u.name,
                email: u.email,
                phone: u.phone,
                createdAt: u.created_at,
                totalSpent: Number(u.total_spent),
                orderCount: u.order_count,
            })),
            meta: {
                total,
                totalPages: Math.ceil(total / limit),
            },
        };
    }
}
