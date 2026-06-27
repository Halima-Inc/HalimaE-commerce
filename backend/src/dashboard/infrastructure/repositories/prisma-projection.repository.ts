import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import {
    IDashboardProjectionRepository,
    PaidOrder,
    PaidOrderItem,
    SimpleOrder,
    UserOrder,
    ProductWithCategory,
    VariantInventoryWithVariant,
} from '../../application/services/projection-repository.interface';
import { ORDERSTATUS } from '@prisma/client';

@Injectable()
export class PrismaProjectionRepository
    implements IDashboardProjectionRepository
{
    constructor(private readonly prisma: PrismaService) {}

    async upsertRevenueSnapshot(
        date: Date,
        revenueDelta: number,
        ordersDelta = 0,
        itemsDelta = 0,
    ): Promise<void> {
        const day = new Date(date.toISOString().slice(0, 10));
        const existing = await this.prisma.dashboardRevenueSnapshot
            .findUnique({ where: { date: day } as any })
            .catch(() => null);
        if (existing) {
            await this.prisma.dashboardRevenueSnapshot.update({
                where: { id: existing.id },
                data: {
                    revenue: { increment: revenueDelta },
                    orders: { increment: ordersDelta },
                    itemsSold: { increment: itemsDelta },
                },
            });
        } else {
            await this.prisma.dashboardRevenueSnapshot.create({
                data: {
                    date: day,
                    revenue: revenueDelta,
                    orders: ordersDelta,
                    itemsSold: itemsDelta,
                },
            });
        }
    }

    async upsertOrdersByStatus(
        status: string,
        date: Date,
        delta: number,
    ): Promise<void> {
        const day = new Date(date.toISOString().slice(0, 10));
        const existing = await this.prisma.ordersByStatus.findFirst({
            where: { status: status as ORDERSTATUS, date: day },
        });
        if (existing) {
            await this.prisma.ordersByStatus.update({
                where: { id: existing.id },
                data: { count: { increment: delta } },
            });
        } else {
            await this.prisma.ordersByStatus.create({
                data: { status: status as any, date: day, count: delta },
            });
        }
    }

    async upsertBestSellingProduct(
        productId: string,
        periodStart: Date,
        periodEnd: Date,
        qtyDelta: number,
        revenueDelta: number,
    ): Promise<void> {
        const existing = await this.prisma.bestSellingProduct.findFirst({
            where: { productId, periodStart },
        } as any);
        if (existing) {
            await this.prisma.bestSellingProduct.update({
                where: { id: existing.id },
                data: {
                    qtySold: { increment: qtyDelta },
                    revenue: { increment: revenueDelta },
                },
            });
        } else {
            await this.prisma.bestSellingProduct.create({
                data: {
                    productId,
                    periodStart,
                    periodEnd,
                    qtySold: qtyDelta,
                    revenue: revenueDelta,
                },
            });
        }
    }

    async upsertLowStockProduct(
        variantId: string,
        productId: string,
        stockOnHand: number,
        lowStockThreshold: number,
    ): Promise<void> {
        const existing = await this.prisma.lowStockProduct
            .findUnique({ where: { variantId } as any })
            .catch(() => null);
        if (existing) {
            await this.prisma.lowStockProduct.update({
                where: { id: existing.id },
                data: { stockOnHand, lowStockThreshold },
            });
        } else {
            await this.prisma.lowStockProduct.create({
                data: { variantId, productId, stockOnHand, lowStockThreshold },
            });
        }
    }

    async upsertOrdersByLocation(
        location: string,
        date: Date,
        countDelta: number,
        revenueDelta: number,
    ): Promise<void> {
        const day = new Date(date.toISOString().slice(0, 10));
        const existing = await this.prisma.ordersByLocation.findFirst({
            where: { location, date: day },
        });
        if (existing) {
            await this.prisma.ordersByLocation.update({
                where: { id: existing.id },
                data: {
                    count: { increment: countDelta },
                    revenue: { increment: revenueDelta },
                },
            });
        } else {
            await this.prisma.ordersByLocation.create({
                data: {
                    location,
                    date: day,
                    count: countDelta,
                    revenue: revenueDelta,
                },
            });
        }
    }

    async upsertOrderStatistic(
        key: string,
        intValue?: number,
        decValue?: number,
        jsonValue?: any,
    ): Promise<void> {
        const existing = await this.prisma.orderStatistics
            .findUnique({ where: { key } as any })
            .catch(() => null);
        if (existing) {
            await this.prisma.orderStatistics.update({
                where: { id: existing.id },
                data: {
                    intValue: intValue ?? existing.intValue,
                    decValue: decValue ?? existing.decValue,
                    jsonValue: jsonValue ?? existing.jsonValue,
                },
            });
        } else {
            await this.prisma.orderStatistics.create({
                data: { key, intValue, decValue, jsonValue },
            });
        }
    }

    async upsertCustomerCounter(
        customerId: string,
        ordersDelta = 0,
        lifetimeValueDelta = 0,
    ): Promise<void> {
        const existing = await this.prisma.customerCounters
            .findUnique({ where: { customerId } as any })
            .catch(() => null);
        if (existing) {
            await this.prisma.customerCounters.update({
                where: { id: existing.id },
                data: {
                    orders: { increment: ordersDelta },
                    lifetimeValue: { increment: lifetimeValueDelta },
                },
            });
        } else {
            await this.prisma.customerCounters.create({
                data: {
                    customerId,
                    orders: ordersDelta,
                    lifetimeValue: lifetimeValueDelta,
                },
            });
        }
    }

    async upsertProductsByCategory(
        categoryId: string,
        periodStart: Date,
        periodEnd: Date,
        qtyDelta: number,
        revenueDelta: number,
    ): Promise<void> {
        const existing = await this.prisma.productsByCategory.findFirst({
            where: { categoryId, periodStart },
        } as any);
        if (existing) {
            await this.prisma.productsByCategory.update({
                where: { id: existing.id },
                data: {
                    qtySold: { increment: qtyDelta },
                    revenue: { increment: revenueDelta },
                },
            });
        } else {
            await this.prisma.productsByCategory.create({
                data: {
                    categoryId,
                    periodStart,
                    periodEnd,
                    qtySold: qtyDelta,
                    revenue: revenueDelta,
                },
            });
        }
    }

    // Read implementations
    async getRevenueSnapshot(
        date: Date,
    ): Promise<{ revenue: number; orders: number; itemsSold: number } | null> {
        const day = new Date(date.toISOString().slice(0, 10));
        const r = await this.prisma.dashboardRevenueSnapshot
            .findUnique({ where: { date: day } as any })
            .catch(() => null);
        if (!r) return null;
        return {
            revenue: Number(r.revenue),
            orders: r.orders,
            itemsSold: r.itemsSold,
        };
    }

    async getOrdersByStatus(date: Date): Promise<Record<string, number>> {
        const day = new Date(date.toISOString().slice(0, 10));
        const rows = await this.prisma.ordersByStatus.findMany({
            where: { date: day },
        });
        const out: Record<string, number> = {};
        for (const r of rows) out[String(r.status)] = r.count;
        return out;
    }

    async getBestSellingProducts(
        periodStart: Date,
        periodEnd: Date,
        limit = 10,
    ): Promise<
        Array<{
            productId: string;
            title?: string;
            qty: number;
            revenue: number;
        }>
    > {
        const rows = await this.prisma.bestSellingProduct.findMany({
            where: { periodStart, periodEnd },
            orderBy: { qtySold: 'desc' },
            take: limit,
        });
        return rows.map((r) => ({
            productId: r.productId,
            title: undefined,
            qty: r.qtySold,
            revenue: Number(r.revenue),
        }));
    }

    async getLowStockProducts(
        limit = 20,
    ): Promise<Array<{ productId: string; variantId: string; stock: number }>> {
        const rows = await this.prisma.lowStockProduct.findMany({
            orderBy: { updatedAt: 'desc' },
            take: limit,
        });
        return rows.map((r) => ({
            variantId: r.variantId,
            productId: r.productId,
            stock: r.stockOnHand,
        }));
    }

    async getOrdersByLocation(
        date: Date,
    ): Promise<Array<{ location: string; count: number; revenue: number }>> {
        const day = new Date(date.toISOString().slice(0, 10));
        const rows = await this.prisma.ordersByLocation.findMany({
            where: { date: day },
        });
        return rows.map((r) => ({
            location: r.location,
            count: r.count,
            revenue: Number(r.revenue),
        }));
    }

    async getOrderStatistic(key: string): Promise<{
        intValue?: number;
        decValue?: number;
        jsonValue?: any;
    } | null> {
        const r = await this.prisma.orderStatistics
            .findUnique({ where: { key } as any })
            .catch(() => null);
        if (!r) return null;
        return {
            intValue: r.intValue ?? undefined,
            decValue: r.decValue ? Number(r.decValue) : undefined,
            jsonValue: r.jsonValue ?? undefined,
        };
    }

    async getCustomerCounter(
        customerId: string,
    ): Promise<{ orders: number; lifetimeValue: number } | null> {
        const r = await this.prisma.customerCounters
            .findUnique({ where: { customerId } as any })
            .catch(() => null);
        if (!r) return null;
        return { orders: r.orders, lifetimeValue: Number(r.lifetimeValue) };
    }

    async getProductsByCategory(
        periodStart: Date,
        periodEnd: Date,
        limit = 10,
    ): Promise<Array<{ categoryId: string; qty: number; revenue: number }>> {
        const rows = await this.prisma.productsByCategory.findMany({
            where: { periodStart, periodEnd },
            orderBy: { qtySold: 'desc' },
            take: limit,
        });
        return rows.map((r) => ({
            categoryId: r.categoryId,
            qty: r.qtySold,
            revenue: Number(r.revenue),
        }));
    }

    async getPaidOrdersWithItems(): Promise<PaidOrder[]> {
        return (await this.prisma.order.findMany({
            where: { paymentStatus: 'PAID' },
            include: {
                items: true,
                shippingAddress: true,
            },
        })) as unknown as PaidOrder[];
    }

    async getPaidOrderItemsWithPrices(): Promise<PaidOrderItem[]> {
        return (await this.prisma.orderItem.findMany({
            where: { order: { paymentStatus: 'PAID' } },
            include: {
                variant: {
                    include: {
                        prices: true,
                    },
                },
            },
        })) as unknown as PaidOrderItem[];
    }

    async getTotalOrdersCount(): Promise<number> {
        return this.prisma.order.count();
    }

    async getOrdersTodayCount(todayStart: Date): Promise<number> {
        return this.prisma.order.count({
            where: { placedAt: { gte: todayStart } },
        });
    }

    async getAllOrdersStatus(): Promise<SimpleOrder[]> {
        return this.prisma.order.findMany({
            select: { status: true },
        });
    }

    async getAllOrdersUsers(): Promise<UserOrder[]> {
        return this.prisma.order.findMany({
            select: { userId: true },
        });
    }

    async getActiveProductsCount(): Promise<number> {
        return this.prisma.product.count({
            where: { status: 'ACTIVE' },
        });
    }

    async getActiveProductsWithCategory(): Promise<ProductWithCategory[]> {
        return this.prisma.product.findMany({
            where: { status: 'ACTIVE' },
            include: { category: true },
        });
    }

    async getTotalCustomersCount(): Promise<number> {
        return this.prisma.user.count({
            where: { role: { name: 'customer' } },
        });
    }

    async getLowStockInventories(
        limit: number,
    ): Promise<VariantInventoryWithVariant[]> {
        return this.prisma.variantInventory.findMany({
            where: {
                stockOnHand: {
                    lte: 10,
                },
            },
            include: {
                variant: true,
            },
            take: limit,
        });
    }
}

export default PrismaProjectionRepository;
