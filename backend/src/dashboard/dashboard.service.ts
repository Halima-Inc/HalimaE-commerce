import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { LogService } from '../logger/log.service';
import { DashboardDto } from './dto';
import { Prisma } from '@prisma/client';

@Injectable()
export class DashboardService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly logger: LogService,
    ) {}

    async computeDashboardMetrics(): Promise<DashboardDto> {
        this.logger.debug('Computing dashboard metrics...', DashboardService.name);

        const now          = new Date();
        const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const startOfWeek  = new Date(startOfToday);

        startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());

        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const startOfYear  = new Date(now.getFullYear(), 0, 1);
        const lastYear     = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate());

        const [
            revenueData,
            orderStats,
            customerStats,
            productStats,
            inventoryStats,
            categoryStats,
        ] = await Promise.all([
            this.computeRevenueMetrics(startOfToday, startOfWeek, startOfMonth, startOfYear, lastYear),
            this.computeOrderMetrics(startOfToday),
            this.computeCustomerMetrics(startOfToday),
            this.computeProductMetrics(),
            this.computeInventoryMetrics(),
            this.computeCategoryMetrics(),
        ]);

        return {
            // Revenue metrics
            totalRevenue     : revenueData.totalRevenue,
            grossRevenue     : revenueData.grossRevenue,
            totalDiscounts   : revenueData.totalDiscounts,
            avgDiscountPct   : revenueData.avgDiscountPct,
            revenueByCurrency: revenueData.revenueByCurrency,
            salesByPeriod    : revenueData.salesByPeriod,
            peakPeriods      : revenueData.peakPeriods,
            seasonalTrends   : revenueData.seasonalTrends,
            yoyComparison    : revenueData.yoyComparison,

              // Location metrics
            ordersByLocation: revenueData.ordersByLocation,
            topRegions      : revenueData.topRegions,

              // Order metrics
            totalOrders         : orderStats.totalOrders,
            ordersByStatus      : orderStats.ordersByStatus,
            ordersToday         : orderStats.ordersToday,
            averageItemsPerOrder: orderStats.averageItemsPerOrder,
            aov                 : orderStats.aov,

              // Customer metrics
            totalCustomers    : customerStats.totalCustomers,
            newCustomersByDay : customerStats.newCustomersByDay,
            repeatCustomerRate: customerStats.repeatCustomerRate,

              // Product metrics
            totalProducts      : productStats.totalProducts,
            productsByCategory : categoryStats.productsByCategory,
            bestSellingProducts: productStats.bestSellingProducts,

              // Inventory metrics
            lowStockProducts: inventoryStats.lowStockProducts,
        };
    }

    private async computeRevenueMetrics(
        startOfToday: Date,
        startOfWeek : Date,
        startOfMonth: Date,
        startOfYear : Date,
        lastYear    : Date,
    ) {
        // Get all completed orders with items
        const orders = await this.prisma.order.findMany({
            where: {
                paymentStatus: 'PAID',
                deletedAt    : null,
            },
            include: {
                items: {
                    include: {
                        variant: {
                            include: {
                                prices: true,
                            },
                        },
                    },
                },
                shippingAddress: true,
            },
        });

        let totalRevenue   = 0;
        let grossRevenue   = 0;
        let totalDiscounts = 0;
        let discountCount  = 0;
        let thisYearRevenue = 0;
        const revenueByCurrency: Record<string, number>  = {};
        const salesByHour      : Record<string, number>  = {};
        const salesByDay       : Record<string, number>  = {};
        const salesByWeek      : Record<string, number>  = {};
        const salesByMonth     : Record<string, number>  = {};
        const ordersByCountry  : Record<
            string, {
                totalOrders: number; revenue: number
            }
        > = {};

        for (const order of orders) {
            let orderTotal = 0;
            let orderGross = 0;

            for (const item of order.items) {
                const itemTotal = Number(item.unitPrice) * item.qty;
                orderTotal += itemTotal;

                // Calculate gross and discounts from variant prices
                const price = item.variant.prices.find(p => p.currency === order.currency);
                if (price) {
                    const compareAt = price.compareAt ? Number(price.compareAt) : Number(price.amount);
                    orderGross += compareAt * item.qty;
                    if (price.compareAt && Number(price.compareAt) > Number(price.amount)) {
                        totalDiscounts += (Number(price.compareAt) - Number(price.amount)) * item.qty;
                        discountCount++;
                    }
                }
            }

            totalRevenue += orderTotal;
            grossRevenue += orderGross;

            // Revenue by currency
            revenueByCurrency[order.currency] = (revenueByCurrency[order.currency] || 0) + orderTotal;

            // Sales by period
            const placedAt = new Date(order.placedAt);

            if (placedAt >= startOfYear) {
                thisYearRevenue += orderTotal;
            }
            const hourKey  = `${placedAt.toISOString().slice(0, 13)}:00`;
            const dayKey   = placedAt.toISOString().slice(0, 10);
            const weekKey  = this.getWeekKey(placedAt);
            const monthKey = placedAt.toISOString().slice(0, 7);

            salesByHour[hourKey]   = (salesByHour[hourKey] || 0) + orderTotal;
            salesByDay[dayKey]     = (salesByDay[dayKey] || 0) + orderTotal;
            salesByWeek[weekKey]   = (salesByWeek[weekKey] || 0) + orderTotal;
            salesByMonth[monthKey] = (salesByMonth[monthKey] || 0) + orderTotal;

            // Orders by location
            const country = order.shippingAddress.country;
            if (!ordersByCountry[country]) {
                ordersByCountry[country] = { totalOrders: 0, revenue: 0 };
            }
            ordersByCountry[country].totalOrders++;
            ordersByCountry[country].revenue += orderTotal;
        }

        // Calculate average discount percentage
        const avgDiscountPct = grossRevenue > 0 ? (totalDiscounts / grossRevenue) * 100 : 0;

        // Peak periods (top 5 days by revenue)
        const peakPeriods = Object.entries(salesByDay)
            .map(([period, revenue]) => ({ period, revenue }))
            .sort((a, b) => b.revenue - a.revenue)
            .slice(0, 5);

        // Orders by location array
        const ordersByLocation = Object.entries(ordersByCountry)
            .map(([country, data]) => ({
                country,
                totalOrders: data.totalOrders,
                revenue: data.revenue,
            }))
            .sort((a, b) => b.revenue - a.revenue);

        // Top regions
        const topRegions = ordersByLocation.slice(0, 5);

        // Year-over-year comparison (thisYearRevenue already calculated in the loop above)
        const lastYearOrders = await this.prisma.order.findMany({
            where: {
                paymentStatus: 'PAID',
                deletedAt    : null,
                placedAt     : {
                    gte: new Date(lastYear.getFullYear(), 0, 1),
                    lt : startOfYear,
                },
            },
            include: { items: true },
        });

        const lastYearRevenue = lastYearOrders.reduce(
            (sum, o) => sum + o.items.reduce((s, i) => s + Number(i.unitPrice) * i.qty, 0),
            0,
        );

        const yoyComparison = {
            thisYear  : thisYearRevenue,
            lastYear  : lastYearRevenue,
            growthRate: lastYearRevenue > 0 ? ((thisYearRevenue - lastYearRevenue) / lastYearRevenue) * 100: 0,
        };

        // Seasonal trends (monthly averages)
        const seasonalTrends = Object.entries(salesByMonth).reduce(
            (acc, [month, revenue]) => {
                const monthNum = parseInt(month.slice(5, 7));
                acc[monthNum] = (acc[monthNum] || 0) + revenue;
                return acc;
            },
            {} as Record<number, number>,
        );

        return {
            totalRevenue,
            grossRevenue,
            totalDiscounts,
            avgDiscountPct,
            revenueByCurrency,
            salesByPeriod: {
                hourly : salesByHour,
                daily  : salesByDay,
                weekly : salesByWeek,
                monthly: salesByMonth,
            },
            peakPeriods,
            seasonalTrends,
            ordersByLocation,
            topRegions,
            yoyComparison,
        };
    }

    private async computeOrderMetrics(startOfToday: Date) {
        const [totalOrders, ordersToday, ordersByStatusRaw, orderItemsAgg] = await Promise.all([
            this.prisma.order.count({ where: { deletedAt: null } }),
            this.prisma.order.count({
                where: { deletedAt: null, placedAt: { gte: startOfToday } },
            }),
            this.prisma.order.groupBy({
                by    : ['status'],
                _count: true,
                where : { deletedAt: null },
            }),
            this.prisma.orderItem.aggregate({
                _sum  : { qty: true },
                _count: true,
            }),
        ]);

        const ordersByStatus = ordersByStatusRaw.reduce(
            (acc, item) => {
                acc[item.status] = item._count;
                return acc;
            },
            {} as Record<string, number>,
        );

        // Average items per order
        const averageItemsPerOrder = totalOrders > 0 ? (orderItemsAgg._sum.qty || 0) / totalOrders : 0;

        // Average order value
        const revenueAgg = await this.prisma.orderItem.aggregate({
            _sum: { qty: true },
            where: { order: { paymentStatus: 'PAID', deletedAt: null } },
        });

        const paidOrders = await this.prisma.order.count({
            where: { paymentStatus: 'PAID', deletedAt: null },
        });

        const totalPaidRevenue = await this.prisma.orderItem.findMany({
            where: { order: { paymentStatus: 'PAID', deletedAt: null } },
            select: { unitPrice: true, qty: true },
        });

        const totalRevenueSum = totalPaidRevenue.reduce(
            (sum, item) => sum + Number(item.unitPrice) * item.qty,
            0,
        );

        const aov = paidOrders > 0 ? totalRevenueSum / paidOrders : 0;

        return {
            totalOrders,
            ordersToday,
            ordersByStatus,
            averageItemsPerOrder,
            aov,
        };
    }

    private async computeCustomerMetrics(startOfToday: Date) {
        const thirtyDaysAgo = new Date(startOfToday);
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const [totalCustomers, newCustomersRaw, repeatCustomers] = await Promise.all([
            this.prisma.customer.count(),
            this.prisma.customer.groupBy({
                by    : ['createdAt'],
                _count: true,
                where : { createdAt: { gte: thirtyDaysAgo } },
            }),
            this.prisma.order.groupBy({
                by    : ['customerId'],
                _count: true,
                having: { customerId: { _count: { gt: 1 } } },
            }),
        ]);

        // New customers by day
        const newCustomersByDay: Record<string, number> = {};
        for (const row of newCustomersRaw) {
            const dayKey = new Date(row.createdAt).toISOString().slice(0, 10);
            newCustomersByDay[dayKey] = (newCustomersByDay[dayKey] || 0) + row._count;
        }

        // Repeat customer rate
        const customersWithOrders = await this.prisma.order.groupBy({
            by: ['customerId'],
            _count: true,
        });

        const repeatCustomerRate =
            customersWithOrders.length > 0
                ? (repeatCustomers.length / customersWithOrders.length) * 100
                : 0;

        return {
            totalCustomers,
            newCustomersByDay,
            repeatCustomerRate,
        };
    }

    private async computeProductMetrics() {
        const [totalProducts, bestSellingRaw] = await Promise.all([
            this.prisma.product.count({ where: { deletedAt: null } }),
            this.prisma.orderItem.groupBy({
                by: ['variantId'],
                _sum: { qty: true },
                orderBy: { _sum: { qty: 'desc' } },
                take: 10,
            }),
        ]);

        // Get product details for best selling
        const variantIds = bestSellingRaw.map(r => r.variantId);
        const variants = await this.prisma.productVariant.findMany({
            where: { id: { in: variantIds } },
            include: {
                product: { select: { id: true, name: true } },
                prices: true,
            },
        });

        const bestSellingProducts = bestSellingRaw.map(row => {
            const variant = variants.find(v => v.id === row.variantId);
            const qty     = row._sum.qty || 0;
            const price   = variant?.prices[0];
            const revenue = price ? Number(price.amount) * qty : 0;

            return {
                productId: variant?.productId || row.variantId,
                title    : variant?.product.name,
                qty,
                revenue,
            };
        });

        return {
            totalProducts,
            bestSellingProducts,
        };
    }

    private async computeInventoryMetrics() {
        // Fetch all inventory and filter manually since Prisma doesn't support field-to-field comparison
        const allInventory = await this.prisma.variantInventory.findMany({
            select: {
                variantId        : true,
                stockOnHand      : true,
                lowStockThreshold: true,
            },
        });

        const lowStock = allInventory
            .filter(inv => inv.stockOnHand <= (inv.lowStockThreshold ?? 10))
            .map(inv => ({
                productId: inv.variantId,
                stock    : inv.stockOnHand,
            }))
            .slice(0, 20);

        return {
            lowStockProducts: lowStock,
        };
    }

    private async computeCategoryMetrics() {
        const productsByCategory = await this.prisma.product.groupBy({
            by    : ['categoryId'],
            _count: true,
            where : { deletedAt: null },
        });

        const categoryIds = productsByCategory.map(p => p.categoryId);
        const categories = await this.prisma.category.findMany({
            where : { id: { in: categoryIds } },
            select: { id: true, name: true },
        });

        const productsByCategoryMap: Record<string, number> = {};
        for (const row of productsByCategory) {
            const category = categories.find(c => c.id === row.categoryId);
            const name = category?.name || row.categoryId;
            productsByCategoryMap[name] = row._count;
        }

        return {
            productsByCategory: productsByCategoryMap,
        };
    }

    private getWeekKey(date: Date): string {
        const startOfYear = new Date(date.getFullYear(), 0, 1);
        const days        = Math.floor((date.getTime() - startOfYear.getTime()) / (24 * 60 * 60 * 1000));
        const weekNum     = Math.ceil((days + startOfYear.getDay() + 1) / 7);
        return `${date.getFullYear()}-W${weekNum.toString().padStart(2, '0')}`;
    }
}
