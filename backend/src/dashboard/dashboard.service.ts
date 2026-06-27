import { Inject, Injectable } from '@nestjs/common';
import { LogService } from '../common/log.service';
import { DashboardDto } from './dto';
import type IDashboardProjectionRepository from './application/services/projection-repository.interface';
import { DASHBOARD_PROJECTION_REPOSITORY } from './dashboard.tokens';

@Injectable()
export class DashboardService {
    constructor(
        @Inject(DASHBOARD_PROJECTION_REPOSITORY)
        private readonly projections: IDashboardProjectionRepository,
        private readonly logger: LogService,
    ) {}

    async computeDashboardMetrics(): Promise<DashboardDto> {
        this.logger.debug(
            'Computing dashboard metrics from projections and database...',
            DashboardService.name,
        );

        const today = new Date();
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);

        // Fetch projections
        const [
            revSnapshot,
            ordersByStatusProj,
            bestSelling,
            lowStock,
            ordersByLocationProj,
        ] = await Promise.all([
            this.projections.getRevenueSnapshot(today),
            this.projections.getOrdersByStatus(today),
            this.projections.getBestSellingProducts(
                new Date(today.getFullYear(), today.getMonth(), 1),
                today,
            ),
            this.projections.getLowStockProducts(20),
            this.projections.getOrdersByLocation(today),
        ]);

        // Fallbacks/Dynamic Calculations from DB for full metrics coverage
        const paidOrders = await this.projections.getPaidOrdersWithItems();

        let dbRevenue = 0;
        const revenueByCurrency: Record<string, number> = {};
        for (const o of paidOrders) {
            const orderTotal = o.items.reduce(
                (sum: number, item) => sum + Number(item.unitPrice) * item.qty,
                0,
            );
            dbRevenue += orderTotal;
            revenueByCurrency[o.currency] =
                (revenueByCurrency[o.currency] || 0) + orderTotal;
        }
        const totalRevenue = revSnapshot
            ? Number(revSnapshot.revenue)
            : dbRevenue;

        // Calculate discounts and average discount percentage
        const orderItems = await this.projections.getPaidOrderItemsWithPrices();

        let totalDiscounts = 0;
        let totalOriginalPrice = 0;
        for (const item of orderItems) {
            const price =
                item.variant.prices.find((p) => p.currency === 'EGP') ||
                item.variant.prices[0];
            const compareAt = price?.compareAt
                ? Number(price.compareAt)
                : Number(item.unitPrice);
            const unitPrice = Number(item.unitPrice);
            const discount = Math.max(0, compareAt - unitPrice) * item.qty;
            totalDiscounts += discount;
            totalOriginalPrice += compareAt * item.qty;
        }
        const avgDiscountPct =
            totalOriginalPrice > 0
                ? (totalDiscounts / totalOriginalPrice) * 100
                : 0;
        const grossRevenue = totalRevenue + totalDiscounts;

        // Count total orders and orders today
        const totalOrders = await this.projections.getTotalOrdersCount();
        const ordersToday =
            await this.projections.getOrdersTodayCount(todayStart);

        // Group orders by status
        const allOrdersForStatus = await this.projections.getAllOrdersStatus();
        const dbOrdersByStatus: Record<string, number> = {};
        for (const o of allOrdersForStatus) {
            dbOrdersByStatus[o.status] = (dbOrdersByStatus[o.status] || 0) + 1;
        }
        const ordersByStatus =
            Object.keys(ordersByStatusProj).length > 0
                ? ordersByStatusProj
                : dbOrdersByStatus;

        // AOV (Average Order Value)
        const aov = totalOrders > 0 ? totalRevenue / totalOrders : 0;

        // Count total customers (users with customer role)
        const totalCustomers = await this.projections.getTotalCustomersCount();

        // Repeat customer rate
        const allOrdersForUsers = await this.projections.getAllOrdersUsers();
        const userOrderCounts: Record<string, number> = {};
        for (const o of allOrdersForUsers) {
            userOrderCounts[o.userId] = (userOrderCounts[o.userId] || 0) + 1;
        }
        const userIds = Object.keys(userOrderCounts);
        const totalWithOrders = userIds.length;
        const repeats = userIds.filter(
            (uid) => userOrderCounts[uid] > 1,
        ).length;
        const repeatCustomerRate =
            totalWithOrders > 0 ? (repeats / totalWithOrders) * 100 : 0;

        // Count total active products
        const totalProducts = await this.projections.getActiveProductsCount();

        // Group products by category
        const products = await this.projections.getActiveProductsWithCategory();
        const productsByCategory: Record<string, number> = {};
        for (const p of products) {
            if (p.category) {
                productsByCategory[p.category.name] =
                    (productsByCategory[p.category.name] || 0) + 1;
            }
        }

        // Sales by period (daily)
        const daily: Record<string, number> = {};
        const orders = await this.projections.getPaidOrdersWithItems();
        for (const o of orders) {
            const dateStr = o.placedAt.toISOString().split('T')[0];
            const orderTotal = o.items.reduce(
                (sum: number, item) => sum + Number(item.unitPrice) * item.qty,
                0,
            );
            daily[dateStr] = (daily[dateStr] || 0) + orderTotal;
        }
        const salesByPeriod = { hourly: {}, daily, weekly: {}, monthly: {} };

        // Group orders by location dynamically
        const paidOrdersForLocation =
            await this.projections.getPaidOrdersWithItems();
        const locationStats: Record<
            string,
            { count: number; revenue: number }
        > = {};
        for (const o of paidOrdersForLocation) {
            const country = o.shippingAddress?.country || 'Egypt';
            if (!locationStats[country]) {
                locationStats[country] = { count: 0, revenue: 0 };
            }
            locationStats[country].count++;
            locationStats[country].revenue += o.items.reduce(
                (sum: number, item) => sum + Number(item.unitPrice) * item.qty,
                0,
            );
        }
        const dbOrdersByLocation = Object.entries(locationStats).map(
            ([country, stats]) => ({
                location: country,
                country: country,
                count: stats.count,
                revenue: stats.revenue,
            }),
        );
        if (dbOrdersByLocation.length === 0) {
            dbOrdersByLocation.push({
                location: 'Egypt',
                country: 'Egypt',
                count: totalOrders,
                revenue: totalRevenue,
            });
        }
        const ordersByLocation =
            ordersByLocationProj.length > 0
                ? ordersByLocationProj.map((loc) => ({
                      location: loc.location,
                      country: loc.location,
                      count: loc.count,
                      revenue: loc.revenue,
                  }))
                : dbOrdersByLocation;

        // Compute best-selling products dynamically
        const productSales: Record<string, { qty: number; revenue: number }> =
            {};
        for (const item of orderItems) {
            const pId = item.variant.productId;
            if (!productSales[pId]) {
                productSales[pId] = { qty: 0, revenue: 0 };
            }
            productSales[pId].qty += item.qty;
            productSales[pId].revenue += Number(item.unitPrice) * item.qty;
        }
        const dynamicBestSelling = Object.entries(productSales)
            .map(([productId, sales]) => ({
                productId,
                qty: sales.qty,
                revenue: sales.revenue,
            }))
            .sort((a, b) => b.qty - a.qty)
            .slice(0, 10);
        const finalBestSelling =
            bestSelling.length > 0 ? bestSelling : dynamicBestSelling;

        // Compute low-stock products dynamically
        const lowStockInventories =
            await this.projections.getLowStockInventories(20);
        const dynamicLowStock = lowStockInventories.map((inv) => ({
            productId: inv.variant.productId,
            variantId: inv.variantId,
            stock: inv.stockOnHand,
        }));
        const finalLowStock = lowStock.length > 0 ? lowStock : dynamicLowStock;

        return {
            totalRevenue,
            grossRevenue,
            totalDiscounts,
            avgDiscountPct,
            revenueByCurrency,
            salesByPeriod,
            peakPeriods: [],
            seasonalTrends: {},
            yoyComparison: {
                thisYear: totalRevenue,
                lastYear: 0,
                growthRate: 0,
            },
            ordersByLocation,
            topRegions: ordersByLocation.slice(0, 5),
            totalOrders,
            ordersByStatus,
            ordersToday,
            averageItemsPerOrder: orderItems.length / (totalOrders || 1),
            aov,
            totalCustomers,
            newCustomersByDay: {},
            repeatCustomerRate,
            totalProducts,
            productsByCategory,
            bestSellingProducts: finalBestSelling,
            lowStockProducts: finalLowStock,
        } as DashboardDto;
    }
}
