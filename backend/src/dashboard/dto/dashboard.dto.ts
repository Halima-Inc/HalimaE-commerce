import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

// Sub-DTOs for nested objects
export class SalesByPeriodDto {
    @ApiPropertyOptional({ description: 'Hourly sales breakdown', example: { '2025-12-04T10:00': 150.00 } })
    readonly hourly?: Record<string, number>;

    @ApiPropertyOptional({ description: 'Daily sales breakdown', example: { '2025-12-04': 1200.00 } })
    readonly daily?: Record<string, number>;

    @ApiPropertyOptional({ description: 'Weekly sales breakdown', example: { '2025-W49': 8500.00 } })
    readonly weekly?: Record<string, number>;

    @ApiPropertyOptional({ description: 'Monthly sales breakdown', example: { '2025-12': 35000.00 } })
    readonly monthly?: Record<string, number>;
}

export class PeakPeriodDto {
    @ApiProperty({ description: 'Time period identifier', example: '2025-12-01' })
    readonly period: string;

    @ApiProperty({ description: 'Revenue during this period', example: 5000.00 })
    readonly revenue: number;
}

export class OrdersByLocationDto {
    @ApiProperty({ description: 'Country name', example: 'Egypt' })
    readonly country: string;

    @ApiProperty({ description: 'Total number of orders from this location', example: 150 })
    readonly totalOrders: number;

    @ApiProperty({ description: 'Total revenue from this location', example: 25000.00 })
    readonly revenue: number;
}

export class BestSellingProductDto {
    @ApiProperty({ description: 'Product ID', example: '550e8400-e29b-41d4-a716-446655440000' })
    readonly productId: string;

    @ApiPropertyOptional({ description: 'Product title', example: 'Premium Hijab - Black' })
    readonly title?: string;

    @ApiProperty({ description: 'Total quantity sold', example: 250 })
    readonly qty: number;

    @ApiProperty({ description: 'Total revenue generated', example: 12500.00 })
    readonly revenue: number;
}

export class LowStockProductDto {
    @ApiProperty({ description: 'Product ID', example: '550e8400-e29b-41d4-a716-446655440000' })
    readonly productId: string;

    @ApiProperty({ description: 'Current stock level', example: 5 })
    readonly stock: number;
}

export class DashboardDto {
    // Revenue Metrics
    @ApiProperty({ description: 'Total net revenue after discounts', example: 150000.00 })
    readonly totalRevenue: number;

    @ApiProperty({ description: 'Gross revenue before discounts', example: 175000.00 })
    readonly grossRevenue: number;

    @ApiProperty({ description: 'Total discounts applied', example: 25000.00 })
    readonly totalDiscounts: number;

    @ApiProperty({ description: 'Average discount percentage', example: 14.28 })
    readonly avgDiscountPct: number;

    @ApiProperty({ description: 'Revenue breakdown by currency', example: { 'EGP': 120000.00, 'USD': 30000.00 } })
    readonly revenueByCurrency: Record<string, number>;

    @ApiProperty({ description: 'Sales breakdown by time periods', type: SalesByPeriodDto })
    readonly salesByPeriod: SalesByPeriodDto;

    @ApiProperty({ description: 'Peak revenue periods', type: [PeakPeriodDto] })
    readonly peakPeriods: PeakPeriodDto[];

    @ApiProperty({ description: 'Seasonal trend analysis', example: { 'Q4': 'high', 'Q1': 'low' } })
    readonly seasonalTrends: any;

    // Location Metrics
    @ApiProperty({ description: 'Orders grouped by location/country', type: [OrdersByLocationDto] })
    readonly ordersByLocation: OrdersByLocationDto[];

    @ApiProperty({ description: 'Top performing regions', example: [{ region: 'Cairo', revenue: 50000 }] })
    readonly topRegions: any[];

    @ApiProperty({ description: 'Year-over-year comparison data', example: { 'growthRate': 15.5, 'lastYear': 130000 } })
    readonly yoyComparison: any;

    // Order Metrics
    @ApiProperty({ description: 'Total number of orders', example: 1250 })
    readonly totalOrders: number;

    @ApiProperty({ description: 'Orders grouped by status', example: { 'PENDING': 50, 'CONFIRMED': 200, 'DELIVERED': 1000 } })
    readonly ordersByStatus: Record<string, number>;

    @ApiProperty({ description: 'Number of orders placed today', example: 25 })
    readonly ordersToday: number;

    @ApiProperty({ description: 'Average number of items per order', example: 3.5 })
    readonly averageItemsPerOrder: number;

    @ApiProperty({ description: 'Average Order Value (AOV)', example: 120.00 })
    readonly aov: number;

    // Customer Metrics
    @ApiProperty({ description: 'Total number of registered customers', example: 850 })
    readonly totalCustomers: number;

    @ApiProperty({ description: 'New customer registrations by day', example: { '2025-12-01': 15, '2025-12-02': 20 } })
    readonly newCustomersByDay: Record<string, number>;

    @ApiProperty({ description: 'Percentage of customers who made repeat purchases', example: 35.5 })
    readonly repeatCustomerRate: number;

    // Product Metrics
    @ApiProperty({ description: 'Total number of products', example: 500 })
    readonly totalProducts: number;

    @ApiProperty({ description: 'Products grouped by category', example: { 'Hijabs': 150, 'Abayas': 100 } })
    readonly productsByCategory: Record<string, number>;

    @ApiProperty({ description: 'Best selling products by quantity and revenue', type: [BestSellingProductDto] })
    readonly bestSellingProducts: BestSellingProductDto[];

      // Inventory Metrics
    @ApiProperty({ description: 'Products with low stock levels', type: [LowStockProductDto] })
    readonly lowStockProducts: LowStockProductDto[];
}
