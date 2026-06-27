export interface PaidOrderItem {
    id: string;
    orderId: string;
    variantId: string;
    qty: number;
    unitPrice: any;
    variant: {
        id: string;
        productId: string;
        prices: Array<{
            id: string;
            currency: string;
            amount: any;
            compareAt: any;
        }>;
    };
}

export interface PaidOrder {
    id: string;
    orderNo: string;
    userId: string;
    currency: string;
    status: string;
    paymentStatus: string;
    placedAt: Date;
    items: Array<{
        id: string;
        orderId: string;
        variantId: string;
        qty: number;
        unitPrice: any;
    }>;
    shippingAddress?: {
        id: string;
        userId: string;
        country: string;
    } | null;
}

export interface SimpleOrder {
    status: string;
}

export interface UserOrder {
    userId: string;
}

export interface ProductWithCategory {
    id: string;
    name: string;
    slug: string;
    status: string;
    category?: {
        id: string;
        name: string;
    } | null;
}

export interface VariantInventoryWithVariant {
    id: string;
    variantId: string;
    stockOnHand: number;
    variant: {
        id: string;
        productId: string;
    };
}

export interface IDashboardProjectionRepository {
    upsertRevenueSnapshot(
        date: Date,
        revenueDelta: number,
        ordersDelta?: number,
        itemsDelta?: number,
    ): Promise<void>;
    upsertOrdersByStatus(
        status: string,
        date: Date,
        delta: number,
    ): Promise<void>;
    upsertBestSellingProduct(
        productId: string,
        periodStart: Date,
        periodEnd: Date,
        qtyDelta: number,
        revenueDelta: number,
    ): Promise<void>;
    upsertLowStockProduct(
        variantId: string,
        productId: string,
        stockOnHand: number,
        lowStockThreshold: number,
    ): Promise<void>;
    upsertOrdersByLocation(
        location: string,
        date: Date,
        countDelta: number,
        revenueDelta: number,
    ): Promise<void>;
    upsertOrderStatistic(
        key: string,
        intValue?: number,
        decValue?: number,
        jsonValue?: any,
    ): Promise<void>;
    upsertCustomerCounter(
        customerId: string,
        ordersDelta?: number,
        lifetimeValueDelta?: number,
    ): Promise<void>;
    upsertProductsByCategory(
        categoryId: string,
        periodStart: Date,
        periodEnd: Date,
        qtyDelta: number,
        revenueDelta: number,
    ): Promise<void>;
    // Read methods for projections
    getRevenueSnapshot(
        date: Date,
    ): Promise<{ revenue: number; orders: number; itemsSold: number } | null>;
    getOrdersByStatus(date: Date): Promise<Record<string, number>>;
    getBestSellingProducts(
        periodStart: Date,
        periodEnd: Date,
        limit?: number,
    ): Promise<
        Array<{
            productId: string;
            title?: string;
            qty: number;
            revenue: number;
        }>
    >;
    getLowStockProducts(
        limit?: number,
    ): Promise<Array<{ productId: string; variantId: string; stock: number }>>;
    getOrdersByLocation(
        date: Date,
    ): Promise<Array<{ location: string; count: number; revenue: number }>>;
    getOrderStatistic(key: string): Promise<{
        intValue?: number;
        decValue?: number;
        jsonValue?: any;
    } | null>;
    getCustomerCounter(
        customerId: string,
    ): Promise<{ orders: number; lifetimeValue: number } | null>;
    getProductsByCategory(
        periodStart: Date,
        periodEnd: Date,
        limit?: number,
    ): Promise<Array<{ categoryId: string; qty: number; revenue: number }>>;
    getPaidOrdersWithItems(): Promise<PaidOrder[]>;
    getPaidOrderItemsWithPrices(): Promise<PaidOrderItem[]>;
    getTotalOrdersCount(): Promise<number>;
    getOrdersTodayCount(todayStart: Date): Promise<number>;
    getAllOrdersStatus(): Promise<SimpleOrder[]>;
    getAllOrdersUsers(): Promise<UserOrder[]>;
    getActiveProductsCount(): Promise<number>;
    getActiveProductsWithCategory(): Promise<ProductWithCategory[]>;
    getTotalCustomersCount(): Promise<number>;
    getLowStockInventories(
        limit: number,
    ): Promise<VariantInventoryWithVariant[]>;
}

export default IDashboardProjectionRepository;
