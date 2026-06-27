import { ORDERSTATUS, Prisma } from '@prisma/client';

export type CheckoutOrderItemInput = {
    variantId: string;
    nameSnapshot: string;
    skuSnapshot: string;
    unitPrice: Prisma.Decimal;
    qty: number;
};

export type CheckoutOrderRecord = {
    id: string;
    orderNo: string;
    userId: string;
    currency: string;
    status: string;
    paymentStatus: string;
    fulfillmentStatus: string;
    placedAt: Date;
    updatedAt: Date;
    deletedAt: Date | null;
    items: Array<{
        id: string;
        variantId: string;
        nameSnapshot: string;
        skuSnapshot: string;
        unitPrice: Prisma.Decimal;
        qty: number;
    }>;
    billingAddress: {
        id: string;
        firstName: string;
        lastName: string;
        city: string;
        country: string;
        line1: string;
        line2: string | null;
        phone: string | null;
        postalCode: string;
    };
    shippingAddress: {
        id: string;
        firstName: string;
        lastName: string;
        city: string;
        country: string;
        line1: string;
        line2: string | null;
        phone: string | null;
        postalCode: string;
    };
};

export type CustomerOrderListFilters = {
    userId: string;
    page: number;
    limit: number;
    status?: string;
    paymentStatus?: string;
    fulfillmentStatus?: string;
    orderNo?: string;
    orderBy?: string;
    sortOrder?: 'asc' | 'desc';
};

export type AdminOrderListFilters = {
    page: number;
    limit: number;
    status?: string;
    paymentStatus?: string;
    fulfillmentStatus?: string;
    orderNo?: string;
};

export type CustomerOrderListRecord = {
    id: string;
    orderNo: string;
    userId: string;
    currency: string;
    status: string;
    paymentStatus: string;
    fulfillmentStatus: string;
    placedAt: Date;
    updatedAt: Date;
    deletedAt: Date | null;
    items: Array<{
        id?: string;
        variantId: string;
        nameSnapshot?: string;
        skuSnapshot?: string;
        unitPrice: Prisma.Decimal;
        qty: number;
    }>;
    billingAddressId?: string;
    shippingAddressId?: string;
    billingAddress?: {
        id: string;
        firstName: string;
        lastName: string;
        city: string;
        country: string;
        line1: string;
        line2: string | null;
        phone: string | null;
        postalCode: string;
    } | null;
    shippingAddress?: {
        id: string;
        firstName: string;
        lastName: string;
        city: string;
        country: string;
        line1: string;
        line2: string | null;
        phone: string | null;
        postalCode: string;
    } | null;
};

export type CancelOrderItemRecord = {
    variantId: string;
    qty: number;
    variant: {
        inventory: {
            id: string;
        } | null;
    };
};

export type CancelOrderRecord = {
    id: string;
    orderNo: string;
    userId: string;
    status: ORDERSTATUS;
    items: CancelOrderItemRecord[];
};

export type OrderOutboxRecord = {
    id: string;
    eventId: string;
    eventName: string;
    aggregateId: string;
    idempotencyKey: string;
    version: number;
    occurredAt: Date;
    payload: object;
    attempts: number;
};

export interface IOrderRepository {
    enqueueOutboxEvent?(input: {
        eventId: string;
        eventName: string;
        aggregateId: string;
        providerRef: string;
        idempotencyKey: string;
        version: number;
        occurredAt: Date;
        payload: object;
    }): Promise<void>;

    fetchPendingOutboxEvents?(limit: number): Promise<OrderOutboxRecord[]>;

    claimOutboxEvent?(outboxId: string): Promise<boolean>;

    markOutboxEventPublished?(outboxId: string): Promise<void>;

    markOutboxEventFailed?(
        outboxId: string,
        attempts: number,
        errorMessage: string,
        nextAttemptAt: Date,
        deadLetter: boolean,
    ): Promise<void>;

    validateCustomerAddresses(
        userId: string,
        billingAddressId: string,
        shippingAddressId: string,
    ): Promise<boolean>;

    generateNextOrderNumber(): Promise<string>;

    createCheckoutOrder(input: {
        userId: string;
        orderNo: string;
        currency: string;
        billingAddressId: string;
        shippingAddressId: string;
        items: CheckoutOrderItemInput[];
    }): Promise<CheckoutOrderRecord>;

    findCustomerOrders(
        filters: CustomerOrderListFilters,
    ): Promise<{ orders: CustomerOrderListRecord[]; total: number }>;

    findAllOrders(
        filters: AdminOrderListFilters,
    ): Promise<{ orders: CustomerOrderListRecord[]; total: number }>;

    findOrderById(
        orderId: string,
        userId?: string,
    ): Promise<CustomerOrderListRecord | null>;

    findOrderByOrderNo(
        orderNo: string,
        userId?: string,
    ): Promise<CustomerOrderListRecord | null>;

    findOrderForCancellation(
        orderId: string,
        customerId: string,
    ): Promise<CancelOrderRecord | null>;

    cancelOrder(orderId: string): Promise<void>;

    updateOrderStatus(
        orderId: string,
        status: string,
    ): Promise<CustomerOrderListRecord | null>;

    updatePaymentStatus(
        orderId: string,
        paymentStatus: string,
    ): Promise<CustomerOrderListRecord | null>;

    updateFulfillmentStatus(
        orderId: string,
        fulfillmentStatus: string,
    ): Promise<CustomerOrderListRecord | null>;
}
