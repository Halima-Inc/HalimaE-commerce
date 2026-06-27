import {
    FULFILLMENTSTATUS,
    ORDERSTATUS,
    PAYMENTSTATUS,
    OUTBOXSTATUS,
    Prisma,
} from '@prisma/client';
import { randomUUID } from 'crypto';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import {
    AdminOrderListFilters,
    CancelOrderRecord,
    CustomerOrderListFilters,
    CustomerOrderListRecord,
    CheckoutOrderRecord,
    IOrderRepository,
} from '../../domain/interfaces';

const orderItemSelect = {
    id: true,
    variantId: true,
    nameSnapshot: true,
    skuSnapshot: true,
    unitPrice: true,
    qty: true,
} as const;

const addressSelect = {
    id: true,
    firstName: true,
    lastName: true,
    city: true,
    country: true,
    line1: true,
    line2: true,
    phone: true,
    postalCode: true,
} as const;

const orderDetailSelect = {
    id: true,
    orderNo: true,
    userId: true,
    currency: true,
    status: true,
    paymentStatus: true,
    fulfillmentStatus: true,
    placedAt: true,
    updatedAt: true,
    deletedAt: true,
    items: {
        select: orderItemSelect,
    },
    billingAddress: {
        select: addressSelect,
    },
    shippingAddress: {
        select: addressSelect,
    },
} as const;

const orderListSelect = {
    id: true,
    orderNo: true,
    userId: true,
    currency: true,
    status: true,
    paymentStatus: true,
    fulfillmentStatus: true,
    placedAt: true,
    updatedAt: true,
    deletedAt: true,
    items: {
        select: {
            unitPrice: true,
            qty: true,
        },
    },
    billingAddressId: true,
    shippingAddressId: true,
} as const;

const cancelOrderSelect = {
    id: true,
    orderNo: true,
    userId: true,
    status: true,
    items: {
        select: {
            variantId: true,
            qty: true,
            variant: {
                select: {
                    inventory: {
                        select: {
                            id: true,
                        },
                    },
                },
            },
        },
    },
} as const;

@Injectable()
export class PrismaOrderRepository implements IOrderRepository {
    constructor(private readonly prisma: PrismaService) {}

    async validateCustomerAddresses(
        userId: string,
        billingAddressId: string,
        shippingAddressId: string,
    ): Promise<boolean> {
        const [billingAddress, shippingAddress] = await Promise.all([
            this.prisma.address.findFirst({
                where: { id: billingAddressId, userId },
                select: { id: true },
            }),
            this.prisma.address.findFirst({
                where: { id: shippingAddressId, userId },
                select: { id: true },
            }),
        ]);

        return Boolean(billingAddress && shippingAddress);
    }

    async generateNextOrderNumber(): Promise<string> {
        const year = new Date().getFullYear();
        const prefix = `ORD-${year}-`;

        const latestOrder = await this.prisma.order.findFirst({
            where: {
                orderNo: {
                    startsWith: prefix,
                },
            },
            orderBy: {
                orderNo: 'desc',
            },
            select: { orderNo: true },
        });

        let nextNumber = 1;
        if (latestOrder) {
            const lastNumber = parseInt(latestOrder.orderNo.split('-')[2], 10);
            nextNumber = lastNumber + 1;
        }

        return `${prefix}${nextNumber.toString().padStart(6, '0')}`;
    }

    async createCheckoutOrder(input: {
        userId: string;
        orderNo: string;
        currency: string;
        billingAddressId: string;
        shippingAddressId: string;
        items: Array<{
            variantId: string;
            nameSnapshot: string;
            skuSnapshot: string;
            unitPrice: any;
            qty: number;
        }>;
    }): Promise<CheckoutOrderRecord> {
        const order = await this.prisma.$transaction(async (prisma) => {
            const created = await prisma.order.create({
                data: {
                    orderNo: input.orderNo,
                    userId: input.userId,
                    currency: input.currency,
                    status: ORDERSTATUS.PENDING,
                    paymentStatus: PAYMENTSTATUS.PENDING,
                    fulfillmentStatus: FULFILLMENTSTATUS.PENDING,
                    billingAddressId: input.billingAddressId,
                    shippingAddressId: input.shippingAddressId,
                    items: {
                        create: input.items,
                    },
                },
                include: {
                    items: {
                        select: orderItemSelect,
                    },
                    billingAddress: {
                        select: addressSelect,
                    },
                    shippingAddress: {
                        select: addressSelect,
                    },
                },
            });

            // Decrement inventory for each ordered item inside the same transaction
            for (const item of input.items) {
                await prisma.variantInventory.update({
                    where: { variantId: item.variantId },
                    data: {
                        stockOnHand: {
                            decrement: item.qty,
                        },
                    },
                });
            }

            // Enqueue outbox event for order created
            await prisma.outboxEvent.create({
                data: {
                    eventId: randomUUID(),
                    eventName: 'OrderCreated',
                    aggregateId: created.id,
                    providerRef: '',
                    idempotencyKey: `order:${input.orderNo}:created`,
                    version: 1,
                    occurredAt: new Date(),
                    payload: {
                        orderId: created.id,
                        orderNo: input.orderNo,
                        userId: input.userId,
                    } as Prisma.InputJsonValue,
                    status: OUTBOXSTATUS.PENDING,
                },
            });

            return created;
        });

        return order as CheckoutOrderRecord;
    }

    async findCustomerOrders(
        filters: CustomerOrderListFilters,
    ): Promise<{ orders: CustomerOrderListRecord[]; total: number }> {
        const {
            userId,
            page,
            limit,
            status,
            paymentStatus,
            fulfillmentStatus,
            orderNo,
            orderBy,
            sortOrder,
        } = filters;

        const where: any = { userId };

        if (status) where.status = status;
        if (paymentStatus) where.paymentStatus = paymentStatus;
        if (fulfillmentStatus) where.fulfillmentStatus = fulfillmentStatus;
        if (orderNo) {
            where.orderNo = {
                contains: orderNo,
                mode: 'insensitive',
            };
        }

        const allowedOrderBy = new Set([
            'placedAt',
            'updatedAt',
            'orderNo',
            'status',
            'paymentStatus',
            'fulfillmentStatus',
        ]);

        const resolvedOrderBy =
            orderBy && allowedOrderBy.has(orderBy) ? orderBy : 'placedAt';

        const [orders, total] = await this.prisma.$transaction([
            this.prisma.order.findMany({
                where,
                select: orderListSelect,
                orderBy: {
                    [resolvedOrderBy]: sortOrder || 'desc',
                },
                skip: (page - 1) * limit,
                take: limit,
            }),
            this.prisma.order.count({ where }),
        ]);

        return {
            orders: orders as unknown as CustomerOrderListRecord[],
            total,
        };
    }

    async findAllOrders(
        filters: AdminOrderListFilters,
    ): Promise<{ orders: CustomerOrderListRecord[]; total: number }> {
        const {
            page,
            limit,
            status,
            paymentStatus,
            fulfillmentStatus,
            orderNo,
        } = filters;

        const where: any = {};

        if (status) where.status = status;
        if (paymentStatus) where.paymentStatus = paymentStatus;
        if (fulfillmentStatus) where.fulfillmentStatus = fulfillmentStatus;
        if (orderNo) {
            where.orderNo = {
                contains: orderNo,
                mode: 'insensitive',
            };
        }

        const [orders, total] = await this.prisma.$transaction([
            this.prisma.order.findMany({
                where,
                select: orderListSelect,
                orderBy: {
                    placedAt: 'desc',
                },
                skip: (page - 1) * limit,
                take: limit,
            }),
            this.prisma.order.count({ where }),
        ]);

        return {
            orders: orders as unknown as CustomerOrderListRecord[],
            total,
        };
    }

    async findOrderById(
        orderId: string,
        userId?: string,
    ): Promise<CustomerOrderListRecord | null> {
        const order = await this.prisma.order.findFirst({
            where: {
                id: orderId,
                ...(userId ? { userId } : {}),
            },
            select: orderDetailSelect,
        });

        return order as CustomerOrderListRecord | null;
    }

    async findOrderByOrderNo(
        orderNo: string,
        userId?: string,
    ): Promise<CustomerOrderListRecord | null> {
        const order = await this.prisma.order.findFirst({
            where: {
                orderNo,
                ...(userId ? { userId } : {}),
            },
            select: orderDetailSelect,
        });

        return order as CustomerOrderListRecord | null;
    }

    async findOrderForCancellation(
        orderId: string,
        customerId: string,
    ): Promise<CancelOrderRecord | null> {
        const order = await this.prisma.order.findFirst({
            where: {
                id: orderId,
                userId: customerId,
            },
            select: cancelOrderSelect,
        });

        return order as CancelOrderRecord | null;
    }

    async cancelOrder(orderId: string): Promise<void> {
        await this.prisma.$transaction(async (prisma) => {
            const order = await prisma.order.findUnique({
                where: { id: orderId },
                select: cancelOrderSelect,
            });

            if (!order) {
                return;
            }

            for (const item of order.items) {
                if (!item.variant.inventory) {
                    continue;
                }

                await prisma.variantInventory.update({
                    where: { variantId: item.variantId },
                    data: {
                        stockOnHand: {
                            increment: item.qty,
                        },
                    },
                });
            }

            const updated = await prisma.order.update({
                where: { id: orderId },
                data: {
                    status: ORDERSTATUS.CANCELLED,
                    paymentStatus: PAYMENTSTATUS.REFUNDED,
                },
            });

            // Enqueue outbox event for order cancellation
            await prisma.outboxEvent.create({
                data: {
                    eventId: randomUUID(),
                    eventName: 'OrderCancelled',
                    aggregateId: order.id,
                    providerRef: '',
                    idempotencyKey: `order:${order.orderNo}:cancelled`,
                    version: 1,
                    occurredAt: new Date(),
                    payload: {
                        orderId: order.id,
                        orderNo: order.orderNo,
                        userId: order.userId,
                        status: updated.status,
                    } as Prisma.InputJsonValue,
                    status: OUTBOXSTATUS.PENDING,
                },
            });
        });
    }

    async updateOrderStatus(
        orderId: string,
        status: string,
    ): Promise<CustomerOrderListRecord | null> {
        const order = await this.prisma.order.update({
            where: { id: orderId },
            data: { status: status as ORDERSTATUS },
            select: orderDetailSelect,
        });

        // enqueue outbox event
        await this.prisma.outboxEvent.create({
            data: {
                eventId: randomUUID(),
                eventName: 'OrderStatusUpdated',
                aggregateId: order.id,
                providerRef: '',
                idempotencyKey: `order:${order.orderNo}:status:${Date.now()}`,
                version: 1,
                occurredAt: new Date(),
                payload: {
                    orderId: order.id,
                    status: order.status,
                } as Prisma.InputJsonValue,
                status: OUTBOXSTATUS.PENDING,
            },
        });

        return order as CustomerOrderListRecord;
    }

    async updatePaymentStatus(
        orderId: string,
        paymentStatus: string,
    ): Promise<CustomerOrderListRecord | null> {
        const order = await this.prisma.order.update({
            where: { id: orderId },
            data: { paymentStatus: paymentStatus as PAYMENTSTATUS },
            select: orderDetailSelect,
        });

        await this.prisma.outboxEvent.create({
            data: {
                eventId: randomUUID(),
                eventName: 'PaymentStatusUpdated',
                aggregateId: order.id,
                providerRef: '',
                idempotencyKey: `order:${order.orderNo}:payment:${Date.now()}`,
                version: 1,
                occurredAt: new Date(),
                payload: {
                    orderId: order.id,
                    paymentStatus: order.paymentStatus,
                } as Prisma.InputJsonValue,
                status: OUTBOXSTATUS.PENDING,
            },
        });

        return order as CustomerOrderListRecord;
    }

    async updateFulfillmentStatus(
        orderId: string,
        fulfillmentStatus: string,
    ): Promise<CustomerOrderListRecord | null> {
        const order = await this.prisma.order.update({
            where: { id: orderId },
            data: { fulfillmentStatus: fulfillmentStatus as FULFILLMENTSTATUS },
            select: orderDetailSelect,
        });

        await this.prisma.outboxEvent.create({
            data: {
                eventId: randomUUID(),
                eventName: 'FulfillmentStatusUpdated',
                aggregateId: order.id,
                providerRef: '',
                idempotencyKey: `order:${order.orderNo}:fulfillment:${Date.now()}`,
                version: 1,
                occurredAt: new Date(),
                payload: {
                    orderId: order.id,
                    fulfillmentStatus: order.fulfillmentStatus,
                } as Prisma.InputJsonValue,
                status: OUTBOXSTATUS.PENDING,
            },
        });

        return order as CustomerOrderListRecord;
    }

    async enqueueOutboxEvent(input: {
        eventId: string;
        eventName: string;
        aggregateId: string;
        providerRef: string;
        idempotencyKey: string;
        version: number;
        occurredAt: Date;
        payload: object;
    }): Promise<void> {
        await this.prisma.outboxEvent.create({
            data: {
                eventId: input.eventId,
                eventName: input.eventName,
                aggregateId: input.aggregateId,
                providerRef: input.providerRef || '',
                idempotencyKey: input.idempotencyKey,
                version: input.version,
                occurredAt: input.occurredAt,
                payload: input.payload as Prisma.InputJsonValue,
                status: OUTBOXSTATUS.PENDING,
            },
        });
    }

    async fetchPendingOutboxEvents(limit: number): Promise<any[]> {
        const rows = await this.prisma.outboxEvent.findMany({
            where: {
                status: OUTBOXSTATUS.PENDING,
                nextAttemptAt: {
                    lte: new Date(),
                },
            },
            orderBy: {
                occurredAt: 'asc',
            },
            take: limit,
        });

        return rows.map((row) => ({
            id: row.id,
            eventId: row.eventId,
            eventName: row.eventName,
            aggregateId: row.aggregateId,
            idempotencyKey: row.idempotencyKey,
            version: row.version,
            occurredAt: row.occurredAt,
            payload: row.payload as object,
            attempts: row.attempts,
        }));
    }

    async claimOutboxEvent(outboxId: string): Promise<boolean> {
        const result = await this.prisma.outboxEvent.updateMany({
            where: {
                id: outboxId,
                status: OUTBOXSTATUS.PENDING,
            },
            data: {
                status: OUTBOXSTATUS.PROCESSING,
            },
        });

        return result.count > 0;
    }

    async markOutboxEventPublished(outboxId: string): Promise<void> {
        await this.prisma.outboxEvent.update({
            where: { id: outboxId },
            data: {
                status: OUTBOXSTATUS.PUBLISHED,
                publishedAt: new Date(),
                lastError: null,
            },
        });
    }

    async markOutboxEventFailed(
        outboxId: string,
        attempts: number,
        errorMessage: string,
        nextAttemptAt: Date,
        deadLetter: boolean,
    ): Promise<void> {
        await this.prisma.outboxEvent.update({
            where: { id: outboxId },
            data: {
                status: deadLetter
                    ? OUTBOXSTATUS.DEAD_LETTER
                    : OUTBOXSTATUS.PENDING,
                attempts,
                lastError: errorMessage,
                nextAttemptAt,
            },
        });
    }
}
