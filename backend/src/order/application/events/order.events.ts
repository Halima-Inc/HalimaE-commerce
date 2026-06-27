export type OrderEventName =
    | 'OrderCreated'
    | 'OrderCancelled'
    | 'OrderStatusUpdated'
    | 'PaymentStatusUpdated'
    | 'FulfillmentStatusUpdated';

export interface OrderEvent {
    eventName: OrderEventName;
    eventId: string;
    version: number;
    occurredAt: string;
    aggregateId: string;
    idempotencyKey: string;
    payload: object;
}

export interface OrderCreatedEventPayload {
    orderId: string;
    orderNo: string;
    userId: string;
    currency?: string;
}

export interface OrderCancelledEventPayload {
    orderId: string;
    orderNo: string;
    userId: string;
    status: string;
}

export interface OrderStatusUpdatedEventPayload {
    orderId: string;
    status: string;
}

export interface PaymentStatusUpdatedEventPayload {
    orderId: string;
    paymentStatus: string;
}

export interface FulfillmentStatusUpdatedEventPayload {
    orderId: string;
    fulfillmentStatus: string;
}
