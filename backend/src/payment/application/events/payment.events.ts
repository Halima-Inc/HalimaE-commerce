export type PaymentEventName =
    | 'PaymentCaptured'
    | 'PaymentFailed'
    | 'RefundProcessed';

export interface PaymentEvent {
    eventName: PaymentEventName;
    eventId: string;
    version: number;
    occurredAt: string;
    aggregateId: string;
    providerRef: string;
    idempotencyKey: string;
    payload: object;
}

export interface PaymentCapturedEventPayload {
    orderId: string;
    provider: string;
    providerRef: string;
    amount: number;
    currency: string;
    method: string;
    capturedAt?: string;
}

export interface PaymentFailedEventPayload {
    orderId: string;
    provider: string;
    providerRef: string;
    amount: number;
    currency: string;
    method: string;
    failedAt?: string;
}

export interface RefundProcessedEventPayload {
    paymentId: string;
    amount: number;
}
