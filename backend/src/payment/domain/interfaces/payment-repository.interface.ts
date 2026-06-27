import { PAYMENTMETHOD, PAYMENTSTATUS } from '@prisma/client';

export interface PaymentPersistenceInput {
    orderId: string;
    provider: string;
    providerRef: string;
    amount: number;
    currency: string;
    status: PAYMENTSTATUS;
    method: PAYMENTMETHOD;
    capturedAt?: Date;
}

export interface PaymentOutboxInput {
    eventId: string;
    eventName: string;
    aggregateId: string;
    providerRef: string;
    idempotencyKey: string;
    version: number;
    occurredAt: Date;
    payload: object;
}

export interface PaymentOutboxRecord {
    id: string;
    eventId: string;
    eventName: string;
    aggregateId: string;
    providerRef: string;
    idempotencyKey: string;
    version: number;
    occurredAt: Date;
    payload: object;
    attempts: number;
}

export interface IPaymentRepository {
    findPaymentByProviderReference(
        providerRef: string,
        provider: string,
    ): Promise<{ id: string } | null>;

    createPayment(input: PaymentPersistenceInput): Promise<void>;

    createPaymentWithOutbox(
        input: PaymentPersistenceInput,
        outboxEvent?: PaymentOutboxInput,
    ): Promise<void>;

    fetchPendingOutboxEvents(limit: number): Promise<PaymentOutboxRecord[]>;

    claimOutboxEvent(outboxId: string): Promise<boolean>;

    markOutboxEventPublished(outboxId: string): Promise<void>;

    markOutboxEventFailed(
        outboxId: string,
        attempts: number,
        errorMessage: string,
        nextAttemptAt: Date,
        deadLetter: boolean,
    ): Promise<void>;

    findOrderById(orderId: string): Promise<{ id: string } | null>;

    findCashPaymentByOrderId(orderId: string): Promise<{ id: string } | null>;

    findWebhookProcessingLog(
        provider: string,
        providerRef: string,
        signatureHash: string,
    ): Promise<{ status: string } | null>;

    createWebhookProcessingLog(
        provider: string,
        providerRef: string,
        payloadHash: string,
        signatureHash: string,
    ): Promise<void>;

    markWebhookProcessingComplete(
        provider: string,
        providerRef: string,
        signatureHash: string,
    ): Promise<void>;

    markWebhookProcessingFailed(
        provider: string,
        providerRef: string,
        signatureHash: string,
        errorMessage: string,
    ): Promise<void>;
}
