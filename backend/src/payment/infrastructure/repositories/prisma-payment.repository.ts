import { Injectable } from '@nestjs/common';
import { OUTBOXSTATUS, PAYMENTMETHOD, Prisma } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import {
    IPaymentRepository,
    PaymentOutboxInput,
    PaymentOutboxRecord,
    PaymentPersistenceInput,
} from '../../domain/interfaces';

@Injectable()
export class PrismaPaymentRepository implements IPaymentRepository {
    constructor(private readonly prisma: PrismaService) {}

    findPaymentByProviderReference(
        providerRef: string,
        provider: string,
    ): Promise<{ id: string } | null> {
        return this.prisma.payment.findFirst({
            where: {
                providerRef,
                provider,
            },
            select: { id: true },
        });
    }

    async createPayment(input: PaymentPersistenceInput): Promise<void> {
        await this.createPaymentWithOutbox(input);
    }

    async createPaymentWithOutbox(
        input: PaymentPersistenceInput,
        outboxEvent?: PaymentOutboxInput,
    ): Promise<void> {
        await this.prisma.$transaction(async (tx) => {
            await tx.payment.create({
                data: {
                    orderId: input.orderId,
                    provider: input.provider,
                    providerRef: input.providerRef,
                    amount: new Prisma.Decimal(input.amount),
                    currency: input.currency,
                    status: input.status,
                    method: input.method,
                    capturedAt: input.capturedAt,
                },
            });

            if (!outboxEvent) {
                return;
            }

            await tx.outboxEvent.create({
                data: {
                    eventId: outboxEvent.eventId,
                    eventName: outboxEvent.eventName,
                    aggregateId: outboxEvent.aggregateId,
                    providerRef: outboxEvent.providerRef,
                    idempotencyKey: outboxEvent.idempotencyKey,
                    version: outboxEvent.version,
                    occurredAt: outboxEvent.occurredAt,
                    payload: outboxEvent.payload as Prisma.InputJsonValue,
                    status: OUTBOXSTATUS.PENDING,
                },
            });
        });
    }

    async fetchPendingOutboxEvents(
        limit: number,
    ): Promise<PaymentOutboxRecord[]> {
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
            providerRef: row.providerRef,
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

    findOrderById(orderId: string): Promise<{ id: string } | null> {
        return this.prisma.order.findUnique({
            where: { id: orderId },
            select: { id: true },
        });
    }

    findCashPaymentByOrderId(orderId: string): Promise<{ id: string } | null> {
        return this.prisma.payment.findFirst({
            where: {
                orderId,
                method: PAYMENTMETHOD.CASH_ON_DELIVERY,
            },
            select: { id: true },
        });
    }

    async findWebhookProcessingLog(
        provider: string,
        providerRef: string,
        signatureHash: string,
    ): Promise<{ status: string } | null> {
        return this.prisma.webhookProcessingLog.findUnique({
            where: {
                provider_providerRef_signatureHash: {
                    provider,
                    providerRef,
                    signatureHash,
                },
            },
            select: { status: true },
        });
    }

    async createWebhookProcessingLog(
        provider: string,
        providerRef: string,
        payloadHash: string,
        signatureHash: string,
    ): Promise<void> {
        await this.prisma.webhookProcessingLog.create({
            data: {
                provider,
                providerRef,
                payloadHash,
                signatureHash,
                status: 'PROCESSING',
            },
        });
    }

    async markWebhookProcessingComplete(
        provider: string,
        providerRef: string,
        signatureHash: string,
    ): Promise<void> {
        await this.prisma.webhookProcessingLog.update({
            where: {
                provider_providerRef_signatureHash: {
                    provider,
                    providerRef,
                    signatureHash,
                },
            },
            data: {
                status: 'SUCCESS',
                processedAt: new Date(),
            },
        });
    }

    async markWebhookProcessingFailed(
        provider: string,
        providerRef: string,
        signatureHash: string,
        errorMessage: string,
    ): Promise<void> {
        await this.prisma.webhookProcessingLog.update({
            where: {
                provider_providerRef_signatureHash: {
                    provider,
                    providerRef,
                    signatureHash,
                },
            },
            data: {
                status: 'FAILED',
                errorMessage: errorMessage.slice(0, 2000),
                processedAt: new Date(),
            },
        });
    }
}
