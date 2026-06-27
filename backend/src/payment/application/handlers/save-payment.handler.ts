import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { PAYMENTSTATUS } from '@prisma/client';
import { LogService } from '../../../common/log.service';
import type {
    IPaymentRepository,
    PaymentOutboxInput,
} from '../../domain/interfaces';
import { PAYMENT_REPOSITORY } from '../../payment.tokens';
import type {
    PaymentCapturedEventPayload,
    PaymentEvent,
    PaymentEventName,
    PaymentFailedEventPayload,
} from '../events';
import { SavePaymentCommand } from '../commands';

@Injectable()
export class SavePaymentHandler {
    constructor(
        @Inject(PAYMENT_REPOSITORY)
        private readonly paymentRepository: IPaymentRepository,
        private readonly logger: LogService,
    ) {}

    async execute(command: SavePaymentCommand): Promise<void> {
        const existingPayment =
            await this.paymentRepository.findPaymentByProviderReference(
                command.providerRef,
                command.provider,
            );

        if (existingPayment) {
            this.logger.log(
                `Payment with providerRef ${command.providerRef} already exists, skipping`,
                SavePaymentHandler.name,
            );
            return;
        }

        const eventName = this.resolveEventName(command.status);
        const outboxEvent = eventName
            ? this.toOutboxInput(this.buildPaymentEvent(eventName, command))
            : undefined;

        await this.paymentRepository.createPaymentWithOutbox(
            {
                orderId: command.orderId,
                provider: command.provider,
                providerRef: command.providerRef,
                amount: command.amount,
                currency: command.currency,
                status: command.status,
                method: command.method,
                capturedAt: command.capturedAt,
            },
            outboxEvent,
        );

        this.logger.log(
            `Payment with providerRef ${command.providerRef} saved and queued for event dispatch`,
            SavePaymentHandler.name,
        );
    }

    private toOutboxInput(event: PaymentEvent): PaymentOutboxInput {
        return {
            eventId: event.eventId,
            eventName: event.eventName,
            aggregateId: event.aggregateId,
            providerRef: event.providerRef,
            idempotencyKey: event.idempotencyKey,
            version: event.version,
            occurredAt: new Date(event.occurredAt),
            payload: event.payload,
        };
    }

    private resolveEventName(status: PAYMENTSTATUS): PaymentEventName | null {
        if (status === PAYMENTSTATUS.PAID) {
            return 'PaymentCaptured';
        }

        if (status === PAYMENTSTATUS.FAILED) {
            return 'PaymentFailed';
        }

        return null;
    }

    private buildPaymentEvent(
        eventName: PaymentEventName,
        command: SavePaymentCommand,
    ): PaymentEvent {
        const occurredAt = new Date().toISOString();
        const idempotencyKey = `${command.provider}:${command.providerRef}`;
        const payload =
            eventName === 'PaymentCaptured'
                ? ({
                      orderId: command.orderId,
                      provider: command.provider,
                      providerRef: command.providerRef,
                      amount: command.amount,
                      currency: command.currency,
                      method: command.method,
                      capturedAt: command.capturedAt?.toISOString(),
                  } satisfies PaymentCapturedEventPayload)
                : ({
                      orderId: command.orderId,
                      provider: command.provider,
                      providerRef: command.providerRef,
                      amount: command.amount,
                      currency: command.currency,
                      method: command.method,
                      failedAt: command.capturedAt?.toISOString(),
                  } satisfies PaymentFailedEventPayload);

        return {
            eventName,
            eventId: randomUUID(),
            version: 1,
            occurredAt,
            aggregateId: command.orderId,
            providerRef: command.providerRef,
            idempotencyKey,
            payload,
        };
    }
}
