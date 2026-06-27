import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import type { IPaymentProvider } from '../../interfaces';
import type { RefundProcessedEventPayload } from '../events';
import type { IPaymentEventPublisher } from '../services';
import {
    PAYMENT_EVENT_PUBLISHER,
    PAYMENT_PROVIDER,
} from '../../payment.tokens';
import { RefundPaymentCommand } from '../commands';

@Injectable()
export class RefundPaymentHandler {
    constructor(
        @Inject(PAYMENT_PROVIDER)
        private readonly paymentProvider: IPaymentProvider,
        @Inject(PAYMENT_EVENT_PUBLISHER)
        private readonly eventPublisher: IPaymentEventPublisher,
    ) {}

    async execute(command: RefundPaymentCommand): Promise<boolean> {
        const refunded = await this.paymentProvider.refundPayment(
            command.paymentId,
            command.amount,
        );

        if (!refunded) {
            return false;
        }

        const payload: RefundProcessedEventPayload = {
            paymentId: command.paymentId,
            amount: command.amount,
        };

        await this.eventPublisher.publish({
            eventName: 'RefundProcessed',
            eventId: randomUUID(),
            version: 1,
            occurredAt: new Date().toISOString(),
            aggregateId: command.paymentId,
            providerRef: command.paymentId,
            idempotencyKey: `refund:${command.paymentId}`,
            payload,
        });

        return true;
    }
}
