import { Injectable, OnModuleInit } from '@nestjs/common';
import { PAYMENTSTATUS } from '@prisma/client';
import { InMemoryPaymentEventPublisher } from '../../../payment/infrastructure/services/in-memory-payment-event.publisher';
import { UpdatePaymentStatusHandler } from '../../application/handlers/update-payment-status.handler';
import { UpdatePaymentStatusCommand } from '../../application/commands/update-payment-status.command';

@Injectable()
export class OrderPaymentEventConsumer implements OnModuleInit {
    constructor(
        private readonly inMemoryPublisher: InMemoryPaymentEventPublisher,
        private readonly updatePaymentStatusHandler: UpdatePaymentStatusHandler,
    ) {}

    onModuleInit(): void {
        this.inMemoryPublisher.subscribe(async (event) => {
            if (event.eventName === 'PaymentCaptured') {
                await this.updatePaymentStatusHandler.execute(
                    new UpdatePaymentStatusCommand(event.aggregateId, {
                        paymentStatus: PAYMENTSTATUS.PAID,
                    }),
                );
            } else if (event.eventName === 'PaymentFailed') {
                await this.updatePaymentStatusHandler.execute(
                    new UpdatePaymentStatusCommand(event.aggregateId, {
                        paymentStatus: PAYMENTSTATUS.FAILED,
                    }),
                );
            }
        });
    }
}
