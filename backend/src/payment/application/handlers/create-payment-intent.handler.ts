import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { PAYMENTMETHOD } from '@prisma/client';
import { LogService } from '../../../common/log.service';
import type { IPaymentProvider } from '../../interfaces';
import { PAYMENT_PROVIDER } from '../../payment.tokens';
import { CreatePaymentIntentCommand } from '../commands';

@Injectable()
export class CreatePaymentIntentHandler {
    constructor(
        @Inject(PAYMENT_PROVIDER)
        private readonly paymentProvider: IPaymentProvider,
        private readonly logger: LogService,
    ) {}

    async execute(command: CreatePaymentIntentCommand): Promise<string | null> {
        if (command.method === PAYMENTMETHOD.CASH_ON_DELIVERY) {
            this.logger.log(
                `Cash on delivery payment for order ${command.orderId}`,
                CreatePaymentIntentHandler.name,
            );
            return null;
        }

        if (command.amount <= 0) {
            throw new BadRequestException(
                'Payment amount must be greater than zero',
            );
        }

        try {
            const paymentUrl = await this.paymentProvider.createPaymentIntent(
                command.amount,
                command.currency,
                command.method,
                command.billingAddress,
            );

            this.logger.log(
                `Payment intent created for order ${command.orderId} with method ${command.method}`,
                CreatePaymentIntentHandler.name,
            );

            return paymentUrl;
        } catch (error) {
            this.logger.error(
                `Failed to create payment intent for order ${command.orderId}`,
                error instanceof Error ? error.stack : undefined,
                CreatePaymentIntentHandler.name,
            );

            throw new BadRequestException(
                `Failed to create payment intent: ${error instanceof Error ? error.message : 'Unknown error'}`,
            );
        }
    }
}
