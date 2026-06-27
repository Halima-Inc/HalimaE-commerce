import {
    BadRequestException,
    Inject,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { PAYMENTMETHOD, PAYMENTSTATUS } from '@prisma/client';
import { LogService } from '../../../common/log.service';
import type { IPaymentRepository } from '../../domain/interfaces';
import { PAYMENT_REPOSITORY } from '../../payment.tokens';
import { RecordCashPaymentCommand, SavePaymentCommand } from '../commands';
import { SavePaymentHandler } from './save-payment.handler';

@Injectable()
export class RecordCashPaymentHandler {
    constructor(
        @Inject(PAYMENT_REPOSITORY)
        private readonly paymentRepository: IPaymentRepository,
        private readonly savePaymentHandler: SavePaymentHandler,
        private readonly logger: LogService,
    ) {}

    async execute(command: RecordCashPaymentCommand): Promise<void> {
        const order = await this.paymentRepository.findOrderById(
            command.orderId,
        );

        if (!order) {
            throw new NotFoundException(`Order ${command.orderId} not found`);
        }

        const existingPayment =
            await this.paymentRepository.findCashPaymentByOrderId(
                command.orderId,
            );

        if (existingPayment) {
            throw new BadRequestException(
                `Cash payment already recorded for order ${command.orderId}`,
            );
        }

        await this.savePaymentHandler.execute(
            new SavePaymentCommand(
                command.orderId,
                'cash',
                `CASH-${command.orderId}-${Date.now()}`,
                command.amount,
                command.currency,
                PAYMENTSTATUS.PAID,
                PAYMENTMETHOD.CASH_ON_DELIVERY,
                new Date(),
            ),
        );

        this.logger.log(
            `Cash payment recorded for order ${command.orderId}`,
            RecordCashPaymentHandler.name,
        );
    }
}
