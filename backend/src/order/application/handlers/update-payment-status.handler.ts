import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import { ORDERSTATUS, PAYMENTSTATUS } from '@prisma/client';
import type { IOrderRepository } from '../../domain/interfaces';
import { ORDER_REPOSITORY } from '../../order.tokens';
import { ResponseOrderDto } from '../../dto';
import { UpdatePaymentStatusCommand } from '../commands/update-payment-status.command';

@Injectable()
export class UpdatePaymentStatusHandler {
    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
    ) {}

    async execute(
        command: UpdatePaymentStatusCommand,
    ): Promise<ResponseOrderDto> {
        const order = await this.orderRepository.findOrderById(command.orderId);

        if (!order) {
            throw new NotFoundException('Order not found');
        }

        await this.orderRepository.updatePaymentStatus(
            command.orderId,
            command.updateDto.paymentStatus,
        );

        if (
            command.updateDto.paymentStatus === PAYMENTSTATUS.PAID &&
            order.status === ORDERSTATUS.PENDING
        ) {
            await this.orderRepository.updateOrderStatus(
                command.orderId,
                ORDERSTATUS.PROCESSING,
            );
        }

        const refreshedOrder = await this.orderRepository.findOrderById(
            command.orderId,
        );

        if (!refreshedOrder) {
            throw new NotFoundException('Order not found');
        }

        const subtotal = refreshedOrder.items.reduce(
            (sum, item) => sum + Number(item.unitPrice) * item.qty,
            0,
        );

        return {
            ...refreshedOrder,
            customerId: refreshedOrder.userId,
            subtotal,
            total: subtotal,
        } as ResponseOrderDto;
    }
}
