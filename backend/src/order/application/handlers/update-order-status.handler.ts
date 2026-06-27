import {
    BadRequestException,
    Inject,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { ORDERSTATUS } from '@prisma/client';
import type { IOrderRepository } from '../../domain/interfaces';
import { ORDER_REPOSITORY } from '../../order.tokens';
import { ResponseOrderDto } from '../../dto';
import { UpdateOrderStatusCommand } from '../commands/update-order-status.command';

@Injectable()
export class UpdateOrderStatusHandler {
    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
    ) {}

    async execute(
        command: UpdateOrderStatusCommand,
    ): Promise<ResponseOrderDto> {
        const order = await this.orderRepository.findOrderById(command.orderId);

        if (!order) {
            throw new NotFoundException('Order not found');
        }

        if (
            order.status === ORDERSTATUS.DELIVERED &&
            command.updateDto.status !== ORDERSTATUS.REFUNDED
        ) {
            throw new BadRequestException(
                'Cannot change status of delivered order',
            );
        }

        if (order.status === ORDERSTATUS.CANCELLED) {
            throw new BadRequestException(
                'Cannot change status of cancelled order',
            );
        }

        const updatedOrder = await this.orderRepository.updateOrderStatus(
            command.orderId,
            command.updateDto.status,
        );

        if (!updatedOrder) {
            throw new NotFoundException('Order not found');
        }

        const subtotal = updatedOrder.items.reduce(
            (sum, item) => sum + Number(item.unitPrice) * item.qty,
            0,
        );

        return {
            ...updatedOrder,
            customerId: updatedOrder.userId,
            subtotal,
            total: subtotal,
        } as ResponseOrderDto;
    }
}
