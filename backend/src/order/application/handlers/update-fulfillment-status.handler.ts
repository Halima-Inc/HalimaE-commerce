import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import { FULFILLMENTSTATUS, ORDERSTATUS } from '@prisma/client';
import type { IOrderRepository } from '../../domain/interfaces';
import { ORDER_REPOSITORY } from '../../order.tokens';
import { ResponseOrderDto } from '../../dto';
import { UpdateFulfillmentStatusCommand } from '../commands/update-fulfillment-status.command';

@Injectable()
export class UpdateFulfillmentStatusHandler {
    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
    ) {}

    async execute(
        command: UpdateFulfillmentStatusCommand,
    ): Promise<ResponseOrderDto> {
        const order = await this.orderRepository.findOrderById(command.orderId);

        if (!order) {
            throw new NotFoundException('Order not found');
        }

        await this.orderRepository.updateFulfillmentStatus(
            command.orderId,
            command.updateDto.fulfillmentStatus,
        );

        if (
            command.updateDto.fulfillmentStatus === FULFILLMENTSTATUS.DELIVERED
        ) {
            await this.orderRepository.updateOrderStatus(
                command.orderId,
                ORDERSTATUS.DELIVERED,
            );
        } else if (
            command.updateDto.fulfillmentStatus === FULFILLMENTSTATUS.SHIPPED
        ) {
            await this.orderRepository.updateOrderStatus(
                command.orderId,
                ORDERSTATUS.SHIPPED,
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
