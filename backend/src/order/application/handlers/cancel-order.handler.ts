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
import { CancelOrderCommand } from '../commands/cancel-order.command';

@Injectable()
export class CancelOrderHandler {
    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
    ) {}

    async execute(command: CancelOrderCommand): Promise<ResponseOrderDto> {
        const order = await this.orderRepository.findOrderForCancellation(
            command.orderId,
            command.customerId,
        );

        if (!order) {
            throw new NotFoundException('Order not found');
        }

        const cancellableStatuses: ORDERSTATUS[] = [
            ORDERSTATUS.PENDING,
            ORDERSTATUS.PROCESSING,
        ];
        if (!cancellableStatuses.includes(order.status)) {
            throw new BadRequestException(
                'Order cannot be cancelled at this stage',
            );
        }

        for (const item of order.items) {
            if (!item.variant.inventory) {
                throw new BadRequestException(
                    `Variant inventory not found for ${item.variantId}`,
                );
            }
        }

        await this.orderRepository.cancelOrder(command.orderId);

        const cancelledOrder = await this.orderRepository.findOrderById(
            command.orderId,
            command.customerId,
        );

        if (!cancelledOrder) {
            throw new NotFoundException('Order not found');
        }

        const subtotal = cancelledOrder.items.reduce(
            (sum, item) => sum + Number(item.unitPrice) * item.qty,
            0,
        );

        return {
            ...cancelledOrder,
            customerId: cancelledOrder.userId,
            subtotal,
            total: subtotal,
        } as ResponseOrderDto;
    }
}
