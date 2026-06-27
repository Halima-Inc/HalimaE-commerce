import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { IOrderRepository } from '../../domain/interfaces';
import { ORDER_REPOSITORY } from '../../order.tokens';
import { ResponseOrderDto } from '../../dto';
import { GetOrderByOrderNoQuery } from '../queries/get-order-by-order-no.query';

@Injectable()
export class GetOrderByOrderNoHandler {
    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
    ) {}

    async execute(query: GetOrderByOrderNoQuery): Promise<ResponseOrderDto> {
        const order = await this.orderRepository.findOrderByOrderNo(
            query.orderNo,
            query.customerId,
        );

        if (!order) {
            throw new NotFoundException('Order not found');
        }

        const subtotal = order.items.reduce(
            (sum, item) => sum + Number(item.unitPrice) * item.qty,
            0,
        );

        return {
            ...order,
            customerId: order.userId,
            subtotal,
            total: subtotal,
        } as ResponseOrderDto;
    }
}
