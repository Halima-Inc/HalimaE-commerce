import { Inject, Injectable } from '@nestjs/common';
import { ResponseOrderDto, ResponseOrdersFilteredDto } from '../../dto';
import { ORDER_REPOSITORY } from '../../order.tokens';
import type { IOrderRepository } from '../../domain/interfaces';
import { GetAllOrdersQuery } from '../queries/get-all-orders.query';

@Injectable()
export class GetAllOrdersHandler {
    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
    ) {}

    async execute(
        query: GetAllOrdersQuery,
    ): Promise<ResponseOrdersFilteredDto> {
        const {
            page = 1,
            limit = 10,
            status,
            paymentStatus,
            fulfillmentStatus,
            orderNo,
        } = query.filters;

        const { orders, total } = await this.orderRepository.findAllOrders({
            page,
            limit,
            status,
            paymentStatus,
            fulfillmentStatus,
            orderNo,
        });

        const mappedOrders = orders.map((order) => {
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
        });

        return {
            orders: mappedOrders,
            meta: {
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit),
            },
        };
    }
}
