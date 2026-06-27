import { Inject, Injectable } from '@nestjs/common';
import { ResponseOrderDto, ResponseOrdersFilteredDto } from '../../dto';
import { ORDER_REPOSITORY } from '../../order.tokens';
import type { IOrderRepository } from '../../domain/interfaces';
import { GetCustomerOrdersQuery } from '../queries/get-customer-orders.query';

@Injectable()
export class GetCustomerOrdersHandler {
    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
    ) {}

    async execute(
        query: GetCustomerOrdersQuery,
    ): Promise<ResponseOrdersFilteredDto> {
        const { customerId, filters } = query;
        const {
            page = 1,
            limit = 10,
            status,
            paymentStatus,
            fulfillmentStatus,
            orderNo,
            orderBy,
            sortOrder,
        } = filters;

        const { orders, total } = await this.orderRepository.findCustomerOrders(
            {
                userId: customerId,
                page,
                limit,
                status,
                paymentStatus,
                fulfillmentStatus,
                orderNo,
                orderBy,
                sortOrder,
            },
        );

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
