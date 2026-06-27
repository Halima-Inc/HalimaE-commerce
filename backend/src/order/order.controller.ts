import {
    Controller,
    Get,
    Post,
    Patch,
    Body,
    Param,
    Query,
    UseGuards,
    HttpCode,
    HttpStatus,
} from '@nestjs/common';
import {
    ApiTags,
    ApiOperation,
    ApiBearerAuth,
    ApiParam,
    ApiExtraModels,
} from '@nestjs/swagger';
import {
    ApiStandardResponse,
    ApiStandardErrorResponse,
} from '../common/swagger/api-response.decorator';
import {
    CreateOrderHandler,
    GetAllOrdersHandler,
    GetCustomerOrdersHandler,
    GetOrderByIdHandler,
    GetOrderByOrderNoHandler,
    CancelOrderHandler,
    UpdateFulfillmentStatusHandler,
    UpdateOrderStatusHandler,
    UpdatePaymentStatusHandler,
} from './application/handlers';
import { CreateOrderCommand } from './application/commands/create-order.command';
import { GetCustomerOrdersQuery } from './application/queries/get-customer-orders.query';
import { GetAllOrdersQuery } from './application/queries/get-all-orders.query';
import { GetOrderByIdQuery } from './application/queries/get-order-by-id.query';
import { GetOrderByOrderNoQuery } from './application/queries/get-order-by-order-no.query';
import { CancelOrderCommand } from './application/commands/cancel-order.command';
import { UpdateOrderStatusCommand } from './application/commands/update-order-status.command';
import { UpdatePaymentStatusCommand } from './application/commands/update-payment-status.command';
import { UpdateFulfillmentStatusCommand } from './application/commands/update-fulfillment-status.command';
import {
    CurrentUser,
    JwtAccessTokenGuard,
    RequiredRoles,
    RolesGuard,
} from '../auth/presentation';
import {
    CreateOrderDto,
    FilterOrderDto,
    UpdateOrderStatusDto,
    UpdatePaymentStatusDto,
    UpdateFulfillmentStatusDto,
    ResponseOrderDto,
    ResponseOrdersFilteredDto,
} from './dto';

type AuthenticatedUser = {
    userId: string;
};

@ApiTags('orders')
@ApiExtraModels(
    CreateOrderDto,
    FilterOrderDto,
    UpdateOrderStatusDto,
    UpdatePaymentStatusDto,
    UpdateFulfillmentStatusDto,
    ResponseOrderDto,
    ResponseOrdersFilteredDto,
)
@Controller('orders')
export class OrderController {
    constructor(
        private readonly createOrderHandler: CreateOrderHandler,
        private readonly getCustomerOrdersHandler: GetCustomerOrdersHandler,
        private readonly getOrderByIdHandler: GetOrderByIdHandler,
        private readonly getOrderByOrderNoHandler: GetOrderByOrderNoHandler,
        private readonly cancelOrderHandler: CancelOrderHandler,
        private readonly getAllOrdersHandler: GetAllOrdersHandler,
        private readonly updateOrderStatusHandler: UpdateOrderStatusHandler,
        private readonly updatePaymentStatusHandler: UpdatePaymentStatusHandler,
        private readonly updateFulfillmentStatusHandler: UpdateFulfillmentStatusHandler,
    ) {}

    @Post('checkout')
    @UseGuards(JwtAccessTokenGuard)
    @ApiBearerAuth()
    @HttpCode(HttpStatus.CREATED)
    @ApiOperation({
        summary: 'Create order from cart',
        description:
            'Convert customer cart to order. Validates inventory, creates order with snapshots, and clears cart.',
    })
    @ApiStandardResponse(ResponseOrderDto, 'Order created successfully', 201)
    @ApiStandardErrorResponse(
        400,
        'Bad Request',
        'Cart is empty or insufficient inventory',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Not Found', 'Address not found')
    async createOrder(
        @CurrentUser() user: AuthenticatedUser,
        @Body() createOrderDto: CreateOrderDto,
    ) {
        return this.createOrderHandler.execute(
            new CreateOrderCommand(user.userId, createOrderDto),
        );
    }

    @Get('my-orders')
    @UseGuards(JwtAccessTokenGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get customer orders',
        description:
            'Get all orders for the authenticated customer with pagination and filtering.',
    })
    @ApiStandardResponse(
        ResponseOrdersFilteredDto,
        'Orders retrieved successfully',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    async getMyOrders(
        @CurrentUser() user: AuthenticatedUser,
        @Query() filterDto: FilterOrderDto,
    ) {
        return this.getCustomerOrdersHandler.execute(
            new GetCustomerOrdersQuery(user.userId, filterDto),
        );
    }

    @Get('my-orders/:id')
    @UseGuards(JwtAccessTokenGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get customer order by ID',
        description:
            'Get detailed information about a specific order for the authenticated customer.',
    })
    @ApiParam({
        name: 'id',
        description: 'Order ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiStandardResponse(ResponseOrderDto, 'Order retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    async getMyOrder(
        @CurrentUser() user: AuthenticatedUser,
        @Param('id') orderId: string,
    ) {
        return this.getOrderByIdHandler.execute(
            new GetOrderByIdQuery(orderId, user.userId),
        );
    }

    @Get('my-orders/number/:orderNo')
    @UseGuards(JwtAccessTokenGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get customer order by order number',
        description:
            'Get detailed information about a specific order using order number.',
    })
    @ApiParam({
        name: 'orderNo',
        description: 'Order number',
        example: 'ORD-2025-000001',
    })
    @ApiStandardResponse(ResponseOrderDto, 'Order retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    async getMyOrderByNumber(
        @CurrentUser() user: AuthenticatedUser,
        @Param('orderNo') orderNo: string,
    ) {
        return this.getOrderByOrderNoHandler.execute(
            new GetOrderByOrderNoQuery(orderNo, user.userId),
        );
    }

    @Patch('my-orders/:id/cancel')
    @UseGuards(JwtAccessTokenGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Cancel order',
        description:
            'Cancel order if status is PENDING or PROCESSING. Restores inventory.',
    })
    @ApiParam({
        name: 'id',
        description: 'Order ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiStandardResponse(ResponseOrderDto, 'Order cancelled successfully')
    @ApiStandardErrorResponse(
        400,
        'Bad Request',
        'Order cannot be cancelled at this stage',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    async cancelOrder(
        @CurrentUser() user: AuthenticatedUser,
        @Param('id') orderId: string,
    ) {
        return this.cancelOrderHandler.execute(
            new CancelOrderCommand(orderId, user.userId),
        );
    }

    // Admin Routes

    @Get('admin/all')
    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get all orders (Admin)',
        description:
            'Get all orders across all customers with pagination and filtering. Admin/Employee only.',
    })
    @ApiStandardResponse(
        ResponseOrdersFilteredDto,
        'Orders retrieved successfully',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    async getAllOrders(@Query() filterDto: FilterOrderDto) {
        return this.getAllOrdersHandler.execute(
            new GetAllOrdersQuery(filterDto),
        );
    }

    @Get('admin/:id')
    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get order by ID (Admin)',
        description:
            'Get detailed information about any order. Admin/Employee only.',
    })
    @ApiParam({
        name: 'id',
        description: 'Order ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiStandardResponse(ResponseOrderDto, 'Order retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    async getOrderById(@Param('id') orderId: string) {
        return this.getOrderByIdHandler.execute(new GetOrderByIdQuery(orderId));
    }

    @Get('admin/number/:orderNo')
    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get order by order number (Admin)',
        description:
            'Get detailed information about any order using order number. Admin/Employee only.',
    })
    @ApiParam({
        name: 'orderNo',
        description: 'Order number',
        example: 'ORD-2025-000001',
    })
    @ApiStandardResponse(ResponseOrderDto, 'Order retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    async getOrderByOrderNo(@Param('orderNo') orderNo: string) {
        return this.getOrderByOrderNoHandler.execute(
            new GetOrderByOrderNoQuery(orderNo),
        );
    }

    @Patch('admin/:id/status')
    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Update order status (Admin)',
        description: 'Update the overall order status. Admin/Employee only.',
    })
    @ApiParam({
        name: 'id',
        description: 'Order ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiStandardResponse(ResponseOrderDto, 'Order status updated successfully')
    @ApiStandardErrorResponse(400, 'Bad Request', 'Invalid status transition')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    async updateOrderStatus(
        @Param('id') orderId: string,
        @Body() updateDto: UpdateOrderStatusDto,
    ) {
        return this.updateOrderStatusHandler.execute(
            new UpdateOrderStatusCommand(orderId, updateDto),
        );
    }

    @Patch('admin/:id/payment-status')
    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Update payment status (Admin)',
        description:
            'Update the payment status of an order. Admin/Employee only.',
    })
    @ApiParam({
        name: 'id',
        description: 'Order ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiStandardResponse(
        ResponseOrderDto,
        'Payment status updated successfully',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    async updatePaymentStatus(
        @Param('id') orderId: string,
        @Body() updateDto: UpdatePaymentStatusDto,
    ) {
        return this.updatePaymentStatusHandler.execute(
            new UpdatePaymentStatusCommand(orderId, updateDto),
        );
    }

    @Patch('admin/:id/fulfillment-status')
    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Update fulfillment status (Admin)',
        description:
            'Update the fulfillment status of an order. Admin/Employee only.',
    })
    @ApiParam({
        name: 'id',
        description: 'Order ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiStandardResponse(
        ResponseOrderDto,
        'Fulfillment status updated successfully',
    )
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Not Found', 'Order not found')
    async updateFulfillmentStatus(
        @Param('id') orderId: string,
        @Body() updateDto: UpdateFulfillmentStatusDto,
    ) {
        return this.updateFulfillmentStatusHandler.execute(
            new UpdateFulfillmentStatusCommand(orderId, updateDto),
        );
    }
}
