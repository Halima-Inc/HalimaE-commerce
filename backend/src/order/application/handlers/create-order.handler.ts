import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { PAYMENTMETHOD, Prisma } from '@prisma/client';
import { LogService } from '../../../common/log.service';
import { CartService } from '../../../cart/cart.service';
import { PaymentService } from '../../../payment/payment.service';
import { PRODUCT_VARIANT_REPOSITORY } from '../../../product/product.tokens';
import type { IProductVariantRepository } from '../../../product/domain/interfaces';
import { ResponseOrderDto } from '../../dto';
import { CreateOrderCommand } from '../commands/create-order.command';
import { ORDER_REPOSITORY } from '../../order.tokens';
import type { IOrderRepository } from '../../domain/interfaces';

type OrderItemSnapshot = {
    variantId: string;
    nameSnapshot: string;
    skuSnapshot: string;
    unitPrice: Prisma.Decimal;
    qty: number;
};

@Injectable()
export class CreateOrderHandler {
    constructor(
        @Inject(ORDER_REPOSITORY)
        private readonly orderRepository: IOrderRepository,
        @Inject(PRODUCT_VARIANT_REPOSITORY)
        private readonly productVariantRepository: IProductVariantRepository,
        private readonly logger: LogService,
        private readonly cartService: CartService,
        private readonly paymentService: PaymentService,
    ) {}

    async execute(command: CreateOrderCommand): Promise<ResponseOrderDto> {
        const { customerId, createOrderDto } = command;

        this.logger.debug(
            `Creating order for customer: ${customerId}`,
            CreateOrderHandler.name,
        );

        try {
            const hasValidAddresses =
                await this.orderRepository.validateCustomerAddresses(
                    customerId,
                    createOrderDto.billingAddressId,
                    createOrderDto.shippingAddressId,
                );

            if (!hasValidAddresses) {
                throw new BadRequestException(
                    'Invalid billing or shipping address',
                );
            }

            const cart = await this.cartService.getCartForCheckout(customerId);

            if (!cart || cart.items.length === 0) {
                throw new BadRequestException('Cart is empty');
            }

            const currency = createOrderDto.currency || 'EGP';
            let subtotal = 0;
            const orderItems: OrderItemSnapshot[] = [];

            for (const item of cart.items) {
                const variant = await this.productVariantRepository.findById(
                    item.variant.id,
                );

                if (variant.inventory.stockOnHand < item.qty) {
                    throw new BadRequestException(
                        `Insufficient stock for "${variant.product.name}". Only ${variant.inventory.stockOnHand} available`,
                    );
                }

                const price = item.variant.prices.find(
                    (p) => p.currency === currency,
                );

                if (!price) {
                    throw new BadRequestException(
                        `Price not available for "${variant.product.name}" in ${currency}`,
                    );
                }

                subtotal += Number(price.amount) * item.qty;

                orderItems.push({
                    variantId: variant.id,
                    nameSnapshot: variant.product.name,
                    skuSnapshot: variant.sku,
                    unitPrice: price.amount,
                    qty: item.qty,
                });
            }

            const orderNo =
                await this.orderRepository.generateNextOrderNumber();

            const order = await this.orderRepository.createCheckoutOrder({
                userId: customerId,
                orderNo,
                currency,
                billingAddressId: createOrderDto.billingAddressId,
                shippingAddressId: createOrderDto.shippingAddressId,
                items: orderItems,
            });

            const total = subtotal;

            let paymentUrl: string | null = null;
            if (
                createOrderDto.paymentMethod !== PAYMENTMETHOD.CASH_ON_DELIVERY
            ) {
                paymentUrl = await this.paymentService.createPaymentIntent({
                    orderId: order.id,
                    amount: Number(total),
                    currency,
                    method: createOrderDto.paymentMethod,
                    billing_address: order.billingAddress
                        ? {
                              id: order.billingAddress.id,
                              firstName: order.billingAddress.firstName,
                              lastName: order.billingAddress.lastName,
                              phone: order.billingAddress.phone || '',
                              line1: order.billingAddress.line1,
                              line2: order.billingAddress.line2 || undefined,
                              city: order.billingAddress.city,
                              country: order.billingAddress.country,
                              postalCode: order.billingAddress.postalCode,
                          }
                        : undefined,
                });

                this.logger.log(
                    `Payment URL created for order ${orderNo}`,
                    CreateOrderHandler.name,
                );
            }

            await this.cartService.clearCart(customerId);

            this.logger.log(
                `Order ${orderNo} created successfully for customer ${customerId}`,
                CreateOrderHandler.name,
            );

            return {
                ...order,
                customerId,
                subtotal,
                total,
                paymentUrl,
            } as ResponseOrderDto;
        } catch (error: any) {
            this.logger.error(
                `Failed to create order for customer ${customerId}`,
                error?.stack,
                CreateOrderHandler.name,
            );
            throw error;
        }
    }
}
