import { ApiProperty } from '@nestjs/swagger';
import { FULFILLMENTSTATUS, ORDERSTATUS, PAYMENTSTATUS, Prisma } from '@prisma/client';

class OrderItemResponseDto {
    @ApiProperty({ type: 'string', description: 'Order item ID', example: '123e4567-e89b-12d3-a456-426614174000' })
    readonly id: string;

    @ApiProperty({ type: 'string', description: 'Variant ID of the item', example: '123e4567-e89b-12d3-a456-426614174001' })
    readonly variantId: string;

    @ApiProperty({ type: 'string', description: 'Name snapshot of the item', example: 'Sample Item Name' })
    readonly nameSnapshot: string;

    @ApiProperty({ type: 'string', description: 'SKU snapshot of the item', example: 'SKU12345' })
    skuSnapshot: string;

    @ApiProperty({ type: 'number', description: 'Unit price of the item', example: 99.99 })
    readonly unitPrice: Prisma.Decimal;

    @ApiProperty({ type: 'number', description: 'Quantity of the item ordered', example: 2 })
    readonly qty: number;
}

class AddressSnapshotDto {
    @ApiProperty({ type: 'string', description: 'Address ID', example: '123e4567-e89b-12d3-a456-426614174000' })
    readonly id: string;

    @ApiProperty({ type: 'string', description: 'First name of the recipient', example: 'Ahmed' })
    readonly firstName: string;

    @ApiProperty({ type: 'string', description: 'Last name of the recipient', example: 'Ali' })
    readonly lastName: string;

    @ApiProperty({ type: 'string', description: 'Phone number of the recipient', example: '+201234567890' })
    readonly phone: string;

    @ApiProperty({ type: 'string', description: 'Address line 1', example: '123 Main St' })
    readonly line1: string;

    @ApiProperty({ required: false, type: 'string', description: 'Address line 2', example: 'Apt 4B' })
    readonly line2?: string;

    @ApiProperty({ type: 'string', description: 'City', example: 'Cairo' })
    readonly city: string;

    @ApiProperty({ type: 'string', description: 'Country', example: 'Egypt' })
    readonly country: string;

    @ApiProperty({ type: 'string', description: 'Postal code', example: '11511' })
    readonly postalCode: string;
}

export class ResponseOrderDto {
    @ApiProperty({ type: 'string', description: 'Order ID', example: '123e4567-e89b-12d3-a456-426614174000' })
    readonly id: string;

    @ApiProperty({ type: 'string', description: 'Order number', example: 'ORD-10001' })
    readonly orderNo: string;

    @ApiProperty({ type: 'string', description: 'Customer ID', example: '123e4567-e89b-12d3-a456-426614174000' })
    readonly customerId: string;

    @ApiProperty({ type: 'string', description: 'Currency code', example: 'EGP' })
    readonly currency: string;

    @ApiProperty({ enum: ORDERSTATUS, description: 'Order status' })
    readonly status: ORDERSTATUS;

    @ApiProperty({ enum: PAYMENTSTATUS, description: 'Payment status', example: PAYMENTSTATUS.PAID })
    readonly paymentStatus: PAYMENTSTATUS;

    @ApiProperty({ enum: FULFILLMENTSTATUS, description: 'Fulfillment status', example: FULFILLMENTSTATUS.PENDING })
    readonly fulfillmentStatus: FULFILLMENTSTATUS;

    @ApiProperty({ type: AddressSnapshotDto, description: 'Billing address snapshot' })
    readonly billingAddress: AddressSnapshotDto;

    @ApiProperty({ type: AddressSnapshotDto, description: 'Shipping address snapshot' })
    readonly shippingAddress: AddressSnapshotDto;

    @ApiProperty({ type: [OrderItemResponseDto], description: 'List of order items' })
    readonly items: OrderItemResponseDto[];

    @ApiProperty({ type: 'number', description: 'Timestamp when the order was placed', example: 1627847263000 })
    readonly placedAt: Date;

    @ApiProperty({ type: 'number', description: 'Timestamp when the order was last updated', example: 1627847263000 })
    readonly updatedAt: Date;

    @ApiProperty({ required: false, type: 'number', description: 'Timestamp when the order was deleted', example: 1627847263000 })
    readonly deletedAt?: Date;

    @ApiProperty({ type: 'number', description: 'Subtotal amount of the order', example: 199.98 })
    readonly subtotal: number;

    @ApiProperty({ type: 'number', description: 'Total amount of the order', example: 199.98 })
    readonly total: number;
}
