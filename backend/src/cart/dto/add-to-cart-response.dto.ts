import { ApiProperty } from '@nestjs/swagger';

export class AddToCartResponseDto {
    @ApiProperty({
        description: 'Cart item ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    readonly id: string;

    @ApiProperty({
        description: 'Quantity of the item in cart',
        example: 2,
    })
    readonly qty: number;

    @ApiProperty({
        description: 'Product variant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    readonly variantId: string;

    @ApiProperty({
        description: 'Cart ID this item belongs to',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    readonly cartId: string;

    @ApiProperty({
        description: 'Item creation date',
        example: '2024-01-01T00:00:00.000Z',
    })
    readonly createdAt: Date;

    @ApiProperty({
        description: 'Item last update date',
        example: '2024-01-01T00:00:00.000Z',
    })
    readonly updatedAt: Date;
}
