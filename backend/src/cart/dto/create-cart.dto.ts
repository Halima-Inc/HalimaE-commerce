import { IsUUID, IsInt, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateCartDto {
    @ApiProperty({
        description: 'Customer ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @IsUUID()
    customerId: string;
}

export class AddToCartDto {
    @ApiProperty({
        description: 'Product variant ID to add to cart',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @IsUUID()
    variantId: string;

    @ApiProperty({
        description: 'Quantity to add',
        example: 2,
        minimum: 1,
    })
    @IsInt()
    @Min(1)
    qty: number;
}

export class UpdateCartItemDto {
    @ApiProperty({
        description: 'New quantity for the cart item (0 to remove)',
        example: 3,
        minimum: 0,
    })
    @IsInt()
    @Min(0)
    qty: number;
}
